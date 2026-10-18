package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// Engine 是原生核心的入口，也是 gomobile 绑定的唯一类型。
//
// 生命周期：Start(cfgJSON, tunFd) → Running() → Stop()。所有失败都返回
// error（Java 侧是异常），消息面向人，会被原样写进应用日志。
//
// 为什么配置用 JSON 字符串而不是 Go struct：gomobile 对嵌套类型和字段导出
// 的支持很别扭，一个字符串最省事，也方便 Java 侧按需加字段。
type Engine struct {
	mu      sync.Mutex
	dev     *device.Device
	tunDev  *fdTun
	socks   *socksTun
	gool    *goolState
	tunnel  *tunnelState
	logs    *logRing
	cfg     Config
	started time.Time
}

func NewEngine() *Engine { return &Engine{logs: newLogRing(4000)} }

// logger 把 wireguard-go 的内部日志接进引擎日志（界面能看到握手/重连）。
func (e *Engine) logger() *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.logs.add("DEBUG", fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			e.logs.add("ERROR", fmt.Sprintf(format, args...))
		},
	}
}

// tunnelState 是「只建隧道、不接管设备 tun」的会话：
// WireGuard 挂在用户态协议栈上，本机开一个走隧道的 socks5（给赛风做上游）。
type tunnelState struct {
	net *userNet
	dev *device.Device
	ln  net.Listener
}

func (e *Engine) Version() string { return "ther-engine/0.1 (wireguard-go + AWG junk)" }

// SetLogFile 让引擎日志同时落盘（Java 侧传绝对路径）。原生崩溃时进程直接消失，
// 只有这个文件能留下「死在 Go 的哪一步」。同目录下的 crash.log 会接管 stderr，
// 用来捕获 goroutine panic / runtime fatal 的堆栈。
func (e *Engine) SetLogFile(path string) {
	e.logs.setFile(path)
	redirectStderr(filepath.Join(filepath.Dir(path), "crash.log"))
}

// SetClockOffsetMinutes 传本地时区偏移（东八区 = 480），让引擎日志与界面时间对齐。
func (e *Engine) SetClockOffsetMinutes(minutes int) { setClockOffset(minutes) }

// Start 建设备、下发配置、拉起隧道。tunFd 必须已经 detach（所有权转给引擎）。
//
// 用命名返回值 + recover：Go 里任何 panic 在 gomobile 下都是 abort 整个进程
// （用户看到的就是「闪退」）。这里把它拦成 Java 异常，让上层能报错、能关设备。
// 注意：goroutine 里的 panic 拦不住，那种情况下只能靠 SetLogFile 的落盘定位。
func (e *Engine) Start(cfgJSON string, tunFd int) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.dev != nil {
		return fmt.Errorf("引擎已在运行，先 Stop()")
	}

	var (
		dev  *device.Device
		tdev *fdTun
	)
	defer func() {
		if r := recover(); r != nil {
			e.logs.add("ERROR", fmt.Sprintf("Start 内部 panic（已拦截）：%v", r))
			if dev != nil {
				dev.Close()
			}
			if tdev != nil {
				tdev.Close()
			}
			e.dev, e.tunDev = nil, nil
			err = fmt.Errorf("引擎内部错误：%v", r)
		}
	}()

	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return fmt.Errorf("配置解析失败: %w", err)
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1280
	}
	// keepalive：**上限 15s**（用户要求「增加保活措施」，2026-10-19）。
	//
	// wireguard-go 的「听不到回应」判定是 KeepaliveTimeout(10s) + RekeyTimeout(5s)
	// = 15s：只要发过数据、15 秒内没收到任何已认证包，它就清掉 endpoint 源地址
	// 并重新握手。keepalive 比 15s 长意味着**保活包自己就是那个「发出去的数据」**，
	// 它的回包要是丢了（这条线路很常见），立刻就会触发一次多余的重握手；重握手
	// 在这条线路上经常失败，表现就是「连上几十秒后突然全打不开」。
	//
	// 取 12s：比 15s 判定留 3s 余量，又比原来的 25s 少一半的空闲窗口。代价是每
	// 分钟多 3 个 32 字节的保活包，可以忽略。
	//
	// ★ 注意历史教训：0.1.23 曾经把 keepalive 压到 10s 并同时砍掉「真握手预筛」，
	// 结果全协议连不上 —— 那次的问题是预筛，不是 keepalive。这次预筛（handshakeGate）
	// 完整保留，只动 keepalive 上限。
	if cfg.Keepalive <= 0 || cfg.Keepalive > 15 {
		cfg.Keepalive = 12
	}
	e.logs.add("INFO", fmt.Sprintf("Start: 配置就绪 fd=%d endpoint=%s mtu=%d junk=%d keepalive=%d",
		tunFd, cfg.Endpoint, cfg.MTU, cfg.JunkCount, cfg.Keepalive))

	tdev, err = newFdTun(tunFd, cfg.MTU)
	if err != nil {
		tdev = nil
		return err
	}
	e.logs.add("INFO", fmt.Sprintf("Start: tun fd 已接管（dup），mtu=%d", cfg.MTU))

	dev = device.NewDevice(tdev, conn.NewDefaultBind(), e.logger())
	e.logs.add("INFO", "Start: device 已创建")

	uapi, err := buildUAPI(cfg)
	if err != nil {
		dev.Close()
		tdev.Close()
		e.logs.add("ERROR", fmt.Sprintf("Start: UAPI 生成失败：%v", err))
		return err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		tdev.Close()
		e.logs.add("ERROR", fmt.Sprintf("Start: IpcSet 失败：%v", err))
		return fmt.Errorf("配置设备失败: %w", err)
	}
	e.logs.add("INFO", "Start: IpcSet 完成")
	if err := dev.Up(); err != nil {
		dev.Close()
		tdev.Close()
		e.logs.add("ERROR", fmt.Sprintf("Start: Up 失败：%v", err))
		return fmt.Errorf("启动设备失败: %w", err)
	}
	e.logs.add("INFO", "Start: device.Up 完成")

	e.dev, e.tunDev, e.cfg = dev, tdev, cfg
	e.started = time.Now()
	e.logs.add("INFO", fmt.Sprintf("原生核心已启动：endpoint=%s mtu=%d junk=%d",
		cfg.Endpoint, cfg.MTU, cfg.JunkCount))
	return nil
}

// SwitchEndpoint 在**不重建设备**的前提下，把对端换到另一个端点。
//
// 为什么必须这样：wireguard-go 的第一次握手重传是 5s（device/constants.go 的
// RekeyTimeout，带 ≤334ms jitter），而且它认的是「同一条流」。每次重建设备都会
// 换一个本地 UDP 源端口 —— 也就是一条新五元组，而这条线路上「新流的第一个包被
// 丢掉」是常态，真正能把握手救回来的恰恰是同一条流上的那次重传。2.5s 就重建，
// 等于每换一个端点都主动放弃重传机会（2026-10-18 实测：这个网络上回包要 1.5~2s，
// 2.5s 预算下 40 个端点 0 个成功，7s 预算下才偶尔有几个）。
//
// 只改 peer 的 endpoint（UAPI: public_key + endpoint），不动密钥、不动 tun、
// 不动定时器，所以重传会在新端点上继续，wireguard-go 自己最多重试 18 次（90s）。
func (e *Engine) SwitchEndpoint(addr string) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	endpoint := strings.TrimSpace(addr)
	if endpoint == "" {
		return fmt.Errorf("端点为空")
	}
	dev := e.dev
	if dev == nil && e.gool != nil {
		// GOOL 要换的是外层（能被运营商看见的那一层）。
		dev = e.gool.outerDev
	}
	if dev == nil {
		return fmt.Errorf("原生核心未启动，无法切换端点")
	}
	defer func() {
		if r := recover(); r != nil {
			e.logs.add("ERROR", fmt.Sprintf("SwitchEndpoint 内部 panic（已拦截）：%v", r))
			err = fmt.Errorf("切换端点内部错误：%v", r)
		}
	}()
	pub, kerr := keyToHex(e.cfg.PeerPublicKey)
	if kerr != nil {
		return fmt.Errorf("对端公钥无效: %w", kerr)
	}
	// 不带 replace_peers：这是「更新已有 peer」，密钥/允许的 IP/定时器全都保留。
	uapi := fmt.Sprintf("public_key=%s\nendpoint=%s\n", pub, endpoint)
	if serr := dev.IpcSet(uapi); serr != nil {
		e.logs.add("WARN", fmt.Sprintf("切换端点失败：%s（%v）", endpoint, serr))
		return fmt.Errorf("切换端点 %s 失败: %w", endpoint, serr)
	}
	e.cfg.Endpoint = endpoint
	e.logs.add("INFO", fmt.Sprintf("端点已热切换：%s（设备不重建，重传继续）", endpoint))
	// ★ 换完立刻主动握一次（0.1.29）。
	//
	// 只改 endpoint 的话，设备里还留着旧 keypair，它会拿旧会话往新地址发数据 ——
	// 对端是新机器，静默丢弃，要等 15s 定时器才重握手。主动发一次 initiation，
	// 1s 内就知道新端点行不行（实测能通的端点 0.3~1.4s 回包）。
	// 内部有 RekeyTimeout(5s) 节流，重复调用是空操作。
	if ferr := dev.ForceHandshake(pub); ferr != nil {
		e.logs.add("WARN", fmt.Sprintf("换端点后主动握手失败：%v", ferr))
	}
	return nil
}

// ForceHandshake 让当前对端立刻发起一次新握手。
//
// 给「会话内换端点」和「断流自愈」用：这两条路径都希望尽快知道新端点行不行，
// 而不是等 wireguard-go 自己的 15s 判定 + 5s 重传。
func (e *Engine) ForceHandshake() (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	dev := e.dev
	if dev == nil && e.gool != nil {
		dev = e.gool.outerDev
	}
	if dev == nil {
		return fmt.Errorf("原生核心未启动")
	}
	defer func() {
		if r := recover(); r != nil {
			e.logs.add("ERROR", fmt.Sprintf("ForceHandshake 内部 panic（已拦截）：%v", r))
			err = fmt.Errorf("主动握手内部错误：%v", r)
		}
	}()
	pub, kerr := keyToHex(e.cfg.PeerPublicKey)
	if kerr != nil {
		return fmt.Errorf("对端公钥无效: %w", kerr)
	}
	if herr := dev.ForceHandshake(pub); herr != nil {
		e.logs.add("WARN", fmt.Sprintf("主动握手失败：%v", herr))
		return herr
	}
	e.logs.add("INFO", "已主动发起一次新握手（不等 15s 判定）")
	return nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	dev, tdev, socks, gool, tunnel := e.dev, e.tunDev, e.socks, e.gool, e.tunnel
	e.dev, e.tunDev, e.socks, e.gool, e.tunnel = nil, nil, nil, nil, nil
	e.started = time.Time{}
	e.mu.Unlock()

	if gool != nil {
		gool.Close(e.logs)
	}
	if dev != nil {
		dev.Close()
		e.logs.add("INFO", "原生核心已停止")
	}
	if tunnel != nil {
		tunnel.Close(e.logs)
	}
	if socks != nil {
		socks.Close()
		e.logs.add("INFO", "socks-tun 已停止")
	}
	if tdev != nil {
		tdev.Close()
	}
}

func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dev != nil || e.socks != nil || e.gool != nil || e.tunnel != nil
}

func (t *tunnelState) Close(logs *logRing) {
	if t.ln != nil {
		_ = t.ln.Close()
	}
	if t.dev != nil {
		t.dev.Close()
	}
	if t.net != nil {
		t.net.Close()
	}
	if logs != nil {
		logs.add("INFO", "隧道会话已停止（tunnel-only）")
	}
}

// StartTunnel 只建隧道，不接管设备的 tun：
// WireGuard 挂到用户态协议栈上，另开一个「走隧道」的 socks5。
// 原生核心 + 赛风出口就是靠它把赛风的出站塞进隧道：
//
//	赛风（--upstream socks5://127.0.0.1:本口）→ 本口 → wireguard-go → 出口
func (e *Engine) StartTunnel(cfgJSON string, socksAddr string) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dev != nil || e.socks != nil || e.gool != nil || e.tunnel != nil {
		return fmt.Errorf("引擎已在运行，先 Stop()")
	}
	defer func() {
		if r := recover(); r != nil {
			e.logs.add("ERROR", fmt.Sprintf("StartTunnel 内部 panic（已拦截）：%v", r))
			err = fmt.Errorf("引擎内部错误：%v", r)
		}
	}()

	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return fmt.Errorf("配置解析失败: %w", err)
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	// 这条隧道只给赛风做出站，空闲窗口同样不能碰到 wireguard-go 的 15s 判定
	// （见 gool.go 里同一条注释）：空闲 15 秒就会重握手，重握手失败等于断流。
	if cfg.Keepalive <= 0 || cfg.Keepalive > 10 {
		cfg.Keepalive = 10
	}
	// 这层协议栈要装的和设备 tun 一样是内层 IP 包，1280 够用；
	// 拨号时的 UDP/TCP 头由协议栈自己加。
	un, uerr := newUserNet(mtu, cfg.Address, cfg.DNS, e.logs)
	if uerr != nil {
		return uerr
	}
	dev := device.NewDevice(un.dev, conn.NewDefaultBind(), e.logger())
	uapi, uerr := buildUAPI(cfg)
	if uerr != nil {
		dev.Close()
		un.Close()
		return fmt.Errorf("UAPI 生成失败：%w", uerr)
	}
	if uerr := dev.IpcSet(uapi); uerr != nil {
		dev.Close()
		un.Close()
		return fmt.Errorf("配置失败：%w", uerr)
	}
	if uerr := dev.Up(); uerr != nil {
		dev.Close()
		un.Close()
		return fmt.Errorf("启动失败：%w", uerr)
	}
	e.logs.add("INFO", fmt.Sprintf("隧道会话已启动：端点 %s，接口 %s", cfg.Endpoint, cfg.Address))
	// 原来这里等 20s 握手，不等通也照样开 socks —— 结果是赛风拿着一个死上游
	// 空转 45s×2 个模式（手机日志 17:35:31→17:35:51 整 20s，端点其实一次都没回）。
	// 现在：7s 内没握手就判这条端点不可用，让上层立刻换下一个；握手后还要再验一次
	// 数据面（只回握手的端点在这条线路上很常见，赛风从它上面一条 TCP 都拨不出去）。
	if !waitHandshake(dev, tunnelHandshakeWait) {
		dev.Close()
		un.Close()
		return fmt.Errorf("隧道端点 %s 在 %v 内没完成握手", cfg.Endpoint, tunnelHandshakeWait)
	}
	if uerr := un.verifyDataPlane(tunnelDataPlaneWait); uerr != nil {
		dev.Close()
		un.Close()
		return fmt.Errorf("隧道端点 %s 握手成功但数据面不通（%v）", cfg.Endpoint, uerr)
	}
	e.logs.add("INFO", "隧道握手 + 数据面都已确认，可以给赛风做上游了")
	ln, lerr := un.ServeSocks(socksAddr, e.logs)
	if lerr != nil {
		dev.Close()
		un.Close()
		return fmt.Errorf("打开隧道内 socks5 失败：%w", lerr)
	}
	e.tunnel = &tunnelState{net: un, dev: dev, ln: ln}
	e.started = time.Now()
	return nil
}

// 「原生核心 + 赛风」那条隧道的等待预算，理由同 gool.go 里那组常量：
// 6.5s 盖住 wireguard-go 的一次握手重传（RekeyTimeout=5s）+ RTT；4s 给一次
// 隧道内 TCP 往返。坏端点 7s 就换，不再白等 20s。
const (
	tunnelHandshakeWait = 6500 * time.Millisecond
	tunnelDataPlaneWait = 4 * time.Second
)

// StartSocks 把 tun 里的 IP 包接到本地 SOCKS5（Aether 核心的出口）上。
//
// Aether 核心只会开本地 SOCKS5，没有 --tun-fd；而 Android 只有 tun 能真正接管
// 整机流量（Wi-Fi 的 HTTP 代理绝大多数应用不认）。所以 VPN 模式下必须由引擎自己
// 起一个用户态协议栈来做 tun→SOCKS 转换，tsocks=127.0.0.1:<核心端口>。
//
// tunFd 不会被接管（内部 dup），调用方仍拥有它。
func (e *Engine) StartSocks(socksAddr string, tunFd int, dnsServer string, mtu int) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.dev != nil || e.socks != nil {
		return fmt.Errorf("引擎已在运行，先 Stop()")
	}
	if mtu <= 0 {
		mtu = 1280
	}

	defer func() {
		if r := recover(); r != nil {
			e.logs.add("ERROR", fmt.Sprintf("StartSocks 内部 panic（已拦截）：%v", r))
			e.socks = nil
			err = fmt.Errorf("引擎内部错误：%v", r)
		}
	}()

	s, serr := startSocksTun(tunFd, mtu, socksAddr, dnsServer, e.logs)
	if serr != nil {
		e.logs.add("ERROR", fmt.Sprintf("StartSocks 失败：%v", serr))
		return serr
	}
	e.socks = s
	e.started = time.Now()
	e.logs.add("INFO", fmt.Sprintf("原生核心已启动（socks-tun）：socks=%s mtu=%d", socksAddr, mtu))
	return nil
}

// StatusJSON 返回连接状态，供 Kotlin 侧解析后更新界面。
//
// handshaken 是「隧道真的通了」的唯一可信信号：设备起来只说明本地设备在跑，
// 对端是否应答全看 last_handshake_time_sec。
func (e *Engine) StatusJSON() string {
	e.mu.Lock()
	dev := e.dev
	socks := e.socks
	gool := e.gool
	tunnel := e.tunnel
	up := !e.started.IsZero()
	since := e.started
	endpoint := e.cfg.Endpoint
	e.mu.Unlock()

	status := map[string]any{
		"running":    dev != nil || socks != nil || gool != nil || tunnel != nil,
		"handshaken": socks != nil,
	}
	if endpoint != "" {
		status["endpoint"] = endpoint
	}
	// GOOL：真正决定「通没通」的是内层设备的握手（外层只是通道）。
	if gool != nil && gool.innerDev != nil {
		status["mode"] = "gool"
		status["handshaken"] = false
		if dump, err := gool.innerDev.IpcGet(); err == nil {
			hs, rx, tx := parseUAPIGet(dump)
			status["handshaken"] = hs > 0
			if hs > 0 {
				status["lastHandshakeUnix"] = hs
				status["hsAgeSec"] = time.Now().Unix() - hs
			}
			status["rxBytes"] = rx
			status["txBytes"] = tx
			// 隧道自己的收发计数单独报一份：带赛风时下面 socks 那段会把
			// rxBytes/txBytes 覆盖成「设备→socks」的计数，用户什么都不干时它是
			// 冻住的，看门狗会误判成断流。内层隧道的 rx 每 10s 一定有 keepalive
			// 回包，才是「隧道还活着」的可靠信号。
			status["tunnelRxBytes"] = rx
			status["tunnelTxBytes"] = tx
		}
		if gool.outerDev != nil {
			if dump, err := gool.outerDev.IpcGet(); err == nil {
				hs, orx, otx := parseUAPIGet(dump)
				status["outerHandshaken"] = hs > 0
				if hs > 0 {
					status["outerHsAgeSec"] = time.Now().Unix() - hs
				}
				// ★ 外层自己的收发计数（0.1.29）。
				//
				// 没有这两个数字时，「断了」只能看到内层 rx 冻住，分不清是外层被掐
				// 还是内层落点死了 —— 两者的处置完全不同（前者换外层端点，后者换
				// 内层落点）。2026-10-19 23:58 那次就卡在这个判断上。
				status["outerRxBytes"] = orx
				status["outerTxBytes"] = otx
			}
		}
	}
	// tunnel-only（原生核心 + 赛风）：设备流量走的是 socks-tun，
	// 这条隧道的握手状态只用来判断「赛风能不能出去」。
	if tunnel != nil && tunnel.dev != nil {
		status["mode"] = "tunnel"
		if dump, err := tunnel.dev.IpcGet(); err == nil {
			hs, rx, tx := parseUAPIGet(dump)
			status["tunnelHandshaken"] = hs > 0
			status["handshaken"] = hs > 0
			// 这条隧道的收发计数单独报：socks-tun 模式会把 rxBytes/txBytes 覆盖成
			// 「设备→socks」的计数，而界面判断「隧道是不是还活着」要看隧道自己有没有
			// 收到 keepalive 回包。
			status["tunnelRxBytes"] = rx
			status["tunnelTxBytes"] = tx
			if hs > 0 {
				status["hsAgeSec"] = time.Now().Unix() - hs
			}
		}
	}
	// socks-tun 模式下隧道由外部核心负责，握手是否成功看核心日志；
	// 这里把转换层自己的计数报上去，至少能区分「一条连接都没进来」和「都在搬」。
	if socks != nil {
		status["mode"] = "socks-tun"
		status["tcpConns"] = socks.tcpConns.Load()
		status["udpDropped"] = socks.udpDrops.Load()
		status["rxBytes"] = socks.rxBytes.Load()
		status["txBytes"] = socks.txBytes.Load()
	}
	if dev != nil {
		if dump, err := dev.IpcGet(); err == nil {
			hs, rx, tx := parseUAPIGet(dump)
			status["handshaken"] = hs > 0
			if hs > 0 {
				status["lastHandshakeUnix"] = hs
				status["hsAgeSec"] = time.Now().Unix() - hs
			}
			status["rxBytes"] = rx
			status["txBytes"] = tx
		}
	}
	if up && !since.IsZero() {
		status["uptimeSec"] = int(time.Since(since).Seconds())
	}
	b, err := json.Marshal(status)
	if err != nil {
		return `{"running":false,"handshaken":false}`
	}
	return string(b)
}

// DrainLogs 取走自上次调用以来的引擎日志（多行文本）。
func (e *Engine) DrainLogs() string { return e.logs.drain() }

// parseUAPIGet 从 IpcGet 的 dump 里取握手时间与收发字节数。
func parseUAPIGet(dump string) (handshake int64, rx int64, tx int64) {
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "last_handshake_time_sec="):
			if v, err := strconv.ParseInt(line[len("last_handshake_time_sec="):], 10, 64); err == nil && v > handshake {
				handshake = v
			}
		case strings.HasPrefix(line, "rx_bytes="):
			if v, err := strconv.ParseInt(line[len("rx_bytes="):], 10, 64); err == nil {
				rx += v
			}
		case strings.HasPrefix(line, "tx_bytes="):
			if v, err := strconv.ParseInt(line[len("tx_bytes="):], 10, 64); err == nil {
				tx += v
			}
		}
	}
	return
}
