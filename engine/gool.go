package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// GOOL（wireguard in wireguard）：外面一层 WireGuard 到 Cloudflare 边缘，
// 里面再跑一层 WireGuard，内层握手发的 UDP 全部从外层隧道里出去。
//
// 为什么要两层：外层只负责「出得去、躲过 DPI」，内层负责「落地 IP 是另一个
// 边缘」——单层 WARP 常常被判回国内出口（日志里 "wireguard exit: …, CN via LAX"），
// 两层之后内层是从 Cloudflare 自己的网络里挑到的另一个边缘，出口地址随之改变。
//
// 实现上没有引入新的协议栈：外层用 usernet.go 里的用户态协议栈（userNet），
// 内层设备换一个自定义的 conn.Bind，把 UDP 写进外层协议栈即可。

// GOOL 各级的等待预算。全部按「wireguard-go 的一次握手重传（RekeyTimeout=5s）
// + 最多 2s RTT」定，而不是靠拍一个大数：
//   - 外层握手：能通的端点 0.6~1.4s 就回了（手机实测），6.5s 足够盖住一次重传；
//   - 外层数据面：隧道内一次 TCP 往返，4s 已很宽裕；
//   - 内层握手：内层包要穿两层，给它 8s。
//
// 换来的效果：坏端点 6.5s 就换掉，而不是原来的 15s + 20s 白等。
const (
	goolOuterHandshakeWait = 6500 * time.Millisecond
	goolOuterDataPlaneWait = 4 * time.Second
	// 内层落点在隧道里的验活预算：探针是 64 字节的往返，穿两层 RTT 一般
	// 0.3~0.8s，1.5s 足够判「这个落点从 WARP 内部通不通」。
	goolInnerProbeWait = 1500 * time.Millisecond
	// 验活之后最多拿几个落点去握手：每个 4.5s，取最快的 3 个是 13.5s，
	// 再多就把「换外层端点」这件事拖得太晚了。
	//
	// 0.1.28 是 4 个（18s）。用户要求「总时间不能超过 2 分钟」：GOOL 每个外层端点
	// 的最坏耗时 = 6.5(外层握手) + 4(数据面) + 1.5(落点验活) + 落点数×4.5，
	// 4 个落点就是 30s/端点 × 3 个外层 = 90s，再加上探活和预筛必然超 2 分钟。
	// 3 个落点压到 76.5s，实测里第 1~2 个落点就能握上（00:00:16 那次第 1 个失败、
	// 第 2 个成功），第 4 个几乎用不到。
	goolInnerMaxLandings = 3
	// 单个落点等握手的预算：能通的落点 1s 内就回（另一个项目的日志是立即成功），
	// 4.5s 盖住 wireguard-go 的一次重传（RekeyTimeout=5s 略欠一点，但它重传前
	// 已经发了 2 次 initiation）。原来是 8s，白等了 3.5s × 4 个落点。
	goolInnerHandshakeWait = 4500 * time.Millisecond
)

// failedLandings 记住「这次进程里内层握手失败过」的落点。
//
// 为什么必须有：落点按隧道内 RTT 排序，而「最快」的那个如果握不上手，每次重试
// （换外层端点、或上层自动重扫一轮）都会把它重新排到第一位，于是 3 个外层端点 ×
// 4 轮全撞在同一个地址上，看起来像「怎么试都不行」。
//
// 10 分钟 TTL：线路状态会变，别永久拉黑。
var (
	failedLandingMu sync.Mutex
	failedLandings  = map[string]time.Time{}
)

const failedLandingTTL = 10 * time.Minute

func markLandingFailed(addr string) {
	failedLandingMu.Lock()
	failedLandings[addr] = time.Now()
	failedLandingMu.Unlock()
}

// skipFailedLandings 去掉最近握不上手的落点。
//
// 全都在黑名单里时**原样返回**：宁可再试一遍，也不要返回空列表把这条外层判死
// （那会让上层以为「这个外层端点不行」，其实是落点全被自己拉黑了）。
func skipFailedLandings(in []string) []string {
	failedLandingMu.Lock()
	defer failedLandingMu.Unlock()
	out := make([]string, 0, len(in))
	for _, a := range in {
		if t, ok := failedLandings[a]; ok && time.Since(t) < failedLandingTTL {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return in
	}
	return out
}

// tunnelEndpoint 是内层设备的对端地址。GOOL 只连一个固定入口，
// 不需要 wireguard-go 那套 src 地址缓存，所以实现得非常薄。
type tunnelEndpoint struct {
	addr netip.AddrPort
	str  string
}

func (e *tunnelEndpoint) ClearSrc()           {}
func (e *tunnelEndpoint) SrcToString() string { return "" }
func (e *tunnelEndpoint) DstToString() string { return e.str }
func (e *tunnelEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *tunnelEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *tunnelEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}

// tunnelBind 把 wireguard-go 的收发接到外层隧道上。
type tunnelBind struct {
	net  *userNet
	dst  *tunnelEndpoint
	conn net.Conn

	mu     sync.Mutex
	closed bool
}

// newTunnelBind 建一个内层通道。u 可以为 nil —— GOOL 的内层要先知道落点、
// 后建协议栈（落点由 buildInnerLayer 决定），那时再把 net 填进来。
func newTunnelBind(u *userNet, endpoint string) (*tunnelBind, error) {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("GOOL 内层端点 %q 无效（要 ip:port）：%w", endpoint, err)
	}
	return &tunnelBind{net: u, dst: &tunnelEndpoint{addr: ap, str: ap.String()}}, nil
}

func (b *tunnelBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if b.net == nil {
		return nil, 0, fmt.Errorf("GOOL 内层通道没有挂到外层协议栈上")
	}
	c, err := b.net.DialUDP(b.dst.str)
	if err != nil {
		return nil, 0, fmt.Errorf("在外层隧道里打开 UDP 失败：%w", err)
	}
	b.mu.Lock()
	b.conn = c
	b.mu.Unlock()
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *tunnelBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return 0, net.ErrClosed
	}
	n, err := c.Read(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	eps[0] = b.dst
	return 1, nil
}

func (b *tunnelBind) Close() error {
	b.mu.Lock()
	c := b.conn
	b.conn = nil
	closed := b.closed
	b.closed = true
	b.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	if closed {
		return nil
	}
	return nil
}

func (b *tunnelBind) SetMark(mark uint32) error { return nil }

func (b *tunnelBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *tunnelBind) ParseEndpoint(s string) (conn.Endpoint, error) { return b.dst, nil }

func (b *tunnelBind) BatchSize() int { return 1 }

// goolState 是 GOOL 会话的运行时对象。
type goolState struct {
	outerNet *userNet
	outerDev *device.Device
	innerDev *device.Device
	// 内层落点二选一：接管设备 tun（普通 GOOL），或用户态协议栈（GOOL + 赛风）。
	innerTun *fdTun
	innerNet *userNet
	ln       net.Listener
	bind     *tunnelBind
}

func (g *goolState) Close(logs *logRing) {
	if g.ln != nil {
		_ = g.ln.Close()
	}
	if g.innerDev != nil {
		g.innerDev.Close()
	}
	if g.outerDev != nil {
		g.outerDev.Close()
	}
	if g.outerNet != nil {
		g.outerNet.Close()
	}
	if g.innerNet != nil {
		g.innerNet.Close()
	}
	if g.innerTun != nil {
		g.innerTun.Close()
	}
	if logs != nil {
		logs.add("INFO", "GOOL 已停止（内外两层都已关闭）")
	}
}

// startGool 建立内外两层隧道。outer 是「能被运营商看见的那一层」，
// inner 是「真正给设备走的那一层」，它的 UDP 会被塞进 outer。
//
// tunFd > 0：内层接管设备 tun（普通 GOOL）。
// tunFd == 0：内层挂到用户态协议栈上，并在隧道里开 socks5（[socksAddr]），
// 给赛风做上游——这就是「GOOL + Psiphon」。
func startGool(outer, inner Config, tunFd int, socksAddr string, logs *logRing, logger *device.Logger) (*goolState, error) {
	if outer.PrivateKey == "" || outer.PeerPublicKey == "" || outer.Endpoint == "" {
		return nil, fmt.Errorf("GOOL 外层配置不完整")
	}
	if inner.PrivateKey == "" || inner.PeerPublicKey == "" || inner.Endpoint == "" {
		return nil, fmt.Errorf("GOOL 内层配置不完整")
	}
	innerMtu := inner.MTU
	if innerMtu <= 0 {
		innerMtu = 1280
	}
	// 嵌套隧道的 keepalive 必须 ≤10s。
	//
	// wireguard-go 的「听不到回应」判定是 KeepaliveTimeout(10s)+RekeyTimeout(5s)=15s：
	// 只要连续 15 秒没有收到对端的认证包，它就清 endpoint 源地址并重新握手。而默认
	// keepalive=25s > 15s，于是**隧道一空闲就必然触发一次重握手**；在这条被 DPI 盯着
	// 的线路上，重握手经常失败，表现就是「GOOL 连上几十秒后网页全打不开」。
	// 把 keepalive 压到 10s，空闲窗口永远到不了 15s，就不会有那次多余的重握手。
	if outer.Keepalive <= 0 || outer.Keepalive > 10 {
		outer.Keepalive = 10
	}
	if inner.Keepalive <= 0 || inner.Keepalive > 10 {
		inner.Keepalive = 10
	}
	// 外层要比内层多装下内层 WireGuard 的 32 字节头 + IP/UDP 头，
	// 1420 足够 1280 的内层（1280+32+28=1340）。
	outerMtu := outer.MTU
	if outerMtu < innerMtu+100 {
		outerMtu = innerMtu + 140
	}

	un, err := newUserNet(outerMtu, outer.Address, outer.DNS, logs)
	if err != nil {
		return nil, err
	}
	logs.add("INFO", fmt.Sprintf("GOOL：外层协议栈就绪（mtu=%d 接口=%s）", outerMtu, outer.Address))

	outerDev := device.NewDevice(un.dev, conn.NewDefaultBind(), logger)
	uapi, err := buildUAPI(outer)
	if err != nil {
		outerDev.Close()
		un.Close()
		return nil, fmt.Errorf("GOOL 外层 UAPI 生成失败：%w", err)
	}
	if err := outerDev.IpcSet(uapi); err != nil {
		outerDev.Close()
		un.Close()
		return nil, fmt.Errorf("GOOL 外层配置失败：%w", err)
	}
	if err := outerDev.Up(); err != nil {
		outerDev.Close()
		un.Close()
		return nil, fmt.Errorf("GOOL 外层启动失败：%w", err)
	}
	logs.add("INFO", fmt.Sprintf("GOOL：外层隧道已请求，端点 %s", outer.Endpoint))

	// 外层必须「握手 + 数据面」都通过才值得起内层：
	//  - 没握手就起内层，内层包被外层静默丢掉，只表现为「一直连不上」；
	//  - 握上手但数据面不通（手机日志里 outer rx=0 的那两次）更坑：内层会白等
	//    20s，然后整次连接以「6 个端点全失败」结束。这类端点在这条线路上很常见
	//    （握手成功 ≠ 会转发数据），所以必须在这里就把它判死、立刻换下一个。
	//
	// 6.5s 而不是原来的 15s：wireguard-go 的握手重传是 RekeyTimeout=5s，能通的
	// 端点 1s 内就回了（手机实测 0.6~1.4s）。15s 只会让每个坏端点白等。
	if !waitHandshake(outerDev, goolOuterHandshakeWait) {
		outerDev.Close()
		un.Close()
		return nil, fmt.Errorf("GOOL 外层 %s 在 %v 内没完成握手", outer.Endpoint, goolOuterHandshakeWait)
	}
	logs.add("INFO", "GOOL：外层隧道握手完成，验证数据面…")
	if err := un.verifyDataPlane(goolOuterDataPlaneWait); err != nil {
		outerDev.Close()
		un.Close()
		return nil, fmt.Errorf("GOOL 外层 %s 握手成功但数据面不通（%v）——只回握手不转发数据的端点", outer.Endpoint, err)
	}
	logs.add("INFO", "GOOL：外层数据面已确认（隧道内 TCP 往返成功）")

	// 内层落点：只走 WARP 的**标准端口**，并且从外层隧道里验活。
	//
	// ★ 0.1.28 按另一个项目的 mihomo 核心日志重写（那个项目 GOOL 每次 10s 内连上）：
	//     [tunnel] 候选端点 29 个 × 端口 [2408 500 1701 4500]（wg）
	//     [tunnel] 8.6.112.3:2408 握手成功，验证出口…
	// 它的内层落点**全部**落在 WARP 标准端口上，从来没有拿探针扫出来的高位端口
	// 当内层。我们之前正好相反：内层落点取自「手机上真握手通过」的那批，也就是
	// 1002/3854/1387/955/7559/968/943 这些高位端口 —— 0xcf 探针从隧道里能回
	// （所以 0.1.27 的验活是「通过」的），真握手却零回包：2026-10-18 23:39~23:41
	// 的日志里 11 个落点全灭，只有 8.6.112.57:1701 沾到标准端口。
	//
	// 所以现在的候选池是「已知活的 WARP 服务器 IP × 四个标准端口」，2408 排最前。
	innerCands := innerCandidates(inner)
	landings := innerCands
	pool := innerLandingPool(innerCands)
	logs.add("INFO", fmt.Sprintf(
		"GOOL：内层落点候选 %d 个（已知活的 WARP IP × 标准端口 2408/500/1701/4500，含各段 .1:2408），从隧道里验活…",
		len(pool),
	))
	if alive := un.probeWarpThroughPool(pool, goolInnerProbeWait, 32); len(alive) > 0 {
		landings = capLandings(skipFailedLandings(aliveAddrs(alive)), goolInnerMaxLandings)
		logs.add("INFO", fmt.Sprintf(
			"GOOL：内层落点隧道内验活 %d/%d 个，取最快 %d 个（%s）",
			len(alive), len(pool), len(landings), strings.Join(landings, ", "),
		))
	} else {
		// 标准端口一个都没回：退回原来那批高位端口再验一次（保留旧行为，不判死）。
		logs.add("WARN", fmt.Sprintf(
			"GOOL：标准端口 %d 个落点从隧道里全没回探针，改验原来那批高位端口",
			len(pool),
		))
		if alive := un.probeWarpThroughPool(innerCands, goolInnerProbeWait, 12); len(alive) > 0 {
			landings = capLandings(skipFailedLandings(aliveAddrs(alive)), goolInnerMaxLandings)
			logs.add("INFO", fmt.Sprintf(
				"GOOL：高位端口验活 %d/%d 个（%s）",
				len(alive), len(innerCands), strings.Join(landings, ", "),
			))
		} else {
			logs.add("WARN", fmt.Sprintf(
				"GOOL：两批落点都没回探针 —— 外层隧道很可能不转发 UDP；仍按标准端口顺序硬试 %d 个",
				goolInnerMaxLandings,
			))
			landings = capLandings(skipFailedLandings(pool), goolInnerMaxLandings)
		}
	}

	var layer *innerLayer
	var handshaken bool
	var lastErr error
	for i, cand := range landings {
		if layer != nil {
			layer.close()
			layer = nil
		}
		l, berr := buildInnerLayer(inner, cand, tunFd, un, logs, logger)
		if berr != nil {
			lastErr = berr
			continue
		}
		layer = l
		if waitNewHandshake(l.dev, 0, goolInnerHandshakeWait) {
			handshaken = true
			inner.Endpoint = cand
			break
		}
		logs.add("WARN", fmt.Sprintf(
			"GOOL：内层落点 %s 在 %v 内没握手（%d/%d），换下一个",
			cand, goolInnerHandshakeWait, i+1, len(landings),
		))
		// 拉黑它：下一轮（换外层端点 / 上层自动重扫）不要再从这个地址开始。
		markLandingFailed(cand)
	}
	if layer == nil {
		outerDev.Close()
		un.Close()
		if lastErr == nil {
			lastErr = fmt.Errorf("没有可用的内层落点")
		}
		return nil, fmt.Errorf("GOOL 内层一个都没起来：%w", lastErr)
	}
	logs.add("INFO", fmt.Sprintf("GOOL：内层隧道已启动（端点 %s，经外层隧道）", inner.Endpoint))

	g := &goolState{
		outerNet: un, outerDev: outerDev, innerDev: layer.dev,
		innerTun: layer.tun, innerNet: layer.net, bind: layer.bind,
	}
	if !handshaken {
		// 外层是好的、内层怎么都握不上：把这条会话判死，让上层换一个外层端点
		// （换了外层，内层落点也会跟着重算），别交一个假隧道出去。
		g.Close(logs)
		return nil, fmt.Errorf(
			"GOOL 内层 %d 个落点都没完成握手（外层 %s 握手 + 数据面都是好的）",
			len(landings), outer.Endpoint,
		)
	}
	if socksAddr != "" {
		ln, lerr := layer.net.ServeSocks(socksAddr, logs)
		if lerr != nil {
			g.Close(logs)
			return nil, fmt.Errorf("GOOL 隧道内 socks5 打开失败：%w", lerr)
		}
		g.ln = ln
	}
	return g, nil
}

// innerLayer 是 GOOL 内层的「一层」：一个设备 + 它的落点通道。
// 落点失败时整层重建（wireguard-go 的 Bind 是一次性绑定，换落点只能重建），
// 外层完全不动。
type innerLayer struct {
	dev  *device.Device
	tun  *fdTun
	net  *userNet
	bind *tunnelBind
}

func (l *innerLayer) close() {
	if l == nil {
		return
	}
	if l.dev != nil {
		l.dev.Close()
	}
	if l.net != nil {
		l.net.Close()
	}
	if l.tun != nil {
		l.tun.Close()
	}
}

// innerCandidates 把 Endpoint 和 InnerCandidates 合成一条去重后的尝试序列。
func innerCandidates(inner Config) []string {
	out := make([]string, 0, len(inner.InnerCandidates)+1)
	seen := make(map[string]struct{}, len(inner.InnerCandidates)+1)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(inner.Endpoint)
	for _, c := range inner.InnerCandidates {
		add(c)
	}
	return out
}

// innerLandingPool 把「已知活的 WARP 服务器 IP」铺成**标准端口**的落点池。
//
// 依据（另一个项目的 mihomo 核心日志，GOOL 每次 10s 内连上）：
//
//	[tunnel] 候选端点 29 个 × 端口 [2408 500 1701 4500]（wg）
//	[tunnel] 8.6.112.3:2408 握手成功，验证出口…
//
// 内层落点全部落在 2408/500/1701/4500 上。我们之前用探针扫出来的高位端口
// （1002/3854/7559…）当内层落点：0xcf 从隧道里能回，真握手零回包。
//
// 顺序：先所有 IP 的 2408，再 500 / 1701 / 4500，最后每个 anycast 段的 .1:2408
// （162.159.192.1 就是 engage.cloudflareclient.com 的地址，说明 .1 是真实入口）。
func innerLandingPool(seeds []string) []string {
	ips := make([]string, 0, len(seeds))
	seenIP := make(map[string]struct{}, len(seeds))
	addIP := func(s string) {
		ip := s
		if i := strings.LastIndexByte(s, ':'); i > 0 {
			ip = s[:i]
		}
		if ip == "" {
			return
		}
		if _, ok := seenIP[ip]; ok {
			return
		}
		seenIP[ip] = struct{}{}
		ips = append(ips, ip)
	}
	for _, s := range seeds {
		addIP(s)
	}

	out := make([]string, 0, len(ips)*4+len(cfIPv4Prefixes))
	seen := make(map[string]struct{}, cap(out))
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, p := range []int{2408, 500, 1701, 4500} {
		for _, ip := range ips {
			add(fmt.Sprintf("%s:%d", ip, p))
		}
	}
	for _, pfx := range cfIPv4Prefixes {
		add(pfx + ".1:2408")
	}
	return out
}

// aliveAddrs 把探活结果摊平成地址列表（已按 RTT 升序）。
func aliveAddrs(in []liveEndpoint) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.Addr)
	}
	return out
}

// capLandings 截到最多 n 个（输入已按 RTT 升序，所以截掉的就是最慢的）。
func capLandings(in []string, n int) []string {
	if n > 0 && len(in) > n {
		return in[:n]
	}
	return in
}

// buildInnerLayer 按 [endpoint] 建一层内层设备。tunFd > 0 时接管设备 tun，
// 否则挂到用户态协议栈上（GOOL + 赛风）。两种情况下内层的 UDP 都要塞进
// [outer] 这一层协议栈里出去。
func buildInnerLayer(inner Config, endpoint string, tunFd int, outer *userNet, logs *logRing, logger *device.Logger) (*innerLayer, error) {
	cfg := inner
	cfg.Endpoint = endpoint
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1280
	}
	bind, err := newTunnelBind(outer, endpoint)
	if err != nil {
		return nil, err
	}
	l := &innerLayer{bind: bind}
	if tunFd > 0 {
		l.tun, err = newFdTun(tunFd, mtu)
		if err != nil {
			return nil, err
		}
		l.dev = device.NewDevice(l.tun, bind, logger)
	} else {
		l.net, err = newUserNet(mtu, cfg.Address, cfg.DNS, logs)
		if err != nil {
			l.close()
			return nil, fmt.Errorf("GOOL 内层协议栈启动失败：%w", err)
		}
		bind.net = l.net
		l.dev = device.NewDevice(l.net.dev, bind, logger)
	}
	uapi, err := buildUAPI(cfg)
	if err != nil {
		l.close()
		return nil, fmt.Errorf("GOOL 内层 UAPI 生成失败：%w", err)
	}
	if err := l.dev.IpcSet(uapi); err != nil {
		l.close()
		return nil, fmt.Errorf("GOOL 内层配置失败：%w", err)
	}
	if err := l.dev.Up(); err != nil {
		l.close()
		return nil, fmt.Errorf("GOOL 内层启动失败：%w", err)
	}
	return l, nil
}

// waitHandshake 轮询 UAPI，直到对端握手成功或超时。
func waitHandshake(dev *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if dump, err := dev.IpcGet(); err == nil {
			if hs, _, _ := parseUAPIGet(dump); hs > 0 {
				return true
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// handshakeUnix 取当前设备的最后一次握手时间（Unix 秒，0 = 从没握上）。
func handshakeUnix(dev *device.Device) int64 {
	if dump, err := dev.IpcGet(); err == nil {
		hs, _, _ := parseUAPIGet(dump)
		return hs
	}
	return 0
}

// waitNewHandshake 等到「握手时间戳比 prev 更新」。
//
// 和 [waitHandshake] 的区别：last_handshake_time_sec 是**粘**的，同一个设备换过
// 落点之后它还是旧值。换落点重试时必须用这个，否则会立刻把「上一轮的旧握手」
// 当成这一轮成功。
func waitNewHandshake(dev *device.Device, prev int64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if handshakeUnix(dev) > prev {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// StartGool 用两份 WARP 身份建立 GOOL 隧道，并把内层挂到设备 tun 上。
func (e *Engine) StartGool(outerJSON, innerJSON string, tunFd int) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dev != nil || e.socks != nil || e.gool != nil || e.tunnel != nil {
		return fmt.Errorf("引擎已在运行，先 Stop()")
	}
	defer func() {
		if r := recover(); r != nil {
			e.logs.add("ERROR", fmt.Sprintf("StartGool 内部 panic（已拦截）：%v", r))
			err = fmt.Errorf("引擎内部错误：%v", r)
		}
	}()

	var outer, inner Config
	if err := json.Unmarshal([]byte(outerJSON), &outer); err != nil {
		return fmt.Errorf("外层配置解析失败: %w", err)
	}
	if err := json.Unmarshal([]byte(innerJSON), &inner); err != nil {
		return fmt.Errorf("内层配置解析失败: %w", err)
	}
	g, serr := startGool(outer, inner, tunFd, "", e.logs, e.logger())
	if serr != nil {
		return serr
	}
	e.gool = g
	// 记下外层配置：SwitchEndpoint 要用它的对端公钥，且目标就是外层设备。
	e.cfg = outer
	e.started = time.Now()
	return nil
}

// StartGoolTunnel 是 GOOL 的「不接管设备 tun」形态：内层挂到用户态协议栈上，
// 并在隧道里开一个 socks5（[socksAddr]）。原生核心 + Psiphon 用它——
// 赛风的每一条 TCP 从这个 socks 进内层隧道，再由外层隧道送出去。
func (e *Engine) StartGoolTunnel(outerJSON, innerJSON string, socksAddr string) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dev != nil || e.socks != nil || e.gool != nil || e.tunnel != nil {
		return fmt.Errorf("引擎已在运行，先 Stop()")
	}
	if socksAddr == "" {
		return fmt.Errorf("缺少隧道内 socks5 地址")
	}
	defer func() {
		if r := recover(); r != nil {
			e.logs.add("ERROR", fmt.Sprintf("StartGoolTunnel 内部 panic（已拦截）：%v", r))
			err = fmt.Errorf("引擎内部错误：%v", r)
		}
	}()

	var outer, inner Config
	if err := json.Unmarshal([]byte(outerJSON), &outer); err != nil {
		return fmt.Errorf("外层配置解析失败: %w", err)
	}
	if err := json.Unmarshal([]byte(innerJSON), &inner); err != nil {
		return fmt.Errorf("内层配置解析失败: %w", err)
	}
	g, serr := startGool(outer, inner, 0, socksAddr, e.logs, e.logger())
	if serr != nil {
		return serr
	}
	e.gool = g
	e.cfg = outer
	e.started = time.Now()
	return nil
}
