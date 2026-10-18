package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// 这个文件是电脑版 internal/wgtun/probe.go 的移植：**一次性握手预筛**（二级闸门）。
//
// 为什么需要它：第一级探针（probe.go 里的 0xcf 无状态包）只能证明「这台机器对
// 这个 UDP 五元组有回包」，跟账号、密钥、握手都无关。2026-10-18 的手机日志就是
// 典型：探活到 12 个端点、6 个候选全部 rx=0 —— 探针通，握手一个都不回。而原来的
// 上层逻辑对每个候选都开一次真隧道、等满预算（GOOL 是 15s × 6 = 90s），用户在
// 「正在握手」上白等一分半才被告知失败。
//
// 这里的做法：起一个**丢弃一切包的假 tun**，配一个普通的宿主 UDP bind，跑真正的
// wireguard-go 握手，靠 UAPI 里的 last_handshake_time_sec 判断成败。它不建 tun
// 设备、不装路由、不碰系统，所以可以在 establish() 之前、并行地对多个候选做。
//
// 它只是**排序/过滤**：真隧道仍然会对自己拿到的每个候选重新握手，所以这里的一次
// 假阴性最多是少试一个候选，不会把能用的端点判死（单个候选时更是直接放行）。

const (
	// 并发数。每个探针都会拉起全套 wireguard-go worker，所以这是 CPU/内存上限，
	// 不是链路上限；手机上和电脑版取同一个值。
	hsProbeWorkers = 6

	// 单个候选的握手预算。WireGuard 的握手重传是 5s，这里要盖住一次重传 + 慢 RTT，
	// 但必须明显小于真隧道的等待，否则「快速失败」就没意义了。
	hsProbeTimeoutMS = 7000

	// 第一个成功之后再多收多久。
	//
	// 不能一成功就立刻取消：那样候选列表就只剩「谁先回包谁赢」，一旦这个赢家的真
	// 隧道握手失败（预筛已知会有假阳性），整次连接就直接判死。电脑版在
	// 2026-10-17 正是这么炸的。给一秒窗口，让几乎同时成功的候选都能报上来。
	hsProbeWindow = time.Second

	// 轮询 IpcGet 的间隔（握手完成时间戳只精确到秒，没必要更密）。
	hsProbePollPeriod = 200 * time.Millisecond
)

// hsProbeResult 是预筛通过的候选，ms 是握手往返耗时（越小越好）。
type hsProbeResult struct {
	Addr string `json:"addr"`
	Ms   int64  `json:"ms"`
}

// dummyTun 是一个丢弃全部报文、从不触碰系统的 tun.Device：
// 有了它，wireguard-go 才能在不创建 VpnService tun、不分配地址、不装路由的前提下
// 跑一次完整握手。
type dummyTun struct {
	mtu    int
	closed chan struct{}
	ev     chan tun.Event
}

func newDummyTun(mtu int) *dummyTun {
	if mtu <= 0 {
		mtu = 1280
	}
	return &dummyTun{mtu: mtu, closed: make(chan struct{}), ev: make(chan tun.Event, 1)}
}

func (d *dummyTun) File() *os.File { return nil }

// Read 一直阻塞到 Close：真 tun 在没有报文时也是这样。阻塞（而不是空转）是让
// 一次性设备足够便宜的关键 —— wireguard-go 的读协程会挂在这上面。
func (d *dummyTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-d.closed
	return 0, os.ErrClosed
}

func (d *dummyTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (d *dummyTun) MTU() (int, error)                            { return d.mtu, nil }
func (d *dummyTun) Name() (string, error)                        { return "hsprobe", nil }
func (d *dummyTun) Events() <-chan tun.Event                     { return d.ev }
func (d *dummyTun) BatchSize() int                               { return 1 }

func (d *dummyTun) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
		close(d.ev)
	}
	return nil
}

// ProbeHandshake 对候选端点做一次性真握手预筛，返回**真的握上了手**的候选。
//
// 参数：cfgJSON 与 Start 用的是同一份配置（私钥/对端公钥/mtu 会用到，endpoint
// 被逐个覆盖）；candsJSON 是 "ip:port" 的 JSON 数组。
//
// 返回**纯文本**，不用 JSON（跨 gomobile/org.json 的往返曾经踩过坑：空结果会被
// 序列化成 `null`，Kotlin 侧解析抛异常，整条预筛静默失效）：
//
//	第一行：通过的数量 n
//	之后 n 行：`ip:port<TAB>握手耗时ms`，按耗时升序
//
// 预筛用的配置与真实会话一致（含 AWG 的 junk/i1）：只有「用什么发就怎么验」，
// 排序结果才代表真实会话能不能握手。keepalive 由预筛自己补（见
// probeHandshakeOnce 的注释：不带 keepalive 就一个 initiation 都不会发）。
func (e *Engine) ProbeHandshake(cfgJSON string, candsJSON string, perTimeoutMs int64, workers int64) string {
	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		e.logs.add("ERROR", fmt.Sprintf("握手预筛：配置解析失败 %v", err))
		return "0\n"
	}
	var cands []string
	if err := json.Unmarshal([]byte(candsJSON), &cands); err != nil {
		e.logs.add("ERROR", fmt.Sprintf("握手预筛：候选解析失败 %v", err))
		return "0\n"
	}
	// 去重，保持顺序（顺序就是上一级探针按 RTT 排好的顺序）。
	seen := make(map[string]struct{}, len(cands))
	uniq := make([]string, 0, len(cands))
	for _, c := range cands {
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		uniq = append(uniq, c)
	}
	if len(uniq) == 0 {
		return "0\n"
	}

	timeout := time.Duration(perTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = hsProbeTimeoutMS * time.Millisecond
	}
	nWorkers := int(workers)
	if nWorkers <= 0 {
		nWorkers = hsProbeWorkers
	}
	if nWorkers > len(uniq) {
		nWorkers = len(uniq)
	}

	started := time.Now()
	ok := rankCandidatesByHandshake(cfg, uniq, timeout, nWorkers)

	// 排序后再输出：上层拿到的第一个就是握手最快的那台。
	sort.Slice(ok, func(i, j int) bool { return ok[i].Ms < ok[j].Ms })
	if len(ok) == 0 {
		e.logs.add("WARN", fmt.Sprintf(
			"握手预筛：%d 个候选全部没握上手（耗时 %dms，keepalive=%ds，junk=%d）——探针通但握手无回包，通常是 DPI 丢弃了握手",
			len(uniq), time.Since(started).Milliseconds(), cfg.Keepalive, cfg.JunkCount))
	} else {
		best := ok[0]
		e.logs.add("INFO", fmt.Sprintf(
			"握手预筛：%d 个候选中 %d 个真握手通过（最快 %s %dms，总耗时 %dms，keepalive=%ds，junk=%d）",
			len(uniq), len(ok), best.Addr, best.Ms, time.Since(started).Milliseconds(),
			cfg.Keepalive, cfg.JunkCount))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d\n", len(ok))
	for _, r := range ok {
		fmt.Fprintf(&b, "%s\t%d\n", r.Addr, r.Ms)
	}
	return b.String()
}

// rankCandidatesByHandshake 并行跑一次性握手，只返回**真正完成握手**的候选。
//
// 第一个成功不再立刻取消（见 hsProbeWindow 的注释），只启动一次收集窗口；
// 窗口到期才取消剩下的探针。返回顺序是完成顺序，排序由调用方做。
func rankCandidatesByHandshake(cfg Config, cands []string, timeout time.Duration, workers int) []hsProbeResult {
	// 只有一个候选时不做过滤：假阴性会把唯一的机会掐掉。仍然探一次，只是结果
	// 无论成败都要把它交回去（调用方从日志里能看出它其实没握上）。
	if len(cands) == 1 {
		one := cands[0]
		ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
		defer cancel()
		if ms, ok := probeHandshakeOnce(ctx, cfg, one, timeout); ok {
			return []hsProbeResult{{Addr: one, Ms: ms}}
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		mu   sync.Mutex
		done []hsProbeResult
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, workers)

	var collectOnce sync.Once
	collect := func() {
		collectOnce.Do(func() {
			time.AfterFunc(hsProbeWindow, cancel)
		})
	}

schedule:
	for _, addr := range cands {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break schedule
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			ms, ok := probeHandshakeOnce(ctx, cfg, addr, timeout)
			if !ok {
				return
			}
			mu.Lock()
			done = append(done, hsProbeResult{Addr: addr, Ms: ms})
			mu.Unlock()
			collect()
		}(addr)
	}
	wg.Wait()
	return done
}

// probeHandshakeOnce 对一个端点跑一次一次性握手，返回握手耗时与是否成功。
func probeHandshakeOnce(ctx context.Context, cfg Config, endpoint string, timeout time.Duration) (int64, bool) {
	probe := cfg
	probe.Endpoint = endpoint
	// ★ 必须带 keepalive，否则这次握手**永远不会发出去**。
	//
	// wireguard-go 不会在设备起来时主动握手（device.upLocked 只在
	// persistentKeepaliveInterval > 0 时才 SendKeepalive），真正触发握手的路径是
	// 「有包要发」→ SendStagedPackets → 没有 keypair → SendHandshakeInitiation。
	// 这里的假 tun（dummyTun）丢弃一切、永不产生上行包，所以没有 keepalive 就
	// 一条 initiation 都不会发：2026-10-18 A/B 实测（同一份身份、同一批活端点、
	// 同一个二进制，只有 keepalive 不同）——
	//
	//	keepalive=0：握手发起=0  收到握手响应=0  → 0/4
	//	keepalive=5：握手发起=5  收到握手响应=3  → 3/4
	//
	// 后果是预筛恒返回空 → NativeCore 只留 2 个兜底端点 → WG/AWG/GOOL 全线连不上。
	if probe.Keepalive <= 0 || probe.Keepalive > 10 {
		probe.Keepalive = 5
	}
	// 混淆必须与真实会话一致：这条线路上「明文握手」和「junk 握手」能被放行的
	// 端点集合并不相同（2026-10-18 实测同一批活端点里两者的成功集合有差异），
	// 用干净握手替 AWG 排序会挑出实际握不上的端点。i1 同理，跟着 cfg 走。
	uapi, err := buildUAPI(probe)
	if err != nil {
		return 0, false
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	}
	dev := device.NewDevice(newDummyTun(probe.MTU), conn.NewDefaultBind(), logger)
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		return 0, false
	}
	if err := dev.Up(); err != nil {
		return 0, false
	}
	start := time.Now()
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return 0, false
		default:
		}
		if dump, gerr := dev.IpcGet(); gerr == nil {
			if hs, _, _ := parseUAPIGet(dump); hs > 0 {
				ms := time.Since(start).Milliseconds()
				if ms <= 0 {
					ms = 1
				}
				return ms, true
			}
		}
		time.Sleep(hsProbePollPeriod)
	}
	return 0, false
}
