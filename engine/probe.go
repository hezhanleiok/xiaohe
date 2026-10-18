package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Cloudflare WARP 的端点不是「一个域名一个 IP」：它是一大片 anycast /24 上的
// 主机，每台开着一堆 UDP 端口。国内网络经常只拦其中一部分（某些 /24 整段死，
// 同一 IP 的 2408 死而 500 活），所以只盯 engage.cloudflareclient.com 解析出来
// 的那一个 IP，失败率极高。
//
// 这里照搬电脑版（E:\aether internal/wgtun）的做法：先做**无状态存活探测**——
// Cloudflare 对那 64 字节探针会回 5 字节 0xcf 标记，跟账号和密钥无关，所以
// 能在不建隧道的前提下把「这台机器到底通不通」问清楚；然后再拿存活的那几个去
// 真握手。

// cfIPv4Prefixes 是 WARP anycast 所在的 /24 段（与电脑版同一份清单）。
var cfIPv4Prefixes = []string{
	"8.6.112", "8.34.70", "8.34.146", "8.35.211",
	"8.39.125", "8.39.204", "8.39.214", "8.47.69",
	"162.159.192", "162.159.193", "162.159.195",
	"188.114.96", "188.114.97", "188.114.98", "188.114.99",
}

// warpPorts 是官方 WARP 的 54 个 UDP 端口。
var warpPorts = []int{
	4500, 2408, 500, 1701,
	854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
	943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074,
	1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233,
	5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
}

// stdPorts 是 WARP 的四个**标准** UDP 端口。
//
// ★ 0.1.29 起探测改成「标准端口优先」（对齐另一个项目 mihomo 核心的做法：
// 候选端点 × 端口 [2408 500 1701 4500]，它每次 10s 内就能连上）：
//
//	[tunnel] 候选端点 29 个 × 端口 [2408 500 1701 4500]（wg）
//	[tunnel] 8.6.112.3:2408 握手成功，验证出口…
//
// 我们之前是「每台主机随机映射到 54 个端口里的一个」，扫出来的大量高位端口
// （1002/3854/955/7103…）在手机上确实能握手，但它们的**寿命明显短**：
// 2026-10-19 00:00 那次连上 8.39.214.95:500 之后一路稳到 29MB 才断，而
// 23:57 那次连上的内层落点 8.39.204.1:2408 只撑了 9 秒。2408/500/1701/4500
// 是 IKE / IPsec / L2TP / WireGuard 的标准端口，运营商的中间设备对它们有
// 长期会话，不像高位端口那样一空闲就被清掉。
//
// 顺序有意义：2408 是 engage.cloudflareclient.com 的默认入口，实测最稳。
var stdPorts = []int{2408, 500, 1701, 4500}

// 探测分级（用户要求「首连尽量快、总时间可控」）。
//
// 之前是「小样本 300 个 → 一个都没活就扫全池 3810 个」，全池那一轮在手机上要
// 23~28s（2026-10-19 23:58:16→23:58:40 的 gen=2 就是 23.5s 全花在这上面）。
// 现在改成三级、共享一个 wall-clock 预算，超时就用已有结果：
//
//	1/3 标准端口 240 个   → 正常 0.5~1.5s 拿到 10 个活点
//	2/3 标准端口再 960 个 → 约 +2~5s
//	3/3 高位端口兜底 1200 → 约 +3~7s（直连 WG/AWG 在高位端口上确实能握手）
const (
	probePass1Addrs = 240
	probePass2Addrs = 960
	probePass3Addrs = 1200
	probeWorkers    = 128
	probeStopAfter  = 10
)

// standardPortAddr 把序号映射成「标准端口池」里的一个地址（纯函数，可按区间取，
// 不必把 15240 个地址全物化出来）。
//
// 布局决定抽样覆盖面：
//   - 前 len(cfIPv4Prefixes)*4 个：每个 anycast 段的 **.1**，四个标准端口轮转。
//     162.159.192.1 就是 engage.cloudflareclient.com 的地址，说明 .1 是真实入口，
//     命中率远高于随机主机号。
//   - 之后：主机号 × 端口 × 段 三维铺开，**端口在最内层轮转**，所以任何等步长
//     抽样都会同时覆盖四个端口，不会只扫到 2408。
func standardPortAddr(i int) (string, bool) {
	np := len(stdPorts)
	head := len(cfIPv4Prefixes) * np
	if i < 0 {
		return "", false
	}
	if i < head {
		return fmt.Sprintf("%s.1:%d", cfIPv4Prefixes[i/np], stdPorts[i%np]), true
	}
	j := i - head
	if j >= 254*len(cfIPv4Prefixes)*np {
		return "", false
	}
	port := stdPorts[j%np]
	k := j / np
	host := (k*97)%254 + 1
	prefix := cfIPv4Prefixes[k%len(cfIPv4Prefixes)]
	return fmt.Sprintf("%s.%d:%d", prefix, host, port), true
}

// standardPortSlice 取标准端口池的 [from, from+count) 这一段。
func standardPortSlice(from, count int) []string {
	if count <= 0 {
		return nil
	}
	out := make([]string, 0, count)
	for i := from; i < from+count; i++ {
		a, ok := standardPortAddr(i)
		if !ok {
			break
		}
		out = append(out, a)
	}
	return out
}

// widePoolSample 从历史的高位端口池里等步长抽 n 个（兜底用）。
func widePoolSample(n int) []string {
	pool := poolAddresses()
	if n <= 0 || n >= len(pool) {
		return pool
	}
	step := len(pool) / n
	if step < 1 {
		step = 1
	}
	out := make([]string, 0, n)
	for i := 0; i < len(pool) && len(out) < n; i += step {
		out = append(out, pool[i])
	}
	return out
}

// cfProbePacket 是 WARP 的无状态存活探针（64 字节）。活着的端点会回 5 字节
// (0xcf 00 00 00 00)，与账号/密钥无关。
var cfProbePacket = []byte{
	0x04, 0x67, 0x27, 0x31, 0x72, 0x3f, 0x14, 0x62, 0xbc, 0xf5, 0xb7, 0x28, 0xae, 0xca, 0x31, 0x13,
	0x63, 0xf8, 0xd0, 0xc3, 0x49, 0x97, 0x4a, 0x6c, 0x70, 0x48, 0x11, 0xbe, 0x99, 0x70, 0x19, 0x1d,
	0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xed, 0x1b,
	0xed, 0x21, 0x65, 0x69, 0x02, 0xb9, 0xd8, 0xf3, 0xc2, 0xbd, 0x7d, 0x98, 0xda,
}

type liveEndpoint struct {
	Addr    string `json:"addr"`
	Latency int64  `json:"latency"`
}

// poolAddresses 生成候选池：每个 /24 的 254 个主机，各自映射到一个端口
// (host%54)。host 用 97 步进（与 254 互质），保证任何前缀切片都均匀铺满
// 所有 /24 和整个 host 区间——早期停止时才不会只看到某个段。
func poolAddresses() []string {
	portCount := len(warpPorts)
	out := make([]string, 0, len(cfIPv4Prefixes)*254)
	for i := 0; i < 254; i++ {
		host := (i*97)%254 + 1
		for _, prefix := range cfIPv4Prefixes {
			out = append(out, fmt.Sprintf("%s.%d:%d", prefix, host, warpPorts[host%portCount]))
		}
	}
	return out
}

// ProbeEndpoints 扫一遍端点池，返回按 RTT 排序的存活端点（JSON 数组）。
//
// perProbeTimeoutMs：单个探针的超时；limit：**第一级**扫多少个地址（0 = 默认）；
// budgetMs：整轮探活的 wall-clock 预算（0 = 8s），超时立刻用已有结果返回。
//
// 顺序是「标准端口优先、高位端口兜底」，见 stdPorts 的注释。
func (e *Engine) ProbeEndpoints(perProbeTimeoutMs int, limit int, budgetMs int) string {
	timeout := time.Duration(perProbeTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 600 * time.Millisecond
	}
	budget := time.Duration(budgetMs) * time.Millisecond
	if budget <= 0 {
		budget = 8 * time.Second
	}
	deadline := time.Now().Add(budget)

	p1 := limit
	if p1 <= 0 {
		p1 = probePass1Addrs
	}

	// 三级共用一条 live 切片：**不跨级重排**，标准端口永远排在前面。
	// 这样上层拿到的前几个候选就是「标准端口 + 快」，端点质量有保证。
	var live []liveEndpoint
	started := time.Now()
	live = append(live, probePoolUntil(standardPortSlice(0, p1), timeout, probeWorkers, probeStopAfter, deadline)...)
	e.logs.add("INFO", fmt.Sprintf(
		"探活 1/3：标准端口 %d 个地址，存活 %d 个（%dms）",
		p1, len(live), time.Since(started).Milliseconds(),
	))

	if len(live) < 4 && time.Now().Before(deadline) {
		n := probePass2Addrs
		if n < p1 {
			n = p1
		}
		more := probePoolUntil(standardPortSlice(p1, n), timeout, probeWorkers, probeStopAfter, deadline)
		live = append(live, more...)
		e.logs.add("INFO", fmt.Sprintf(
			"探活 2/3：标准端口再扫 %d 个，累计存活 %d 个（%dms）",
			n, len(live), time.Since(started).Milliseconds(),
		))
	}

	if len(live) < 4 && time.Now().Before(deadline) {
		wide := widePoolSample(probePass3Addrs)
		more := probePoolUntil(wide, timeout, probeWorkers, probeStopAfter, deadline)
		live = append(live, more...)
		e.logs.add("INFO", fmt.Sprintf(
			"探活 3/3：高位端口兜底 %d 个，累计存活 %d 个（%dms）",
			len(wide), len(live), time.Since(started).Milliseconds(),
		))
	}

	if len(live) == 0 {
		e.logs.add("WARN", fmt.Sprintf("端点存活探测：%dms 内一个都没探活（本网络很可能整体拦了 WARP 的 UDP）", time.Since(started).Milliseconds()))
	}
	top := live
	if len(top) > 12 {
		top = top[:12]
	}
	for _, ep := range top {
		e.logs.add("INFO", fmt.Sprintf("存活端点 %s（%dms）", ep.Addr, ep.Latency))
	}
	b, err := json.Marshal(top)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// probePoolUntil 并发探一批地址，返回按 RTT 升序的存活端点。
//
// deadline 非零时，到点就停止发新探针，并把单个探针的超时钳到剩余预算 ——
// 这是「总时间可控」的落地点：以前全池 3810 个地址能跑 23~28s。
func probePoolUntil(pool []string, timeout time.Duration, workers, stopAfter int, deadline time.Time) []liveEndpoint {
	if len(pool) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = 96
	}
	if workers > len(pool) {
		workers = len(pool)
	}
	// 先把任务塞进带缓冲的 channel：worker 提前退出也不会让生产者卡死。
	jobs := make(chan string, len(pool))
	for _, a := range pool {
		jobs <- a
	}
	close(jobs)

	var (
		mu       sync.Mutex
		live     []liveEndpoint
		cancel   int32
		inflight sync.WaitGroup
	)
	inflight.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer inflight.Done()
			for addr := range jobs {
				if atomic.LoadInt32(&cancel) == 1 {
					return
				}
				t := timeout
				if !deadline.IsZero() {
					rest := time.Until(deadline)
					if rest <= 0 {
						return
					}
					if rest < t {
						t = rest
					}
				}
				if ms, ok := probeOnce(addr, t); ok {
					mu.Lock()
					live = append(live, liveEndpoint{Addr: addr, Latency: ms})
					full := len(live) >= stopAfter
					mu.Unlock()
					if full {
						atomic.StoreInt32(&cancel, 1)
						return
					}
				}
			}
		}()
	}
	inflight.Wait()

	sort.Slice(live, func(i, j int) bool { return live[i].Latency < live[j].Latency })
	return live
}

// probeWarpThrough 从**隧道里**发一个 WARP 存活探针（0xcf），证明这个落点
// 「从隧道内部可达」。
//
// 为什么必须单独有这一版：probeOnce 走的是物理网络，量到的是「手机上能不能
// 直达这个 IP:端口」。GOOL 的内层包是从外层 WARP 里出去的，两条路径的可达性
// 完全不同 —— 2026-10-18 23:12 的日志里，内层落点 8.39.214.187:1002 /
// 8.39.214.201:3854 / 188.114.97.99:7103 全都是刚在手机上真握手通过的端点，
// 换成「从外层隧道里发」之后，两个落点各 8s 零回包（userNet rx 一直停在 112
// 不动），而外层握手和数据面全程都是好的。
func (u *userNet) probeWarpThrough(addr string, timeout time.Duration) (int64, bool) {
	c, err := u.DialUDP(addr)
	if err != nil {
		return 0, false
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := c.Write(cfProbePacket); err != nil {
		return 0, false
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil || n < 5 {
		return 0, false
	}
	if buf[0] != 0xcf || buf[1] != 0 || buf[2] != 0 || buf[3] != 0 || buf[4] != 0 {
		return 0, false
	}
	ms := time.Since(start).Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	return ms, true
}

// probeWarpThroughPool 并发地从隧道里探一批落点，按 RTT 升序返回活着的。
//
// 这里不做「够数就提前收工」：内层落点只要 1~4 个，全扫完也就一个探针超时的
// 时间（1.5s），早退省不下什么，反而可能错过最快的那个。
func (u *userNet) probeWarpThroughPool(addrs []string, timeout time.Duration, workers int) []liveEndpoint {
	if len(addrs) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = 12
	}
	if workers > len(addrs) {
		workers = len(addrs)
	}
	jobs := make(chan string, len(addrs))
	for _, a := range addrs {
		jobs <- a
	}
	close(jobs)

	var (
		mu   sync.Mutex
		live []liveEndpoint
		wg   sync.WaitGroup
	)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for addr := range jobs {
				if ms, ok := u.probeWarpThrough(addr, timeout); ok {
					mu.Lock()
					live = append(live, liveEndpoint{Addr: addr, Latency: ms})
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	sort.Slice(live, func(i, j int) bool { return live[i].Latency < live[j].Latency })
	return live
}

// probeOnce 发一个探针，只认 0xcf 0000 0000 这个标记。
func probeOnce(addr string, timeout time.Duration) (int64, bool) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, false
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := conn.Write(cfProbePacket); err != nil {
		return 0, false
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return 0, false
	}
	if buf[0] != 0xcf || buf[1] != 0 || buf[2] != 0 || buf[3] != 0 || buf[4] != 0 {
		return 0, false
	}
	ms := time.Since(start).Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	return ms, true
}
