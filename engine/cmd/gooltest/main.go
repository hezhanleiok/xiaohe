//go:build !android

// gooltest 是 GOOL（warp-in-warp）的离线实验工具，跑在电脑上，不进 APK。
//
// 它直接调用引擎里真实的 startGool / userNet 代码（tunFd=0 的隧道形态），
// 所以测出来的结论对手机上那套逻辑有效——以前为了绕开 unix.Dup 把逻辑抄到
// .tmp 里，抄出来的副本和真实代码越走越远，这次不再抄。
//
// 用法（在 engine 目录）：
//
//	go run ./cmd/gooltest -inner fixed      # 内层用固定端点 162.159.192.1:2408
//	go run ./cmd/gooltest -inner scan       # 内层改用另一个扫描到的边缘
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	engine "ther/engine"
)

const fixedInner = "162.159.192.1:2408"

type liveEp struct {
	Addr string `json:"addr"`
	Ms   int64  `json:"ms"`
}

func main() {
	innerMode := flag.String("inner", "fixed", "fixed | scan")
	attempts := flag.Int("attempts", 2, "how many outer endpoints to try")
	doScreen := flag.Bool("prescreen", true, "screen candidates with a one-shot handshake first")
	flag.Parse()

	probe := engine.NewEngine()
	outerJSON, err := probe.ProvisionWARP()
	must(err, "注册外层身份")
	innerJSON, err := probe.ProvisionWARP()
	must(err, "注册内层身份")
	fmt.Println("identities ready")

	var live []liveEp
	must(json.Unmarshal([]byte(probe.ProbeEndpoints(700, 600, 8000)), &live), "解析探活结果")
	fmt.Printf("live=%d\n", len(live))

	n := len(live)
	if n > 6 {
		n = 6
	}
	cands := make([]string, 0, n)
	for i := 0; i < n; i++ {
		cands = append(cands, live[i].Addr)
	}

	// -prescreen 时先用「一次性真握手」筛一遍；但注意：同一身份 1~2 秒内对同一
	// 端点连着握手，边缘可能直接不理第二次（实测预筛通过、紧接着 GOOL 又握不上）。
	// 所以想测生产路径（生产不做预筛）就用 -prescreen=false。
	verified := cands
	if *doScreen {
		cfg := fmt.Sprintf(`{"privateKey":%q,"peerPublicKey":%q,"mtu":1280,"keepalive":5}`,
			field(outerJSON, "privateKey"), field(outerJSON, "peerPublicKey"))
		out := probe.ProbeHandshake(cfg, candsJSON(cands), 7000, 6)
		verified = parseVerified(out)
	}
	fmt.Printf("outer candidates=%d verified=%v\n", len(cands), verified)

	if len(verified) == 0 {
		fmt.Println("RESULT: 没有能完成外层握手的端点，GOOL 无从开始")
		return
	}
	if len(verified) < *attempts {
		*attempts = len(verified)
	}

	for i := 0; i < *attempts; i++ {
		outer := verified[i]
		inner := fixedInner
		if *innerMode == "scan" {
			// 与电脑版一致：内外两层必须是两个不同的边缘（同一个 IP 会被拒绝）。
			inner = ""
			for _, v := range verified {
				if !strings.HasPrefix(v, strings.Split(outer, ":")[0]+":") {
					inner = v
					break
				}
			}
			if inner == "" {
				fmt.Printf("\n--- outer=%s: 没有第二个不同的边缘，跳过\n", outer)
				continue
			}
		}
		fmt.Printf("\n=== attempt %d/%d  outer=%s  inner=%s ===\n", i+1, *attempts, outer, inner)
		tryOne(outerJSON, innerJSON, outer, inner)
	}
}

func tryOne(outerJSON, innerJSON, outer, inner string) {
	e := engine.NewEngine()
	e.SetClockOffsetMinutes(480)

	started := time.Now()
	err := e.StartGoolTunnel(patchEndpoint(outerJSON, outer), patchEndpoint(innerJSON, inner), "127.0.0.1:1081")
	if err != nil {
		fmt.Printf("start 失败（%.1fs）：%v\n", time.Since(started).Seconds(), err)
		fmt.Println(e.DrainLogs())
		return
	}
	defer e.Stop()
	fmt.Printf("start 返回：%.1fs  status=%s\n", time.Since(started).Seconds(), e.StatusJSON())

	// 数据面：从隧道里的 socks5 拉一次 HTTP。这比握手更能说明端点质量。
	ok, detail := httpThroughSocks("127.0.0.1:1081", "104.16.132.229:80", "one.one.one.one")
	fmt.Printf("数据面 HTTP：ok=%v（%s）\n", ok, detail)
	fmt.Println("=== engine logs ===")
	fmt.Println(e.DrainLogs())
}

func httpThroughSocks(socksAddr, target, host string) (bool, string) {
	c, err := socks5Connect(socksAddr, target, 8*time.Second)
	if err != nil {
		return false, "socks 拨号失败：" + err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	req := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return false, "写请求失败：" + err.Error()
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return false, "读响应失败：" + err.Error()
	}
	line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	return strings.Contains(line, "200") || strings.Contains(line, "301") || strings.Contains(line, "HTTP/"), "响应：" + line
}

// socks5Connect 最小 socks5 CONNECT（只给这个工具用）。
func socks5Connect(socksAddr, target string, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", socksAddr, timeout)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = c.Close()
		return nil, err
	}
	var ack [2]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		_ = c.Close()
		return nil, err
	}
	if ack[0] != 0x05 || ack[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("socks 不接受无认证（%v）", ack)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	port, _ := net.LookupPort("tcp", portStr)
	ip := net.ParseIP(host).To4()
	if ip == nil {
		_ = c.Close()
		return nil, fmt.Errorf("目标 %q 不是 IPv4", host)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, err
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		_ = c.Close()
		return nil, err
	}
	if rep[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("socks CONNECT 被拒（code=%d）", rep[1])
	}
	return c, nil
}

func candsJSON(cands []string) string {
	var b strings.Builder
	b.WriteString("[")
	for i, c := range cands {
		if i > 0 {
			b.WriteString(",")
		}
		q, _ := json.Marshal(c)
		b.Write(q)
	}
	b.WriteString("]")
	return b.String()
}

func parseVerified(text string) []string {
	rows := strings.Split(strings.TrimSpace(text), "\n")
	out := make([]string, 0, len(rows))
	for _, r := range rows[1:] {
		if addr := strings.TrimSpace(strings.SplitN(r, "\t", 2)[0]); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

func field(js, key string) string {
	var m map[string]any
	_ = json.Unmarshal([]byte(js), &m)
	s, _ := m[key].(string)
	return s
}

func patchEndpoint(js, endpoint string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		return js
	}
	m["endpoint"] = endpoint
	// 注册返回的是「ipv4 / dns 数组」，而 engine.Config 要的是 address / dns 字符串；
	// App 那边是自己拼 JSON 的（NativeCore.goolOuterConfig），这里补同样的转换，
	// 否则 StartGool 直接报「配置解析失败 / 缺少隧道接口地址」。
	if v, ok := m["ipv4"].(string); ok && v != "" {
		m["address"] = v
	}
	if list, ok := m["dns"].([]any); ok && len(list) > 0 {
		first, _ := list[0].(string)
		m["dns"] = first
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func must(err error, what string) {
	if err != nil {
		fmt.Printf("%s 失败：%v\n", what, err)
		os.Exit(1)
	}
}
