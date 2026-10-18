package engine

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// 这个文件解决的是「隧道在 IP 层，但我们需要在隧道**里面**再拨 TCP/UDP」这件事。
//
// 两处用到：
//   - GOOL（wireguard in wireguard）：内层设备的 UDP 对端只能从外层隧道里出去，
//     所以需要一个挂在「外层隧道」上的协议栈来发包；
//   - 原生核心 + 赛风出口：赛风要「隧道内第二跳」，它需要一个 socks5 上游，
//     而这个 socks5 必须把 TCP 拨进隧道——同样得有一层用户态协议栈。
//
// 方向和 socks.go 正好相反：socks.go 是「tun 里的包 → 本地 SOCKS」，
// 这里是「本进程要拨的包 → tun（交给 wireguard-go 加密）」。

const userNetNIC = tcpip.NICID(2)

// ------------------------------------------------------------------
// userTun：给 wireguard-go 用的内存 tun
// ------------------------------------------------------------------

// userTun 把 wireguard-go 需要的 tun.Device 换成两个 channel：
// in 是「设备解密后交给系统」的包（我们灌进协议栈），out 是「系统要发出去」的包
// （协议栈产生，wireguard-go 读走后加密发送）。
type userTun struct {
	mtu    int
	in     chan []byte
	out    chan []byte
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newUserTun(mtu int) *userTun {
	t := &userTun{
		mtu: mtu,
		// 赛风链的接收窗口放大后，突发的包会一下子涌进来，256 太小会导致
		// pumpStackToDev 频繁阻塞在 channel 上，反过来卡住协议栈的读循环。
		in:     make(chan []byte, 1024),
		out:    make(chan []byte, 1024),
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *userTun) File() *os.File           { return nil }
func (t *userTun) MTU() (int, error)        { return t.mtu, nil }
func (t *userTun) Name() (string, error)    { return "ther-usernet", nil }
func (t *userTun) Events() <-chan tun.Event { return t.events }
func (t *userTun) BatchSize() int           { return 1 }

func (t *userTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.out:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-t.closed:
		return 0, net.ErrClosed
	}
}

func (t *userTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := append([]byte(nil), b[offset:]...)
		select {
		case t.in <- pkt:
		case <-t.closed:
			return 0, net.ErrClosed
		}
	}
	return len(bufs), nil
}

func (t *userTun) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// ------------------------------------------------------------------
// userNet：挂在 userTun 上的协议栈
// ------------------------------------------------------------------

// userNet 让本进程能「从隧道里」拨出 TCP/UDP。
//
// 地址用 WARP 注册拿到的接口地址（172.16.0.2），路由全指到网卡上，
// 于是任何拨号都会变成发进 userTun 的 IP 包，被 wireguard-go 加密。
type userNet struct {
	dev  *userTun
	ep   *channel.Endpoint
	st   *stack.Stack
	mtu  int
	addr tcpip.Address

	// dns 是「隧道内」的 DNS 服务器（默认 1.1.1.1）。
	//
	// 为什么必须走隧道解析：隧道内 socks 收到的 CONNECT 常常是域名（赛风的
	// 前置域名、S3 服务器列表、psiphon 的服务器地址）。如果在物理网络上解析，
	// 这些域名在国内会拿到污染地址，于是拨过去直接被 RST —— psiphon 日志里那句
	// `meek round trip failed: socks connect tcp ...: connection refused` 就是
	// 这么来的（隧道本身是通的，坏在域名落到了假 IP 上）。
	dns string

	// dnsCache 缓存隧道内解析结果（域名 → IP，带过期时间）。
	// 赛风会在几秒内对同一个前置域名发起几十条连接，每次都查一遍 DNS 会让
	// 每一条都多一个 RTT。
	dnsCache sync.Map

	// 数据面字节计数（上行=协议栈发出交给 wireguard 加密，下行=wireguard 解密后进协议栈）。
	// 用来区分「握手通、数据面不通」时到底卡在上行还是下行。
	rxBytes atomic.Int64
	txBytes atomic.Int64

	logs   *logRing
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func newUserNet(mtu int, ifaceAddr string, dns string, logs *logRing) (*userNet, error) {
	if mtu <= 0 {
		mtu = 1420
	}
	protoAddr, err := parseIfaceAddr(ifaceAddr)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dns) == "" {
		dns = "1.1.1.1"
	}
	u := &userNet{
		dev:    newUserTun(mtu),
		mtu:    mtu,
		addr:   protoAddr.AddressWithPrefix.Address,
		dns:    strings.TrimSpace(dns),
		logs:   logs,
		closed: make(chan struct{}),
	}
	ep := channel.New(4096, uint32(mtu), "")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := st.CreateNIC(userNetNIC, ep); err != nil {
		return nil, fmt.Errorf("创建协议栈网卡失败: %v", err)
	}
	if err := st.SetPromiscuousMode(userNetNIC, true); err != nil {
		return nil, fmt.Errorf("开启混杂模式失败: %v", err)
	}
	if err := st.SetSpoofing(userNetNIC, true); err != nil {
		return nil, fmt.Errorf("开启地址伪装失败: %v", err)
	}
	if err := st.AddProtocolAddress(userNetNIC, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("配置接口地址 %s 失败: %v", ifaceAddr, err)
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: userNetNIC},
		{Destination: header.IPv6EmptySubnet, NIC: userNetNIC},
	})
	u.ep, u.st = ep, st
	tuneUserNetStack(st, logs)

	u.wg.Add(2)
	go u.pumpStackToDev()
	go u.pumpDevToStack()
	u.wg.Add(1)
	go u.logStats()
	return u, nil
}

// tuneUserNetStack 把「隧道内」协议栈的 TCP 窗口大幅放大。
//
// 为什么 userNet 必须单独调大（socksTun 那份 4MB 对这里不够）：
// 赛风链的跨公网段就在这条 gonet TCP 上——设备流量经赛风绕一圈后，从这里穿过
// wireguard 隧道到赛风服务器再出公网。这段 RTT 是秒级（赛风服务器自己测到
// cloudflare 都要 1.4~1.9s）。gVisor 默认 1MB 接收窗口在 1.8s RTT 下天花板只有
// ~4.4Mbps，和实测「开赛风只剩 1~4Mbps」完全吻合。
//
// 直连 WG 能到一两百兆，是因为那条链路 RTT 只有 20~100ms；赛风慢不是隧道不行，
// 而是「窗口 / 秒级 RTT」这个天花板没被抬起来。接收窗口默认抬到 16MB
// （1.8s RTT → ~71Mbps 上限），上限 32MB 留给更差的线路。
//
// moderation 特意关掉：它本意是限制内存，但会按 cwnd 收缩窗口，高 RTT 链路上
// 反而把好不容易长起来的大窗口又打回去。这里要的是窗口稳定钉在 Default 上。
func tuneUserNetStack(st *stack.Stack, logs *logRing) {
	recv := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     64 << 10,
		Default: 16 << 20,
		Max:     32 << 20,
	}
	send := tcpip.TCPSendBufferSizeRangeOption{
		Min:     64 << 10,
		Default: 8 << 20,
		Max:     32 << 20,
	}
	sack := tcpip.TCPSACKEnabled(true)
	recovery := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)
	moderate := tcpip.TCPModerateReceiveBufferOption(false)

	set := func(name string, opt tcpip.SettableTransportProtocolOption) {
		if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			logs.add("WARN", fmt.Sprintf("隧道内协议栈调优（%s）失败：%v", name, err))
		}
	}
	set("接收窗口", &recv)
	set("发送窗口", &send)
	set("SACK", &sack)
	set("RACK 丢包检测", &recovery)
	set("接收窗口 moderation", &moderate)
	logs.add("INFO", fmt.Sprintf("隧道内协议栈已调优：接收窗口 %dKB / 上限 %dKB（赛风链高 RTT 靠它撑吞吐）",
		(16<<20)/1024, (32<<20)/1024))
}

func parseIfaceAddr(raw string) (tcpip.ProtocolAddress, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return tcpip.ProtocolAddress{}, fmt.Errorf("缺少隧道接口地址（WARP 身份里的 ipv4）")
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return tcpip.ProtocolAddress{}, fmt.Errorf("隧道接口地址无效: %q", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return tcpip.ProtocolAddress{
			Protocol: header.IPv4ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4Slice(v4),
				PrefixLen: 32,
			},
		}, nil
	}
	v6 := ip.To16()
	return tcpip.ProtocolAddress{
		Protocol: header.IPv6ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(v6),
			PrefixLen: 128,
		},
	}, nil
}

func (u *userNet) pumpStackToDev() {
	defer u.wg.Done()
	notify := make(notifyChan, 1)
	u.ep.AddNotify(notify)
	for {
		select {
		case <-u.closed:
			return
		case <-notify:
		}
		for {
			pb := u.ep.Read()
			if pb == nil {
				break
			}
			view := pb.ToView()
			b := append([]byte(nil), view.AsSlice()...)
			pb.DecRef()
			select {
			case u.dev.out <- b:
				u.txBytes.Add(int64(len(b)))
			case <-u.closed:
				return
			}
		}
	}
}

func (u *userNet) pumpDevToStack() {
	defer u.wg.Done()
	for {
		select {
		case <-u.closed:
			return
		case pkt := <-u.dev.in:
			if len(pkt) < 20 {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch pkt[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			u.rxBytes.Add(int64(len(pkt)))
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
			u.ep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}
}

// logStats 周期打印数据面字节计数，用来在「握手通、数据不通」时定位断点：
// tx 只涨 rx 不涨 = 上行发出去了但下行回不来；两者都不涨 = 数据根本没进协议栈。
func (u *userNet) logStats() {
	defer u.wg.Done()
	for {
		select {
		case <-u.closed:
			return
		case <-time.After(5 * time.Second):
			u.logs.add("DEBUG", fmt.Sprintf("userNet 数据面统计：rx=%d tx=%d（rx=下行进栈，tx=上行出栈）",
				u.rxBytes.Load(), u.txBytes.Load()))
		}
	}
}

// DialTCP 从隧道里拨一条 TCP。赛风的上游代理就靠它。
func (u *userNet) DialTCP(addr string, timeout time.Duration) (net.Conn, error) {
	fa, proto, err := fullAddress(addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return gonet.DialTCPWithBind(ctx, u.st, tcpip.FullAddress{}, fa, proto)
}

// verifyDataPlane 在隧道里做一次**真实往返**，证明「握手成功 ≠ 能转发数据」。
//
// 为什么必须有这一步：2026-10-18 的手机日志里，GOOL 外层有 2/6 个端点握手成功，
// 但之后 8 秒 outer rx 一直是 0 —— 这些端点只回握手包、不转发任何数据，内层
// 于是永远握不上手，整次连接以「6 个端点全失败」结束（白等 2 分钟）。
//
// 做法：在隧道里 TCP 连 1.1.1.1:443（WARP 内部一定允许），TCP 三次握手就是一次
// 完整的上下行往返；失败再退回一次隧道内 DNS 查询。两者都用 IP 字面量，不依赖
// 隧道里能不能解析域名。
func (u *userNet) verifyDataPlane(timeout time.Duration) error {
	lastErr := error(nil)
	if c, err := u.DialTCP("1.1.1.1:443", timeout); err == nil {
		_ = c.Close()
		return nil
	} else {
		lastErr = err
	}
	if _, _, err := u.queryA("1.1.1.1", "cloudflare.com"); err == nil {
		return nil
	} else {
		lastErr = err
	}
	return lastErr
}

// DialUDP 从隧道里拨一条「已连接」的 UDP。GOOL 内层握手走它。
func (u *userNet) DialUDP(addr string) (net.Conn, error) {
	fa, proto, err := fullAddress(addr)
	if err != nil {
		return nil, err
	}
	laddr := tcpip.FullAddress{NIC: userNetNIC, Addr: u.addr}
	return gonet.DialUDP(u.st, &laddr, &fa, proto)
}

func fullAddress(addr string) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return tcpip.FullAddress{}, 0, fmt.Errorf("地址 %q 不是 ip:port：%w", addr, err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return tcpip.FullAddress{}, 0, fmt.Errorf("端口 %q 无效", portStr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return tcpip.FullAddress{}, 0, fmt.Errorf("地址 %q 不是 IP（隧道内不做 DNS）", host)
	}
	if v4 := ip.To4(); v4 != nil {
		return tcpip.FullAddress{
			NIC:  userNetNIC,
			Addr: tcpip.AddrFrom4Slice(v4),
			Port: port,
		}, ipv4.ProtocolNumber, nil
	}
	return tcpip.FullAddress{
		NIC:  userNetNIC,
		Addr: tcpip.AddrFromSlice(ip.To16()),
		Port: port,
	}, ipv6.ProtocolNumber, nil
}

// ------------------------------------------------------------------
// 隧道内 DNS：域名解析本身也从隧道里出去
// ------------------------------------------------------------------

// dnsEntry 是隧道内解析结果，带过期时间。
type dnsEntry struct {
	ip  string
	exp time.Time
}

// resolveInTunnel 在隧道里把域名解析成 IPv4。
//
// 为什么要自己做而不是 net.ResolveIPAddr：隧道内 socks 收到的 CONNECT 大量是
// 域名（赛风的前置域名、它的远程服务器列表、psiphon 的服务器地址）。物理网络上
// 解析这些域名，国内拿到的常常是污染地址，于是 TCP 一拨就被 RST —— 用户看到的
// 就是「隧道明明握手成功，赛风却一直 connection refused」。
//
// 顺序：先查缓存 → 隧道内问 dns（默认 1.1.1.1）→ 再问两个备用 → 最后才退回
// 物理网络（并写 WARN，因为那条路可能拿到假地址）。
func (u *userNet) resolveInTunnel(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if v, ok := u.dnsCache.Load(host); ok {
		if e, ok := v.(dnsEntry); ok && time.Now().Before(e.exp) {
			return e.ip, nil
		}
	}
	servers := []string{u.dns, "1.0.0.1", "8.8.8.8"}
	var lastErr error
	for _, srv := range servers {
		if net.ParseIP(srv) == nil {
			continue
		}
		ip, ttl, err := u.queryA(srv, host)
		if err != nil {
			lastErr = err
			continue
		}
		if ttl < 60 {
			ttl = 60
		}
		if ttl > 600 {
			ttl = 600
		}
		u.dnsCache.Store(host, dnsEntry{ip: ip, exp: time.Now().Add(time.Duration(ttl) * time.Second)})
		if u.logs != nil {
			u.logs.add("DEBUG", fmt.Sprintf("隧道内解析 %s → %s（经 %s，TTL %ds）", host, ip, srv, ttl))
		}
		return ip, nil
	}
	addr, err := net.ResolveIPAddr("ip4", host)
	if err != nil || addr == nil {
		return "", fmt.Errorf("隧道内解析 %s 失败：%v", host, lastErr)
	}
	if u.logs != nil {
		u.logs.add("WARN", fmt.Sprintf("隧道内 DNS 全失败，%s 退回物理网络解析为 %s（可能是污染地址）",
			host, addr.IP.String()))
	}
	u.dnsCache.Store(host, dnsEntry{ip: addr.IP.String(), exp: time.Now().Add(60 * time.Second)})
	return addr.IP.String(), nil
}

// queryA 在隧道里发一条 A 查询，返回第一个 A 记录与 TTL。
func (u *userNet) queryA(server, host string) (string, uint32, error) {
	query, id, err := buildDNSQuery(host)
	if err != nil {
		return "", 0, err
	}
	c, err := u.DialUDP(net.JoinHostPort(server, "53"))
	if err != nil {
		return "", 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(query); err != nil {
		return "", 0, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return "", 0, err
	}
	return parseDNSAnswer(buf[:n], id)
}

// buildDNSQuery 拼一条最小的 A 记录查询（RD=1，单问题）。
func buildDNSQuery(host string) ([]byte, uint16, error) {
	name := strings.TrimSuffix(strings.TrimSpace(host), ".")
	if name == "" || len(name) > 253 {
		return nil, 0, fmt.Errorf("域名 %q 无效", host)
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := uint16(idb[0])<<8 | uint16(idb[1])
	msg := make([]byte, 0, 12+len(name)+6)
	msg = append(msg, idb[0], idb[1], 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("域名 %q 的标签无效", host)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01) // 结束符 + QTYPE=A + QCLASS=IN
	return msg, id, nil
}

// parseDNSAnswer 从响应里取第一条 A 记录。CNAME 会被跳过（继续往后找 A）。
func parseDNSAnswer(msg []byte, id uint16) (string, uint32, error) {
	if len(msg) < 12 {
		return "", 0, fmt.Errorf("DNS 响应过短（%d 字节）", len(msg))
	}
	if uint16(msg[0])<<8|uint16(msg[1]) != id {
		return "", 0, fmt.Errorf("DNS 事务 ID 不匹配")
	}
	if rcode := msg[3] & 0x0F; rcode != 0 {
		return "", 0, fmt.Errorf("DNS 返回 rcode=%d", rcode)
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	for i := 0; i < qd; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return "", 0, err
		}
		off = next + 4 // QTYPE + QCLASS
	}
	for i := 0; i < an; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return "", 0, err
		}
		if next+10 > len(msg) {
			return "", 0, fmt.Errorf("DNS 记录被截断")
		}
		typ := uint16(msg[next])<<8 | uint16(msg[next+1])
		ttl := uint32(msg[next+4])<<24 | uint32(msg[next+5])<<16 | uint32(msg[next+6])<<8 | uint32(msg[next+7])
		rdlen := int(msg[next+8])<<8 | int(msg[next+9])
		rdStart := next + 10
		if rdStart+rdlen > len(msg) {
			return "", 0, fmt.Errorf("DNS 记录被截断")
		}
		if typ == 1 && rdlen == 4 {
			return net.IPv4(msg[rdStart], msg[rdStart+1], msg[rdStart+2], msg[rdStart+3]).String(), ttl, nil
		}
		off = rdStart + rdlen
	}
	return "", 0, fmt.Errorf("DNS 响应里没有 A 记录")
}

// skipDNSName 跳过一条（可能是压缩指针的）域名，返回其后的偏移。
func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("DNS 域名被截断")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0: // 压缩指针：2 字节，指向别处，名字到此结束
			if off+1 >= len(msg) {
				return 0, fmt.Errorf("DNS 压缩指针被截断")
			}
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
}

func (u *userNet) Close() {
	u.once.Do(func() {
		close(u.closed)
		if u.st != nil {
			u.st.Close()
		}
		if u.dev != nil {
			u.dev.Close()
		}
	})
	u.wg.Wait()
}

// ------------------------------------------------------------------
// 隧道内的 SOCKS5（服务端）
// ------------------------------------------------------------------

// ServeSocks 在本机开一个 socks5，所有 CONNECT 都从隧道里拨出去。
//
// 赛风（--upstream socks5://…）挂在它后面，就得到了「隧道内第二跳」：
//
//	tun → psiphon 的 socks → psiphon 客户端 → 本口 → wireguard-go → 出口
func (u *userNet) ServeSocks(listenAddr string, logs *logRing) (net.Listener, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.handleSocks(c, logs)
		}
	}()
	logs.add("INFO", fmt.Sprintf("隧道内 socks5 已监听：%s（出口走 wireguard）", listenAddr))
	return ln, nil
}

func (u *userNet) handleSocks(c net.Conn, logs *logRing) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))

	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return
		}
		host = net.IP(b[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		host = string(name)
	default:
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])

	// 协议栈里没有 DNS：域名只能在这里落地。**必须在隧道里解析**（见
	// resolveInTunnel）——在物理网络上解析会被污染，赛风拨过去直接 RST。
	if net.ParseIP(host) == nil {
		ip, lerr := u.resolveInTunnel(host)
		if lerr != nil || ip == "" {
			_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			if logs != nil {
				logs.add("WARN", fmt.Sprintf("隧道内 socks 解析 %s 失败：%v", host, lerr))
			}
			return
		}
		host = ip
	}
	dst := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	up, err := u.DialTCP(dst, 15*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if logs != nil {
			logs.add("WARN", fmt.Sprintf("隧道内 socks 拨号 %s 失败：%v", dst, err))
		}
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	relayBoth(c, up, nil, nil)
}
