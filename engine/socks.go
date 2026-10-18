package engine

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
	"gvisor.dev/gvisor/pkg/waiter"
)

// 这个文件补的是「Aether 核心只能当本地 SOCKS5 用」和「Android 只有 tun 才管用」
// 之间缺的那一段：一个用户态 TCP/IP 栈，把 tun 里的 IP 包接成本地 SOCKS5 连接。
//
//	设备流量 → tun → gVisor 协议栈（本文件）→ SOCKS5 → aether 核心 → 出口
//
// 为什么必须自己做：Android 的「系统代理」只有 Wi-Fi 的 HTTP 代理，绝大多数应用
// 不认，等于没接（2026-10-17 实测：开了系统代理整机流量仍直连）。而 aether 核心
// 没有 --tun-fd，所以隧道的最后一公里只能在应用里补。
//
// 边界（故意的）：
//   - TCP：全部走 SOCKS5 CONNECT，不支持的命令一律拒绝。
//   - UDP：只代理 53（DNS），而且是折成 TCP DNS 经 SOCKS 转发——aether 的 SOCKS
//     没有 UDP ASSOCIATE，走 UDP 只会绕开隧道。QUIC 等其它 UDP 直接丢弃，
//     应用会退回到 TCP（这是「宁可慢，不能漏」的选择）。
const (
	socksTunNIC = tcpip.NICID(1)

	socksDialTimeout = 12 * time.Second
	dnsTimeout       = 10 * time.Second
)

// notifyChan 适配 gVisor 的 channel.Notification 接口（WriteNotify）。
type notifyChan chan struct{}

func (n notifyChan) WriteNotify() {
	select {
	case n <- struct{}{}:
	default:
	}
}

type socksTun struct {
	dev   *fdTun
	ep    *channel.Endpoint
	st    *stack.Stack
	proxy string // "127.0.0.1:port"
	dns   string // DNS 服务器（IP），经 SOCKS 用 TCP 查询

	logs *logRing

	wmu sync.Mutex // tun 的 Write 不能被并发连接交错

	closeOnce sync.Once
	closed    chan struct{}
	wg        sync.WaitGroup

	tcpConns atomic.Int64
	udpDrops atomic.Int64
	rxBytes  atomic.Int64
	txBytes  atomic.Int64

	fmu   sync.Mutex
	fails map[string]*failRec
}

// failRec 是「同一条拨号失败」的去重状态。
type failRec struct {
	last    time.Time
	skipped int
}

// dialFailLogEvery：同样的失败多久才允许再打一行。
const dialFailLogEvery = 15 * time.Second

func startSocksTun(fd, mtu int, proxy, dns string, logs *logRing) (*socksTun, error) {
	if proxy == "" {
		return nil, fmt.Errorf("缺少 SOCKS 地址")
	}
	if dns == "" {
		dns = "1.1.1.1"
	}
	dev, err := newFdTun(fd, mtu)
	if err != nil {
		return nil, err
	}

	s := &socksTun{
		dev:    dev,
		proxy:  proxy,
		dns:    dns,
		logs:   logs,
		closed: make(chan struct{}),
	}

	ep := channel.New(2048, uint32(mtu), "")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := st.CreateNIC(socksTunNIC, ep); err != nil {
		dev.Close()
		return nil, fmt.Errorf("创建协议栈网卡失败: %v", err)
	}
	// 目标地址是任意公网地址，协议栈必须接受「不是我」的包，并且能用目标地址回包。
	if err := st.SetPromiscuousMode(socksTunNIC, true); err != nil {
		dev.Close()
		return nil, fmt.Errorf("开启混杂模式失败: %v", err)
	}
	if err := st.SetSpoofing(socksTunNIC, true); err != nil {
		dev.Close()
		return nil, fmt.Errorf("开启地址伪装失败: %v", err)
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: socksTunNIC},
		{Destination: header.IPv6EmptySubnet, NIC: socksTunNIC},
	})
	s.ep, s.st = ep, st
	s.tuneTCP(st)

	s.installTCP()
	s.installUDP()

	s.pumpStackToTun()
	s.pumpTunToStack()

	logs.add("INFO", fmt.Sprintf("socks-tun 已启动：socks=%s dns=%s（DNS 走 TCP）", proxy, dns))
	return s, nil
}

// tuneTCP 把协议栈的窗口放大。
//
// 为什么必须调：这条链路上的「跨公网段」不是设备↔我们，而是我们↔赛风服务器。
// 开赛风时，本机这条 TCP 的两个对端分别是「设备里的应用」和「赛风客户端」，
// 而赛风客户端到它服务器的 RTT 实测 1.4~1.9 秒。TCP 单流吞吐 ≈ 窗口 / RTT，
// 1MB 窗口在 1.8s RTT 下天花板只有 ~4.4Mbps —— 和实测的 1~4Mbps 吻合。
//
// 默认抬到 8MB（1.8s RTT → ~35Mbps），上限 16MB 留给更差的线路。
// 内存是懒分配的（gVisor 按实际入队数据记账），空连接不会占满窗口。
func (s *socksTun) tuneTCP(st *stack.Stack) {
	recv := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: 8 << 20,
		Max:     16 << 20,
	}
	send := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: 4 << 20,
		Max:     16 << 20,
	}
	// moderation 会按 cwnd 收缩窗口：高 RTT 链路上好不容易长起来的窗口会被
	// 打回原点，这里必须关掉（和 usernet.go 的 tuneUserNetStack 一致）。
	moderate := tcpip.TCPModerateReceiveBufferOption(false)
	sack := tcpip.TCPSACKEnabled(true)
	recovery := tcpip.TCPRecovery(tcpip.TCPRACKLossDetection)

	set := func(name string, opt tcpip.SettableTransportProtocolOption) {
		if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			s.logs.add("WARN", fmt.Sprintf("协议栈调优（%s）失败：%v", name, err))
		}
	}
	set("接收窗口", &recv)
	set("发送窗口", &send)
	set("接收窗口自动增长", &moderate)
	set("SACK", &sack)
	set("RACK 丢包检测", &recovery)
	s.logs.add("INFO", fmt.Sprintf("协议栈已调优：接收窗口默认 %dKB / 上限 %dKB（高 RTT 链路靠它撑吞吐）",
		(8<<20)/1024, (16<<20)/1024))
}

// ------------------------------------------------------------------
// TCP：每条连接拨一次 SOCKS5 CONNECT
// ------------------------------------------------------------------

func (s *socksTun) installTCP() {
	fwd := tcp.NewForwarder(s.st, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		host := id.LocalAddress.String()
		port := id.LocalPort
		go func() {
			up, err := socks5Connect(s.proxy, host, port, socksDialTimeout)
			if err != nil {
				s.dialFail("socks 拨号", fmt.Sprintf("%s:%d", host, port), err)
				r.Complete(true)
				return
			}
			var wq waiter.Queue
			ep, tErr := r.CreateEndpoint(&wq)
			if tErr != nil {
				up.Close()
				r.Complete(true)
				return
			}
			r.Complete(false)
			down := gonet.NewTCPConn(&wq, ep)
			s.tcpConns.Add(1)
			relayBoth(down, up, &s.rxBytes, &s.txBytes)
		}()
	})
	s.st.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// ------------------------------------------------------------------
// UDP：只把 53 折成 TCP DNS 经 SOCKS 转发，其它一律丢
// ------------------------------------------------------------------

func (s *socksTun) installUDP() {
	fwd := udp.NewForwarder(s.st, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if id.LocalPort != 53 {
			s.udpDrops.Add(1)
			return false // 交给协议栈回 ICMP port unreachable
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		go s.serveDNS(gonet.NewUDPConn(&wq, ep))
		return true
	})
	s.st.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
}

func (s *socksTun) serveDNS(client *gonet.UDPConn) {
	defer client.Close()

	query := make([]byte, 1500)
	n, err := client.Read(query)
	if err != nil || n < 12 {
		return
	}
	s.rxBytes.Add(int64(n))

	up, err := socks5Connect(s.proxy, s.dns, 53, dnsTimeout)
	if err != nil {
		s.dialFail("DNS 经 SOCKS 拨号", s.dns+":53", err)
		return
	}
	defer up.Close()
	_ = up.SetDeadline(time.Now().Add(dnsTimeout))

	// TCP DNS：2 字节长度前缀。
	msg := make([]byte, 2+n)
	binary.BigEndian.PutUint16(msg, uint16(n))
	copy(msg[2:], query[:n])
	if _, err := up.Write(msg); err != nil {
		return
	}
	var lb [2]byte
	if _, err := io.ReadFull(up, lb[:]); err != nil {
		return
	}
	resp := make([]byte, int(binary.BigEndian.Uint16(lb[:])))
	if _, err := io.ReadFull(up, resp); err != nil {
		return
	}
	if _, err := client.Write(resp); err != nil {
		return
	}
	s.txBytes.Add(int64(len(resp)))
}

// dialFail 记录一次拨号失败，但同样的失败 15s 内只打一行。
//
// 一条连不上的连接会被应用/系统反复重试（日志里同一条 0.0.0.1:23861 打了几十次），
// 原样全写出来会把日志页刷满，真正的第一条原因（rep=1 / rep=5 / timeout）反而
// 被淹掉——用户看到的就是「日志里一直在包失败」却不知道该看哪句。
func (s *socksTun) dialFail(what, key string, err error) {
	now := time.Now()
	s.fmu.Lock()
	if s.fails == nil {
		s.fails = make(map[string]*failRec)
	}
	if len(s.fails) > 1024 {
		// 不设上限就是慢性内存泄漏：热点地址一直在变。
		s.fails = make(map[string]*failRec)
	}
	rec := s.fails[key]
	if rec == nil {
		rec = &failRec{}
		s.fails[key] = rec
	}
	if now.Sub(rec.last) < dialFailLogEvery {
		rec.skipped++
		s.fmu.Unlock()
		return
	}
	skipped := rec.skipped
	rec.skipped, rec.last = 0, now
	s.fmu.Unlock()

	msg := fmt.Sprintf("%s %s 失败：%v", what, key, err)
	if skipped > 0 {
		msg += fmt.Sprintf("（同类失败已抑制 %d 次）", skipped)
	}
	s.logs.add("WARN", msg)
}

// ------------------------------------------------------------------
// 包泵
// ------------------------------------------------------------------

func (s *socksTun) pumpTunToStack() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, s.dev.mtu+128)
		for {
			n, err := s.dev.f.Read(buf)
			if err != nil {
				select {
				case <-s.closed:
				default:
					s.logs.add("WARN", fmt.Sprintf("tun 读失败：%v", err))
				}
				return
			}
			if n < 20 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			s.rxBytes.Add(int64(n))

			var proto tcpip.NetworkProtocolNumber
			switch pkt[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
			s.ep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}()
}

func (s *socksTun) pumpStackToTun() {
	notify := make(notifyChan, 1)
	s.ep.AddNotify(notify)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-s.closed:
				return
			case <-notify:
			}
			for {
				pb := s.ep.Read()
				if pb == nil {
					break
				}
				view := pb.ToView()
				b := append([]byte(nil), view.AsSlice()...)
				pb.DecRef()
				s.wmu.Lock()
				_, err := s.dev.f.Write(b)
				s.wmu.Unlock()
				if err != nil {
					select {
					case <-s.closed:
					default:
						s.logs.add("WARN", fmt.Sprintf("tun 写失败：%v", err))
					}
					return
				}
				s.txBytes.Add(int64(len(b)))
			}
		}
	}()
}

func (s *socksTun) Close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.st.Close()
		s.dev.Close()
	})
	s.wg.Wait()
	s.logs.add("INFO", fmt.Sprintf("socks-tun 已停止：tcp=%d udp丢=%d rx=%.1fKB tx=%.1fKB",
		s.tcpConns.Load(), s.udpDrops.Load(), float64(s.rxBytes.Load())/1024, float64(s.txBytes.Load())/1024))
}

// ------------------------------------------------------------------
// SOCKS5 客户端（CONNECT only）
// ------------------------------------------------------------------

func socks5Connect(proxy, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxy, timeout)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		return nil, err
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 认证被拒（%d/%d）", greet[0], greet[1])
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("域名过长")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}

	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return nil, err
	}
	if head[0] != 0x05 {
		return nil, fmt.Errorf("SOCKS5 版本异常：%d", head[0])
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 连接失败，rep=%d", head[1])
	}
	switch head[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, err
		}
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, err
		}
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, make([]byte, int(l[0]))); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("SOCKS5 地址类型异常：%d", head[3])
	}
	var tail [2]byte
	if _, err := io.ReadFull(c, tail[:]); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}

// relayBoth 双向搬运并半关闭写端，避免一侧关写后另一侧干等。
//
// 缓冲显式给到 256KB：这条链路上每一层 relay 都是真 TCP（设备→协议栈→赛风→
// 隧道内协议栈→wireguard），一次拷贝搬得越多，越不容易被 1.8s 的 RTT 卡成
// 「停等」形态。缓冲从池里取，避免每个连接都分配 256KB。
func relayBoth(a, b net.Conn, rx, tx *atomic.Int64) {
	// 关掉 Nagle：多层 relay 里每个小包都可能被攒 40ms，叠三层就是网页首屏
	// 多出一百多毫秒。真实 TCP 才支持，gonet 的连接会走类型断言失败的分支。
	if c, ok := a.(*net.TCPConn); ok {
		_ = c.SetNoDelay(true)
	}
	if c, ok := b.(*net.TCPConn); ok {
		_ = c.SetNoDelay(true)
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn, counter *atomic.Int64) {
		bufp := relayBufPool.Get().(*[]byte)
		n, _ := io.CopyBuffer(dst, src, *bufp)
		relayBufPool.Put(bufp)
		if counter != nil {
			counter.Add(n)
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(a, b, tx)
	go pipe(b, a, rx)
	<-done
	<-done
}

// relayBufSize 是单次拷贝的缓冲大小。
const relayBufSize = 256 * 1024

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayBufSize)
		return &b
	},
}
