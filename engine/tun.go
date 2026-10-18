package engine

import (
	"fmt"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// fdTun 把 Android VpnService.establish() 给的 fd 包成 wireguard-go 需要的
// tun.Device。
//
// 与桌面版的差别只有一个：那边的设备是 wintun（内核驱动 + DLL），这边是
// VpnService 已经建好的 tun 字符设备，读写就是原始的 IP 包，不需要任何驱动。
// 其余（MTU、事件、批量读写）语义完全一致，所以 device 侧代码一行都不用改。
//
// fd 的所有权在 Kotlin 侧用 ParcelFileDescriptor.detachFd() 转移过来：
// 这里 Close 会关掉它，调用方不要再关第二次。
type fdTun struct {
	f      *os.File
	mtu    int
	events chan tun.Event

	closeOnce sync.Once
}

func newFdTun(fd int, mtu int) (*fdTun, error) {
	if fd < 0 {
		return nil, fmt.Errorf("无效的 tun fd: %d", fd)
	}
	if mtu <= 0 {
		mtu = 1280
	}
	// 先 dup 一份再接管：fd 的所有权仍留给 Kotlin 的 ParcelFileDescriptor，
	// 双方各自关各自的，不存在「引擎关了 Kotlin 还想关」的双重关闭。
	dup, err := dupFd(fd)
	if err != nil {
		return nil, fmt.Errorf("复制 tun fd 失败: %w", err)
	}
	t := &fdTun{
		f:      os.NewFile(uintptr(dup), "ther-tun"),
		mtu:    mtu,
		events: make(chan tun.Event, 1),
	}
	if t.f == nil {
		return nil, fmt.Errorf("无法接管 tun fd %d", fd)
	}
	// 设备一开始就是「已连接」：VpnService 的 tun 建立即通，没有 wintun 那种
	// media-connected 延迟。
	t.events <- tun.EventUp
	return t, nil
}

func (t *fdTun) File() *os.File { return t.f }

func (t *fdTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.f.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (t *fdTun) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		if _, err := t.f.Write(buf[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (t *fdTun) MTU() (int, error)        { return t.mtu, nil }
func (t *fdTun) Name() (string, error)    { return "ther-tun", nil }
func (t *fdTun) Events() <-chan tun.Event { return t.events }
func (t *fdTun) BatchSize() int           { return 1 }

func (t *fdTun) Close() error {
	var err error
	t.closeOnce.Do(func() {
		close(t.events)
		err = t.f.Close()
	})
	return err
}
