//go:build !linux && !android && !darwin

package engine

import "fmt"

// dupFd 在非 unix 平台上没有意义：桌面/开发机上没有 VpnService 给的 tun fd。
// 保留这个实现只是为了「引擎包在 Windows 上也能编译」——这样离线的命令行实验
// （engine/cmd 下那些工具）能直接复用引擎里的 GOOL / userNet 代码，
// 而不是像以前那样再抄一份到 .tmp 里，抄出来的副本和真实代码越走越远。
func dupFd(fd int) (int, error) {
	return -1, fmt.Errorf("这个平台不支持接管 tun fd（fd=%d）：只有 Android/Linux 的 VpnService 会给 tun fd", fd)
}
