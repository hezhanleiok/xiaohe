module ther/engine

go 1.27

require (
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	// Aether 核心只会开本地 SOCKS5；VPN 模式要靠 gVisor 的用户态协议栈做
	// tun→SOCKS 转换（见 socks.go）。版本取自本机模块缓存，避免联网拉取。
	gvisor.dev/gvisor v0.0.0-20260616165937-8e4bc62602eb
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

// 本地替换：third_party/wireguard 是工作区电脑版用的那一份，带 AWG junk 补丁
// （device/awgjunk.go 支持 UAPI 的 jc/jmin/jmax/i1 键）。官方模块缓存里那份
// 没有这个补丁，直连 DPI 更强的网络时就没有混淆可用。
replace golang.zx2c4.com/wireguard => ./third_party/wireguard

tool golang.org/x/mobile/cmd/gobind
