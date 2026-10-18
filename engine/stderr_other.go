//go:build !linux && !android && !darwin

package engine

import "fmt"

// dup2ToStderr 在非 unix 平台上是空操作：Windows 没有「重定向 fd 2」这套语义，
// 而引擎在桌面上只用于离线实验（engine/cmd 下的工具），崩溃信息直接在控制台可见。
func dup2ToStderr(fd int) error {
	return fmt.Errorf("这个平台不支持重定向 stderr（fd=%d）", fd)
}
