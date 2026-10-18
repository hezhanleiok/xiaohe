//go:build linux || android || darwin

package engine

import "golang.org/x/sys/unix"

// dup2ToStderr 把 fd 复制到进程的 stderr（fd 2）上，之后 Go 的 panic / runtime
// fatal 输出就落在文件里，而不是只进 logcat。
func dup2ToStderr(fd int) error {
	return unix.Dup2(fd, 2)
}
