//go:build linux || android || darwin

package engine

import "golang.org/x/sys/unix"

// dupFd 复制一个文件描述符：fd 的所有权仍留给调用方（Kotlin 的
// ParcelFileDescriptor），引擎只拿副本，双方各关各的。
func dupFd(fd int) (int, error) {
	return unix.Dup(fd)
}
