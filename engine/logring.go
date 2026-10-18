package engine

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// clockOffsetMinutes 是 Java 侧传进来的本地时区偏移（分钟）。
//
// 安卓进程里的 Go 拿不到系统时区（TZ 没设、也没有 /etc/localtime），time.Now()
// 直接是 UTC，日志时间会比界面上的早 8 小时，排查时对不上号。
var clockOffsetMinutes int64

func setClockOffset(minutes int) { atomic.StoreInt64(&clockOffsetMinutes, int64(minutes)) }

func nowLocal() time.Time {
	return time.Now().UTC().Add(time.Duration(atomic.LoadInt64(&clockOffsetMinutes)) * time.Minute)
}

// logRing 是引擎与 Java 之间的日志通道。
//
// gomobile 不能直接把 Go 的 func(string) 回调传给 Java，所以改成「写进环形
// 缓冲、Java 侧定时 DrainLogs()」。上限 4000 行：一次连接的生命周期够用，
// 又不会因为没人取走而无限涨。
//
// 另外可选地同步落盘（[logRing.setFile]）：原生代码 panic / SIGSEGV 时进程
// 直接消失，内存里的环缓冲一起没了，只有文件能留下「死在 Go 的哪一步」。
type logRing struct {
	mu    sync.Mutex
	lines []string
	max   int
	file  string
}

func newLogRing(max int) *logRing { return &logRing{max: max} }

func (l *logRing) setFile(path string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.file = path
	l.mu.Unlock()
	if path != "" {
		appendToFile(path, "=== 引擎会话开始 ===")
	}
}

// redirectStderr 把进程的 fd 2 指到文件上。
//
// 为什么必须做：Go 里 goroutine 的 panic、runtime 的 fatal error 都只往 stderr
// 打，而安卓上那对应 logcat，应用自己拿不到。原生崩溃时用户只能看到「闪退」，
// 我们什么都收不到。把 fd 2 重定向到文件后，崩溃现场（含 goroutine 栈）就留在
// 应用私有目录里，可以直接导出。每次连接都截断，只留当次会话。
func redirectStderr(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	fd := int(f.Fd())
	if err := dup2ToStderr(fd); err != nil {
		_ = f.Close()
		return
	}
	// dup2 之后 fd 2 是独立引用，原 fd 可以关掉。
	_ = f.Close()
}

func (l *logRing) add(level, msg string) {
	if l == nil {
		return
	}
	line := fmt.Sprintf("%s [%s] %s", nowLocal().Format("15:04:05.000"), level, msg)

	l.mu.Lock()
	l.lines = append(l.lines, line)
	if len(l.lines) > l.max {
		l.lines = l.lines[len(l.lines)-l.max:]
	}
	path := l.file
	l.mu.Unlock()

	// 落盘放在锁外：磁盘 IO 不能拖住 wireguard 的数据路径。
	if path != "" {
		appendToFile(path, line)
	}
}

// drain 取走并清空，返回多行文本（每条一行）。
func (l *logRing) drain() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) == 0 {
		return ""
	}
	out := ""
	for _, s := range l.lines {
		out += s + "\n"
	}
	l.lines = l.lines[:0]
	return out
}

// appendToFile 每次都 open-append-close：日志量小（一次握手几十行），换来的是
// 崩溃前的最后一行一定在磁盘上，不会留在 stdio 缓冲里。
func appendToFile(path, line string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line + "\n")
	_ = f.Close()
}
