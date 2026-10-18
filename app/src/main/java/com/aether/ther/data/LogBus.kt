package com.aether.ther.data

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class LogEntry(
    val at: Long,
    val level: String,
    val tag: String,
    val msg: String,
) {
    fun line(): String = "${fmt.format(Date(at))} ${level.padEnd(5)} [$tag] $msg"

    private companion object {
        val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    }
}

/**
 * 首页日志的来源。
 *
 * 四条约束：
 *  1. 内存里留最近 MAX 条给界面滚动，同时追加写文件（files/logs/ther.log），
 *     这样导出拿到的是完整会话而不只是屏幕上的几十行。
 *  2. 任何线程都能写：内部 synchronized，不依赖协程上下文。
 *  3. 日志永远不能成为失败原因：写文件失败只吞掉，绝不影响连接流程。
 *  4. **重启不清除**：重新打开应用时把上一次的记录读回内存，只有用户点「清空」
 *     才删。闪退之后回来，最重要的就是上一次的现场。
 *
 * 现场分散在三个文件里：
 *  - ther.log   ：Java 侧全部日志（本文件写）；
 *  - engine.log ：Go 引擎的逐步检查点（engine/logring.go 写）；
 *  - crash.log  ：被重定向过来的 stderr，Go 的 goroutine panic 堆栈在这里。
 */
object LogBus {
    private const val MAX = 2000
    private const val FILE_MAX_BYTES = 4L * 1024 * 1024
    private const val FILE_KEEP_BYTES = 1L * 1024 * 1024
    private const val SESSION_MARK = "session.lock"

    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries.asStateFlow()

    private val lock = Any()
    private var file: File? = null

    fun init(context: Context) {
        synchronized(lock) {
            if (file != null) return
            val dir = File(context.filesDir, "logs").apply { mkdirs() }
            val f = File(dir, "ther.log")
            rotateIfNeeded(f)
            file = f

            // 顺序是刻意排的：崩溃现场放最上面。闪退后用户重开应用，首页日志卡片
            // 只显示最后 8 行、截图也只截得到顶部，堆栈埋在 200 行历史里等于没有。
            val restored = ArrayList<LogEntry>()
            val abnormal = tookAbnormalSessionMark(dir)
            if (abnormal) {
                restored += LogEntry(
                    System.currentTimeMillis(),
                    "ERROR",
                    "Crash",
                    "—— 上次连接没有正常结束：进程在连接过程中消失（闪退 / 被系统强杀）——",
                )
            }
            val crash = rawBlock(dir, "crash.log", "Crash", maxLines = 80)
            if (crash != null) {
                restored += crash
            } else if (abnormal) {
                restored += LogEntry(
                    System.currentTimeMillis(),
                    "ERROR",
                    "Crash",
                    "—— crash.log 为空：不是 Go panic（stderr 没有任何输出），说明进程是被外部信号杀掉的 ——",
                )
            }
            historyBlock(f)?.let { restored += it }
            engineBlock(dir)?.let { restored += it }
            if (abnormal) {
                // 放在末尾：首页日志卡只看最后 8 行，这条才会被看到，用来把用户
                // 引到日志页顶部那一大块崩溃现场。
                restored += LogEntry(
                    System.currentTimeMillis(),
                    "ERROR",
                    "Crash",
                    "—— 上次连接异常结束；崩溃现场在日志页最上面（首页日志卡点「查看全部」）——",
                )
            }
            if (restored.isNotEmpty()) _entries.value = restored
        }
        i("App", "日志已就绪：${file?.absolutePath}")
    }

    // ------------------------------------------------------------------
    // 会话标记：判断上一次是不是「连接中闪退」
    // ------------------------------------------------------------------

    /** 连接真正交给引擎之前打上标记；正常收尾时删掉。留着就说明上次没好下场。 */
    fun markSessionStart() {
        val dir = file?.parentFile ?: return
        runCatching { File(dir, SESSION_MARK).writeText(System.currentTimeMillis().toString()) }
    }

    fun markSessionEnd() {
        val dir = file?.parentFile ?: return
        runCatching { File(dir, SESSION_MARK).delete() }
    }

    /** 读一次就删，避免同一个现场每次启动都报一遍。 */
    private fun tookAbnormalSessionMark(dir: File): Boolean {
        val f = File(dir, SESSION_MARK)
        if (!f.isFile) return false
        runCatching { f.delete() }
        return true
    }

    // ------------------------------------------------------------------
    // 启动时恢复：历史 / 引擎 / 崩溃
    // ------------------------------------------------------------------

    private val linePattern =
        Regex("""^(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s+(\w+)\s+\[([^\]]*)]\s?(.*)$""")

    /** ther.log 里已有的行读回内存（吃满内存上限），重启不丢。 */
    private fun historyBlock(f: File, maxLines: Int = MAX): List<LogEntry>? {
        val text = runCatching { f.readText() }.getOrNull()?.takeIf { it.isNotBlank() } ?: return null
        val tail = text.lineSequence().filter { it.isNotBlank() }.toList().takeLast(maxLines)
        if (tail.isEmpty()) return null
        val now = System.currentTimeMillis()
        val out = ArrayList<LogEntry>(tail.size + 1)
        out += LogEntry(now, "INFO", "App", "—— 历史日志 ${tail.size} 行（重启不会清除，只有「清空」才删）——")
        tail.forEach { line ->
            val m = linePattern.find(line) ?: return@forEach
            val (h, mi, s, ms, level, tag, msg) = m.destructured
            val cal = java.util.Calendar.getInstance().apply {
                set(java.util.Calendar.HOUR_OF_DAY, h.toInt())
                set(java.util.Calendar.MINUTE, mi.toInt())
                set(java.util.Calendar.SECOND, s.toInt())
                set(java.util.Calendar.MILLISECOND, ms.toInt())
            }
            out += LogEntry(cal.timeInMillis, level, tag, msg)
        }
        return out
    }

    /**
     * engine.log：Go 侧的检查点。
     *
     * 里面 90% 是 wireguard 的 DEBUG（握手/例程启动），全搬进界面会把真正的信息
     * 淹掉；所以只保留非 DEBUG 行，外加最后 12 行（崩溃前那一刻的上下文）。
     */
    private fun engineBlock(dir: File?, maxLines: Int = 80): List<LogEntry>? {
        val f = dir?.let { File(it, "engine.log") } ?: return null
        if (!f.isFile || f.length() == 0L) return null
        val lines = runCatching { f.readText() }.getOrNull()
            ?.lineSequence()?.filter { it.isNotBlank() }?.toList()
            ?: return null
        if (lines.isEmpty()) return null
        val tailStart = (lines.size - 12).coerceAtLeast(0)
        val kept = lines.filterIndexed { i, line -> i >= tailStart || !line.contains("[DEBUG]") }
            .takeLast(maxLines)
        if (kept.isEmpty()) return null
        val now = System.currentTimeMillis()
        val out = ArrayList<LogEntry>(kept.size + 1)
        out += LogEntry(now, "INFO", "Core", "—— 上次会话的引擎日志（已过滤 DEBUG）——")
        kept.forEach { out += LogEntry(now, "INFO", "Core", it) }
        return out
    }

    private fun rawBlock(dir: File?, name: String, tag: String, maxLines: Int): List<LogEntry>? {
        val f = dir?.let { File(it, name) } ?: return null
        if (!f.isFile || f.length() == 0L) return null
        val lines = runCatching { f.readText() }.getOrNull()
            ?.lineSequence()?.filter { it.isNotBlank() }?.toList()
            ?.takeLast(maxLines)
            ?: return null
        if (lines.isEmpty()) return null
        val now = System.currentTimeMillis()
        val out = ArrayList<LogEntry>(lines.size + 1)
        out += LogEntry(now, "ERROR", tag, "—— 上次会话的原生崩溃现场（stderr，最可能的根因就在这里）——")
        lines.forEach { out += LogEntry(now, "ERROR", tag, it) }
        return out
    }

    // ------------------------------------------------------------------
    // 写 / 导出 / 清空
    // ------------------------------------------------------------------

    /**
     * 导出用：内存里的全部条目 + 引擎与崩溃的原始文件。
     * 内存里那份已经过滤过 DEBUG，原始文件不裁，便于贴给开发者。
     */
    fun exportText(): String = synchronized(lock) {
        val main = _entries.value.joinToString(separator = "\n") { it.line() }
        val dir = file?.parentFile
        val extra = listOf("engine.log", "crash.log").mapNotNull { name ->
            val f = dir?.let { File(it, name) } ?: return@mapNotNull null
            if (!f.isFile || f.length() == 0L) return@mapNotNull null
            val text = runCatching { f.readText() }.getOrNull().orEmpty()
            if (text.isBlank()) null else "—— $name ——\n$text"
        }
        if (extra.isEmpty()) main else main + "\n\n" + extra.joinToString("\n")
    }

    fun logFilePath(): String? = file?.absolutePath

    /** 唯一的删除入口（日志页的垃圾桶）。三个文件必须一起清，否则下次启动又会被捞回来。 */
    fun clear() {
        synchronized(lock) {
            _entries.value = emptyList()
            val dir = file?.parentFile
            runCatching { file?.writeText("") }
            runCatching { dir?.let { File(it, "engine.log") }?.writeText("") }
            runCatching { dir?.let { File(it, "crash.log") }?.writeText("") }
        }
    }

    fun d(tag: String, msg: String) = write("DEBUG", tag, msg)
    fun i(tag: String, msg: String) = write("INFO", tag, msg)
    fun w(tag: String, msg: String) = write("WARN", tag, msg)
    fun e(tag: String, msg: String) = write("ERROR", tag, msg)

    private fun write(level: String, tag: String, msg: String) {
        val entry = LogEntry(System.currentTimeMillis(), level, tag, msg)
        synchronized(lock) {
            val next = ArrayList<LogEntry>(_entries.value.size + 1)
            next.addAll(_entries.value)
            next.add(entry)
            _entries.value = if (next.size > MAX) next.subList(next.size - MAX, next.size) else next
            file?.let { f ->
                runCatching { f.appendText(entry.line() + "\n") }
            }
        }
        // logcat 也留一份：真机上 adb logcat -s Ther 就能看到，不用等 UI。
        Log.println(
            when (level) {
                "ERROR" -> Log.ERROR
                "WARN" -> Log.WARN
                "DEBUG" -> Log.DEBUG
                else -> Log.INFO
            },
            "Ther",
            "[$tag] $msg",
        )
    }

    private fun rotateIfNeeded(f: File) {
        runCatching {
            if (!f.exists() || f.length() < FILE_MAX_BYTES) return@runCatching
            val all = f.readText()
            f.writeText(all.takeLast(FILE_KEEP_BYTES.toInt()))
        }
    }
}
