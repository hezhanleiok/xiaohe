package com.aether.ther.core

/**
 * 核心自己上报的出口（从它的 stdout 里读出来）。
 *
 * 为什么要从日志里读：核心是唯一真正知道「包最后落在哪」的角色。它连上之后会打
 * `...[exit:] <ip>, <CC> via <colo>` 以及 `[app] exit: <旗> <国名> <ip>` 这类行，
 * 而我们在外面自己探测时，核心的 SOCKS 对部分目标会直接回 rep=1，于是出现
 * 「已经连上、首页却还显示本机 IP」。核心既然把答案打出来了，就先用它。
 */
data class CoreExit(
    val ip: String,
    /** ISO-3166-1 alpha-2；解析不出来时为空串。 */
    val country: String,
    /** 到 Cloudflare 边缘的 RTT（毫秒）；没有就 -1。 */
    val latencyMs: Long,
)

/**
 * 宽松解析核心日志里的出口行。**只认它自己报的**，解析不出来就返回 null，
 * 绝不能瞎猜一个 IP 填进首页 —— 那比显示本机 IP 更糟。
 *
 * 兼容的几种形态（不同核心 / 不同出口路径写法不一样）：
 * ```
 * [+] psiphon through the tunnel exit: 217.160.10.119, DE via FRA, 1100ms to cloudflare
 * wireguard exit: 1.2.3.4, PL via WAW
 * [app] exit: 🇩🇪 Germany 1.2.3.4
 * [app] native exit: 🇩🇪 Germany 1.2.3.4 (rtt 47 ms, colo WAW)
 * ```
 */
object ExitLog {

    private val ipv4 = Regex("""(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})""")

    /** "…<ip>, DE via FRA" 里的那个两字母国家码。 */
    private val ccAfterComma = Regex("""^[\s,]+([A-Za-z]{2})(?![A-Za-z])""")

    /** "1100ms to cloudflare" / "(rtt 47 ms, colo WAW)"。 */
    private val msValue = Regex("""(\d{1,6})\s*ms(?![A-Za-z])""")

    fun parse(line: String): CoreExit? {
        val at = line.indexOf("exit:", ignoreCase = true)
        if (at < 0) return null
        val tail = line.substring(at + "exit:".length)

        val m = ipv4.find(tail) ?: return null
        val ip = m.value
        if (!routable(ip)) return null

        val after = tail.substring(m.range.last + 1)
        val country = ccAfterComma.find(after)?.groupValues?.get(1)?.uppercase()
            ?: flagCountry(tail)

        val latency = msValue.find(tail)?.groupValues?.get(1)?.toLongOrNull() ?: -1L
        return CoreExit(ip, country, latency)
    }

    /** 私网 / 回环 / 链路本地都不是出口；核心日志里出现它们说明读到的是别的东西。 */
    private fun routable(ip: String): Boolean {
        val p = ip.split('.').map { it.toIntOrNull() ?: return false }
        if (p.size != 4 || p.any { it !in 0..255 }) return false
        if (p[0] == 0 || p[0] == 10 || p[0] == 127) return false
        if (p[0] == 192 && p[1] == 168) return false
        if (p[0] == 172 && p[1] in 16..31) return false
        if (p[0] == 169 && p[1] == 254) return false
        if (p[0] == 100 && p[1] in 64..127) return false
        return true
    }

    /**
     * 从国旗 emoji（两个区域指示符 U+1F1E6…U+1F1FF）反推国家码。
     *
     * 核心打的是 `<旗> <英文国名> <ip>`，国名要建表才能转码，而旗子本身就是编码，
     * 拆一下就有 ISO2 —— 不依赖任何国家名映射。
     */
    private fun flagCountry(line: String): String {
        // 区域指示符在 UTF-16 里是代理对：U+1F1E6 = D83C DDE6。
        // 逐个 char 扫，不依赖 CharSequence.codePoints()（那是 API 24 起才有的）。
        var i = 0
        while (i + 3 < line.length) {
            val lo1 = line[i + 1]
            val lo2 = line[i + 3]
            if (line[i] == '\uD83C' && line[i + 2] == '\uD83C' &&
                lo1 in '\uDDE6'..'\uDDFF' && lo2 in '\uDDE6'..'\uDDFF'
            ) {
                return "${'A' + (lo1 - '\uDDE6')}${'A' + (lo2 - '\uDDE6')}"
            }
            i++
        }
        return ""
    }
}
