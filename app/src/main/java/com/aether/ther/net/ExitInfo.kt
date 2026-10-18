package com.aether.ther.net

import com.aether.ther.data.LogBus
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket

data class ExitProbe(val ip: String, val country: String, val latencyMs: Long)

/**
 * 「连上之后首页要把本机 IP 换成出口 IP」—— 这句话决定了必须**穿过隧道**去问
 * 一个外部服务，而不能读系统网络接口。所以这里走的是核心自己的本地 SOCKS：
 * 能拿到出口 IP 说明隧道真的在转发；拿不到就如实返回 null，界面保持本机 IP。
 *
 * 选 ipinfo.io 的纯 HTTP 接口：不需要 TLS（省一次握手，也避免证书/DNS 依赖），
 * 返回 JSON 小到几十字节。用 http://ip-api.com 之类也可以，但它的限流更凶。
 */
object ExitInfo {

    private const val HOST = "ipinfo.io"
    private const val PORT = 80
    private const val PATH = "/json"

    /**
     * VPN / Tun 模式下的出口探测：此时整机流量已经被 VpnService 接管，直接发
     * 一个普通 HTTP 请求就会穿过隧道，所以不需要（也没有）本地 SOCKS。
     */
    fun probeDirect(timeoutMs: Int = 12_000): ExitProbe? {
        val started = System.currentTimeMillis()
        return try {
            val conn = (java.net.URL("http://$HOST$PATH").openConnection() as java.net.HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                setRequestProperty("User-Agent", "ther-android")
            }
            try {
                if (conn.responseCode != 200) {
                    LogBus.w("Exit", "出口探测：HTTP ${conn.responseCode}")
                    return null
                }
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                val json = JSONObject(body)
                val ip = json.optString("ip")
                val country = json.optString("country")
                if (ip.isBlank()) {
                    LogBus.w("Exit", "出口探测：返回里没有 ip 字段")
                    return null
                }
                val latency = System.currentTimeMillis() - started
                LogBus.i("Exit", "出口 $ip (${country.ifBlank { "??" }})，探测耗时 ${latency}ms")
                ExitProbe(ip, country, latency)
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            LogBus.w("Exit", "出口探测失败：${e.message}")
            null
        }
    }

    /**
     * 连接阶段的「数据面可用」校验，与电脑版 `internal/wgtun` 的 verifyDataPlane
     * 完全同构：先快速试一次，失败就每 300ms 重试，最多骑过 3s 的收敛窗口。
     *
     * 为什么必须重试：握手刚完成的那一两秒，本机路由 / FIB 还没收敛（安卓上
     * 典型表现是第一次 connect 直接 ENETUNREACH），单次探测会把一条好隧道判成
     * 死的，于是候选端点被一个个否掉，用户看到的就是「无法连接」。电脑版就是
     * 因为这个把「一次探测」改成了「短重试」，这里照搬。
     */
    fun probeDataPlaneSettled(): Boolean {
        if (probeDataPlane(3_000)) return true
        val deadline = System.currentTimeMillis() + SETTLE_WINDOW_MS
        var attempt = 1
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(RETRY_INTERVAL_MS)
            attempt++
            if (probeDataPlane(2_000)) {
                LogBus.i("Exit", "数据面第 $attempt 次探测通过（已骑过收敛窗口）")
                return true
            }
        }
        return false
    }

    /** 与电脑版 dataPlaneSettleWindow / dataPlaneRetryInterval 同值。 */
    private const val SETTLE_WINDOW_MS = 3_000L
    private const val RETRY_INTERVAL_MS = 300L

    /**
     * 隧道数据面健康检查：只做一次 TCP 握手（不发 DNS、不发 HTTP）。
     *
     * 走 IP 字面量（1.1.1.1:443）：隧道刚起来时 DNS 未必可用，用它做判据会把
     * 「DNS 没配好」误判成「隧道不通」。连接阶段请用 [probeDataPlaneSettled]。
     */
    fun probeDataPlane(timeoutMs: Int = 3_000): Boolean {
        val started = System.currentTimeMillis()
        return try {
            java.net.Socket().use { s ->
                s.connect(java.net.InetSocketAddress("1.1.1.1", 443), timeoutMs)
            }
            LogBus.d("Exit", "数据面确认：TCP 1.1.1.1:443 ${System.currentTimeMillis() - started}ms")
            true
        } catch (e: Exception) {
            LogBus.w("Exit", "数据面不通（TCP 1.1.1.1:443，${System.currentTimeMillis() - started}ms）：${e.message}")
            false
        }
    }

    /**
     * 直连查「本机」的公网 IP + 所在国家（不穿隧道，启动时用）。
     *
     * 为什么不是一个源：这几个接口在国内的连通性差别很大，ipinfo.io 经常慢到超时。
     * 依次尝试，谁先给出合法结果就用谁；全失败返回 null，界面退回到内网 IP。
     */
    fun probeLocal(timeoutMs: Int = 5_000): ExitProbe? {
        val started = System.currentTimeMillis()
        val sources = listOf(
            // ip-api：返回 query/countryCode，纯 HTTP，国内一般可达。
            Source("http://ip-api.com/json/?fields=status,query,countryCode") { json ->
                if (json.optString("status") != "success") null
                else json.optString("query") to json.optString("countryCode")
            },
            Source("http://ipinfo.io/json") { json ->
                json.optString("ip") to json.optString("country")
            },
            Source("https://api.ip.sb/geoip") { json ->
                json.optString("ip") to json.optString("country_code")
            },
        )
        for (src in sources) {
            val json = httpJson(src.url, timeoutMs) ?: continue
            val pair = runCatching { src.parse(json) }.getOrNull()
            val ip = pair?.first.orEmpty()
            if (ip.isBlank()) {
                LogBus.d("Exit", "本机探测：${src.url} 没给出 ip")
                continue
            }
            val latency = System.currentTimeMillis() - started
            LogBus.i("Exit", "本机 $ip（${pair?.second?.ifBlank { "??" }}），探测耗时 ${latency}ms")
            return ExitProbe(ip, pair?.second.orEmpty(), latency)
        }
        LogBus.w("Exit", "本机探测失败：所有来源都没返回可用结果")
        return null
    }

    private class Source(
        val url: String,
        val parse: (JSONObject) -> Pair<String, String>?,
    )

    /** 取一个 JSON 正文；失败返回 null（不抛，调用方只关心有没有结果）。 */
    private fun httpJson(url: String, timeoutMs: Int): JSONObject? = try {
        val conn = (java.net.URL(url).openConnection() as java.net.HttpURLConnection).apply {
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("User-Agent", "ther-android")
        }
        try {
            if (conn.responseCode != 200) {
                LogBus.d("Exit", "本机探测：$url HTTP ${conn.responseCode}")
                null
            } else {
                JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
            }
        } finally {
            conn.disconnect()
        }
    } catch (e: Exception) {
        LogBus.d("Exit", "本机探测：$url 失败（${e.message}）")
        null
    }

    fun probeThroughSocks(socksPort: Int, timeoutMs: Int = 12_000): ExitProbe? {
        val started = System.currentTimeMillis()
        val socket = Socket()
        return try {
            socket.connect(InetSocketAddress("127.0.0.1", socksPort), 5_000)
            socket.soTimeout = timeoutMs
            val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
            val output = DataOutputStream(socket.getOutputStream())

            // SOCKS5 握手（无认证）
            output.write(byteArrayOf(5, 1, 0)); output.flush()
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0) {
                LogBus.w("Exit", "出口探测：核心 SOCKS 拒绝无认证")
                return null
            }
            // CONNECT ipinfo.io:80（用域名，让出口侧解析，顺便验证 DNS 没泄漏到本地）
            val hostBytes = HOST.toByteArray(Charsets.UTF_8)
            output.write(byteArrayOf(5, 1, 0, 3, hostBytes.size.toByte()))
            output.write(hostBytes)
            output.writeShort(PORT)
            output.flush()

            val ver = input.readUnsignedByte()
            val rep = input.readUnsignedByte()
            input.readUnsignedByte()
            val atyp = input.readUnsignedByte()
            when (atyp) {
                1 -> input.skipBytes(4)
                4 -> input.skipBytes(16)
                3 -> input.skipBytes(input.readUnsignedByte())
            }
            input.skipBytes(2)
            if (ver != 5 || rep != 0) {
                LogBus.w("Exit", "出口探测：CONNECT 被拒绝 rep=$rep")
                return null
            }

            val req = "GET $PATH HTTP/1.1\r\nHost: $HOST\r\nUser-Agent: ther-android\r\nConnection: close\r\n\r\n"
            output.write(req.toByteArray(Charsets.US_ASCII)); output.flush()

            val raw = input.readBytes().toString(Charsets.UTF_8)
            val body = raw.substringAfter("\r\n\r\n", "")
            if (body.isBlank()) {
                LogBus.w("Exit", "出口探测：响应没有正文")
                return null
            }
            val json = JSONObject(body)
            val ip = json.optString("ip")
            val country = json.optString("country")
            if (ip.isBlank()) {
                LogBus.w("Exit", "出口探测：返回里没有 ip 字段")
                return null
            }
            val latency = System.currentTimeMillis() - started
            LogBus.i("Exit", "出口 ${ip.ifBlank { "?" }} (${country.ifBlank { "??" }})，探测耗时 ${latency}ms")
            ExitProbe(ip, country, latency)
        } catch (e: Exception) {
            LogBus.w("Exit", "出口探测失败：${e.message}")
            null
        } finally {
            runCatching { socket.close() }
        }
    }
}
