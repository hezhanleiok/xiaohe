package com.aether.ther.net

import com.aether.ther.data.LogBus
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * 首页「延迟」到底该量什么。
 *
 * 之前量的是**一次完整 HTTP 请求的耗时**：DNS + TCP 握手 + 请求 + 等服务端生成
 * 响应 + 收完正文。穿隧道时这个数字天然是 1~3 秒，于是首页长期显示「1406ms /
 * 2800ms」这种几千的值——不是链路慢，是量错了东西。
 *
 * 这里改成真正的网络 RTT：TCP 三次握手（SYN → SYN-ACK）的往返时间，也就是
 * 「一个来回」。同一个目标连 2~3 次取最小值，避开第一次的冷启动（ARP/DNS/
 * 隧道首包）。
 *
 * 两种取数路径：
 *  - [direct]：本应用流量在隧道里（原生 WG/AWG/GOOL），直接 connect 就是穿隧道；
 *  - [throughSocks]：本应用被排除在 tun 之外（原生+Psiphon、Aether 核心），
 *    只能经本地 SOCKS5 量——CONNECT 应答回来的那一刻正好是一个完整往返。
 */
object Latency {

    /**
     * 探测目标：都必须是「穿隧道也一定能连通」的地址。
     *
     * 1.1.1.1 是 Cloudflare 自己的解析器，WARP 出口必然可达；8.8.8.8 与
     * 223.5.5.5 用来兜底不同出口地区的策略差异。端口用 443（几乎不会被中间设备
     * 特殊处理），不做 TLS 握手——我们要的是 RTT，不是证书。
     */
    private val targets = listOf(
        "1.1.1.1" to 443,
        "8.8.8.8" to 443,
        "223.5.5.5" to 443,
    )

    /** 单个目标最多试几次；取最小值。 */
    private const val SAMPLES = 2

    /**
     * 穿隧道直连测 RTT。全部失败返回 -1（界面显示「—」，绝不编造数字）。
     */
    fun direct(timeoutMs: Int = 2_000): Long {
        var best = -1L
        for ((host, port) in targets) {
            repeat(SAMPLES) {
                val ms = tcpConnect(host, port, timeoutMs)
                if (ms > 0 && (best < 0 || ms < best)) best = ms
            }
            // 已经拿到一个可信结果就不用把所有目标都试一遍：目标是「显示当前链路
            // 的 RTT」，不是给每个服务器做体检。
            if (best in 1..timeoutMs.toLong()) return best
        }
        return best
    }

    /**
     * 经本地 SOCKS5 测 RTT：计时只包住「握手 + CONNECT + 读应答」。
     *
     * 为什么这条路径也能代表延迟：CONNECT 请求要穿过整条链（赛风/隧道）到目标
     * 建连，应答回来就是一个完整往返。所以它天然包含赛风那一跳的 RTT —— 用户
     * 想看的正是「开了赛风之后到底多慢」。
     */
    fun throughSocks(socksPort: Int, timeoutMs: Int = 6_000): Long {
        if (socksPort <= 0) return -1
        var best = -1L
        for ((host, port) in targets) {
            repeat(SAMPLES) {
                val ms = socksRtt(socksPort, host, port, timeoutMs)
                if (ms > 0 && (best < 0 || ms < best)) best = ms
            }
            if (best in 1..timeoutMs.toLong()) return best
        }
        return best
    }

    private fun tcpConnect(host: String, port: Int, timeoutMs: Int): Long {
        val s = Socket()
        return try {
            val t0 = System.nanoTime()
            s.connect(InetSocketAddress(host, port), timeoutMs)
            val ms = (System.nanoTime() - t0) / 1_000_000
            if (ms <= 0) 1 else ms
        } catch (e: Exception) {
            -1
        } finally {
            runCatching { s.close() }
        }
    }

    private fun socksRtt(socksPort: Int, host: String, port: Int, timeoutMs: Int): Long {
        val s = Socket()
        return try {
            s.connect(InetSocketAddress("127.0.0.1", socksPort), 3_000)
            s.soTimeout = timeoutMs
            val input = DataInputStream(BufferedInputStream(s.getInputStream()))
            val output = DataOutputStream(s.getOutputStream())

            val t0 = System.nanoTime()
            output.write(byteArrayOf(5, 1, 0)); output.flush()
            if (input.readUnsignedByte() != 5 || input.readUnsignedByte() != 0) return -1

            val hostBytes = host.toByteArray(Charsets.UTF_8)
            output.write(byteArrayOf(5, 1, 0, 3, hostBytes.size.toByte()))
            output.write(hostBytes)
            output.writeShort(port)
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
            if (ver != 5 || rep != 0) return -1

            val ms = (System.nanoTime() - t0) / 1_000_000
            if (ms <= 0) 1 else ms
        } catch (e: Exception) {
            LogBus.d("Latency", "经 SOCKS 测延迟失败：${e.message}")
            -1
        } finally {
            runCatching { s.close() }
        }
    }
}
