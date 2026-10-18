package com.aether.ther.net

import com.aether.ther.data.LogBus
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 系统代理模式的入口：把核心的本地 SOCKS5 暴露成一个稳定的
 * `127.0.0.1:7890`，这样用户手动填进 Wi-Fi 代理设置的地址不会随着每次连接的
 * 随机端口变化。
 *
 * 这是一个**桥**，不是一个独立代理：所有 CONNECT 目标都转给上游核心的 SOCKS，
 * 因此不存在「绕开隧道直连」的代码路径（上游不可用时直接拒绝，fail-closed）。
 *
 * 只做 CONNECT：BIND / UDP ASSOCIATE 一律拒绝 —— UDP 走不到核心的隧道里，
 * 放行会让 DNS/QUIC 泄漏到物理网络上。
 */
class LocalProxy(
    private val listenPort: Int = 7890,
    private val upstreamPort: Int,
) {
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null
    private val sockets: MutableSet<Socket> = Collections.synchronizedSet(HashSet())

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress("127.0.0.1", listenPort))
        server = ss
        LogBus.i("Proxy", "系统代理已监听 127.0.0.1:$listenPort → 上游 SOCKS 127.0.0.1:$upstreamPort")
        Thread({
            while (running.get()) {
                val client = runCatching { ss.accept() }.getOrNull() ?: continue
                sockets.add(client)
                Thread({ handle(client) }, "proxy-conn").apply { isDaemon = true }.start()
            }
        }, "proxy-accept").apply { isDaemon = true }.start()
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { server?.close() }
        server = null
        synchronized(sockets) {
            sockets.forEach { runCatching { it.close() } }
            sockets.clear()
        }
        LogBus.i("Proxy", "系统代理已停止")
    }

    private fun handle(client: Socket) {
        try {
            client.soTimeout = 30_000
            val input = DataInputStream(BufferedInputStream(client.getInputStream()))
            val output = DataOutputStream(BufferedOutputStream(client.getOutputStream()))

            // --- 握手：只接受「无认证」
            val ver = input.readUnsignedByte()
            if (ver != 5) return
            val nmethods = input.readUnsignedByte()
            repeat(nmethods) { input.readUnsignedByte() }
            output.write(byteArrayOf(5, 0))
            output.flush()

            // --- 请求：只需要 CONNECT
            val rver = input.readUnsignedByte()
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()
            if (rver != 5) return
            if (cmd != 1) {
                reply(output, 7)
                return
            }
            val host = when (atyp) {
                1 -> {
                    val b = ByteArray(4); input.readFully(b); b.joinToString(".") { (it.toInt() and 0xFF).toString() }
                }
                4 -> {
                    val b = ByteArray(16); input.readFully(b)
                    java.net.InetAddress.getByAddress(b).hostAddress ?: return
                }
                3 -> {
                    val len = input.readUnsignedByte()
                    val b = ByteArray(len); input.readFully(b); String(b, Charsets.UTF_8)
                }
                else -> {
                    reply(output, 8); return
                }
            }
            val port = input.readUnsignedShort()

            // --- 连上游核心
            val upstream = Socket()
            try {
                upstream.connect(InetSocketAddress("127.0.0.1", upstreamPort), 10_000)
            } catch (e: IOException) {
                LogBus.w("Proxy", "上游 SOCKS 不可用（$host:$port）：${e.message}")
                reply(output, 1)
                return
            }
            sockets.add(upstream)
            upstream.soTimeout = 0

            val upOut = DataOutputStream(BufferedOutputStream(upstream.getOutputStream()))
            val upIn = DataInputStream(BufferedInputStream(upstream.getInputStream()))
            // 上游握手
            upOut.write(byteArrayOf(5, 1, 0)); upOut.flush()
            val upVer = upIn.readUnsignedByte()
            val upMethod = upIn.readUnsignedByte()
            if (upVer != 5 || upMethod != 0) {
                LogBus.w("Proxy", "上游拒绝无认证：ver=$upVer method=$upMethod")
                reply(output, 1)
                upstream.close()
                return
            }
            // 转发 CONNECT 请求
            upOut.write(byteArrayOf(5, 1, 0, atyp.toByte()))
            when (atyp) {
                1 -> upOut.write(java.net.InetAddress.getByName(host).address)
                4 -> upOut.write(java.net.InetAddress.getByName(host).address)
                else -> {
                    val b = host.toByteArray(Charsets.UTF_8)
                    upOut.write(b.size)
                    upOut.write(b)
                }
            }
            upOut.writeShort(port)
            upOut.flush()

            // 上游应答原样回给客户端
            val repVer = upIn.readUnsignedByte()
            val rep = upIn.readUnsignedByte()
            upIn.readUnsignedByte()
            val repAtyp = upIn.readUnsignedByte()
            val addrBytes = when (repAtyp) {
                1 -> ByteArray(4).also { upIn.readFully(it) }
                4 -> ByteArray(16).also { upIn.readFully(it) }
                3 -> ByteArray(upIn.readUnsignedByte()).also { upIn.readFully(it) }
                else -> ByteArray(0)
            }
            val repPort = upIn.readUnsignedShort()
            output.write(repVer)
            output.write(rep)
            output.write(0)
            output.write(repAtyp)
            output.write(addrBytes)
            output.writeShort(repPort)
            output.flush()
            if (rep != 0) {
                LogBus.w("Proxy", "上游拒绝 $host:$port（rep=$rep）")
                upstream.close()
                return
            }

            // --- 双向搬运
            val t = Thread({
                runCatching {
                    val buf = ByteArray(16 * 1024)
                    while (true) {
                        val n = upIn.read(buf)
                        if (n <= 0) break
                        output.write(buf, 0, n); output.flush()
                    }
                }
                runCatching { client.shutdownOutput() }
            }, "proxy-up").apply { isDaemon = true }
            t.start()
            runCatching {
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    upOut.write(buf, 0, n); upOut.flush()
                }
            }
            runCatching { upstream.shutdownOutput() }
            t.join(30_000)
            upstream.close()
        } catch (_: EOFException) {
            // 客户端提前断开：正常现象，不刷日志
        } catch (e: IOException) {
            LogBus.d("Proxy", "连接结束：${e.message}")
        } finally {
            runCatching { client.close() }
            sockets.remove(client)
        }
    }

    private fun reply(out: DataOutputStream, code: Int) {
        runCatching {
            out.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
            out.flush()
        }
    }
}
