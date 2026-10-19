package com.aether.ther.core

import android.content.Context
import android.os.Build
import com.aether.ther.Hub
import com.aether.ther.data.LogBus
import com.aether.ther.data.SettingsStore
import com.aether.ther.data.WireProtocol
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Aether 核心：CluvexStudio/Aether 的独立进程（Rust CLI，v2.3.0）。
 *
 * 接口照着**实际发布的二进制**写（`aether --help` 原文核对过）：
 *
 * ```
 *   --psiphon          carry psiphon inside the tunnel: aether -> warp -> psiphon
 *                      -> internet, served on --psiphon-bind
 *   --psiphon-bind <addr>   where the psiphon proxy listens (default 127.0.0.1:1821)
 *   --psiphon-http <addr>   also serve psiphon as an http/connect proxy here
 *   --psiphon-region <cc>   ask psiphon to leave from this country
 *   --bind <addr>      local SOCKS5 for the *warp* exit (default 127.0.0.1:1819)
 * ```
 *
 * ★ 两个监听不能混：`--bind` 出去是 WARP 的出口（104.28.x.x / CN），赛风出口在
 * `--psiphon-bind` 上。只把 `--bind` 交给上层，等于「开了赛风但出口没换」。
 *
 * 没有 `--tun-fd`：核心不接管 tun，整机模式需要外部 tun→SOCKS 前端。
 *
 * 可执行文件必须放 nativeLibraryDir（伪装成 `lib*.so`）：targetSdk>=29 时
 * Android 10 起禁止 exec 应用数据目录里的文件（W^X）。
 */
class AetherCore(private val context: Context) : CoreEngine {
    override val id = "aether"
    override val displayName = "Aether 核心"
    override val provider = "CluvexStudio/Aether · 独立进程"

    @Volatile
    private var process: Process? = null

    @Volatile
    private var running = false

    /**
     * 核心自己说的「赛风已经能出去」（日志 "psiphon is ready"）。
     *
     * 不能拿「端口开始 listen」当就绪：赛风的 SOCKS 端口在它自己连上服务器之前
     * 就开着了，此时所有 CONNECT 都回 rep=1/rep=5。2026-10-17 的日志里就是
     * 早了 10 秒切过去，整整 10 秒里每个包都失败。
     */
    @Volatile
    private var psiphonReady = false

    /** 最后一行和赛风有关的核心日志，超时的时候拿来当证据。 */
    @Volatile
    private var lastPsiphonLine = ""

    /**
     * 这一次赛风启动里，「上游拨不出去」这类致命行的条数。
     *
     * 为什么要数：原生核心 + 赛风时，赛风的每一条 TCP 都从**我方隧道里**的
     * socks5 出去。隧道一旦是「握手通、数据不通」的端点，赛风拿到的就是
     * connection refused / timeout，它会一直重试到超时（手机日志里白等 45s，
     * 换 cdn 又等一轮）。数够 [PSIPHON_FATAL_HITS] 条就当场判死，去换端点。
     */
    @Volatile
    private var psiphonFatalHits = 0

    /** 「上游拨不出去」的特征行。只认这几种，避免把赛风正常的重试当故障。 */
    private fun isUpstreamFatal(line: String): Boolean {
        val s = line.lowercase()
        return s.contains("meek round trip failed") ||
            s.contains("connection refused") ||
            s.contains("socks connect tcp")
    }

    /**
     * 这一次启动是不是「H3 失败后自动改走 H2」的第二次尝试。
     *
     * 只是为了让 start() 递归一次时换掉协议参数，别再多留状态。
     */
    @Volatile
    private var h2Fallback = false

    /** VPN 模式下把 tun 接到核心 SOCKS5 的用户态协议栈（gomobile 的 Go 引擎）。 */
    @Volatile
    private var bridge: engine.Engine_? = null

    @Volatile
    private var pump: Thread? = null

    /**
     * 本实例已被 [stop] 作废（同 [NativeCore] 里的同名标记）。
     *
     * 启动里最长的步骤是「等隧道端口 / 等赛风就绪」，几十秒都有可能。这期间
     * 用户又点了一次连接，新会话会先 stop 旧实例；旧实例如果不检查这个标记，
     * 就会在 stop 之后把核心进程和赛风进程**继续跑在后台**，占着端口和数据库锁，
     * 下一次带赛风的连接就会「datastore timeout / 端口被占」。
     */
    @Volatile
    private var closing = false

    private fun ensureAlive() {
        if (closing) throw IllegalStateException("连接已被新的会话取代")
    }

    override fun isAvailable(): Boolean = binaryOrNull() != null

    override fun unavailableReason(): String =
        if (Build.SUPPORTED_ABIS.contains("arm64-v8a")) {
            "内置的 Aether 核心没解出来（nativeLibraryDir 里没有 libaether.so）。" +
                "请重新安装本版本；仍不行就是打包配置的问题，看安装日志。"
        } else {
            "内置的 Aether 核心只有 arm64 版；这台设备的 ABI 是 " +
                Build.SUPPORTED_ABIS.joinToString("/") + "。"
        }

    // ------------------------------------------------------------------
    // 路径
    // ------------------------------------------------------------------

    /** 核心自己的状态目录（配置、赛风的临时文件）；nativeLibraryDir 是只读的。 */
    private fun coreDir(): File = File(context.filesDir, "core").apply { mkdirs() }

    private fun configFile(): File = File(coreDir(), "aether.toml")

    private fun nativeDir(): File = File(context.applicationInfo.nativeLibraryDir)

    private fun defaultBinary(): File = File(nativeDir(), "libaether.so")

    private fun psiphonBinary(): File = File(nativeDir(), "libpsiphon.so")

    private fun binaryOrNull(): File? {
        val configured = SettingsStore.load(context).aetherCorePath
        if (configured.isNotBlank()) {
            val f = File(configured)
            if (f.isFile) return f
        }
        val f = defaultBinary()
        return if (f.isFile) f else null
    }

    // ------------------------------------------------------------------
    // 启动 / 停止
    // ------------------------------------------------------------------

    override fun start(cfg: EngineConfig, tunFd: Int?): EngineEndpoint {
        // 先收掉上一次（stop 会把 closing 置真），再清掉作废标记 —— 顺序反了的话
        // 这里的 stop() 会把自己刚放开的标记又打上，整条 start 立刻自己退出。
        if (running) stop()
        closing = false

        val bin = binaryOrNull() ?: throw IllegalStateException(unavailableReason())
        if (!bin.canExecute() && !bin.setExecutable(true, false)) {
            throw IllegalStateException("核心文件不可执行：${bin.absolutePath}")
        }
        val psiphon = psiphonBinary()
        if (cfg.psiphonExit && !psiphon.isFile) {
            throw IllegalStateException("内置的赛风客户端缺失（${psiphon.absolutePath}），无法走赛风出口。")
        }

        // warp 出口和赛风出口是两个独立监听，端口都由我们指定（避免撞端口）。
        val warpPort = pickPort()
        val psiphonPort = if (cfg.psiphonExit) pickPort() else 0
        val httpPort = if (cfg.psiphonExit) 0 else pickPort()

        val cmd = mutableListOf(
            bin.absolutePath,
            "--bind", "127.0.0.1:$warpPort",
            // 持久化 WARP 身份：不保存的话每次连接都重新注册设备，会被 Cloudflare 限流。
            "--config", configFile().absolutePath,
            "--stats",
        )
        // 赛风模式下不开 WARP 的 HTTP 代理：那个口出去还是 WARP，留着容易被误用。
        if (!cfg.psiphonExit) cmd += listOf("--http-proxy", "127.0.0.1:$httpPort")
        cmd += if (h2Fallback) listOf("--protocol", "masque", "--h2") else protocolFlags(cfg.protocol)
        if (cfg.psiphonExit) {
            // 自己拥有赛风的数据目录（默认是 <config>-psiphon，散在 core/ 里），
            // 这样锁文件和数据库都在一个可控的地方；先清锁、再交给核心。
            clearStalePsiphonLocks()
            cmd += listOf("--psiphon", "--psiphon-bind", "127.0.0.1:$psiphonPort")
            cmd += listOf("--psiphon-dir", psiphonDir().absolutePath)
            cmd += listOf("--psiphon-bin", psiphon.absolutePath)
            if (cfg.exitRegion.isNotBlank()) {
                cmd += listOf("--psiphon-region", cfg.exitRegion.trim())
            }
        }
        val dns = cfg.dns.split(',', ' ', ';').filter { it.isNotBlank() }
        if (dns.isNotEmpty()) cmd += listOf("--dns", dns.joinToString(","))

        // 身份文件在不在、多大，决定了这次要不要重新注册 WARP 设备。重新注册要访问
        // api.cloudflareclient.com，一条 DNS 失败就会让整次连接失败，所以先把它写清楚。
        LogBus.i(
            "AetherCore",
            if (configFile().isFile) {
                "身份文件 ${configFile().absolutePath}（${configFile().length()} 字节）"
            } else {
                "没有身份文件（${configFile().absolutePath}）：本次会向 Cloudflare 注册新设备"
            },
        )
        LogBus.i("AetherCore", "启动（内置 $CORE_VERSION）：${cmd.joinToString(" ")}")
        val pb = ProcessBuilder(cmd)
            .directory(coreDir())
            .redirectErrorStream(true)
        // 赛风客户端要写自己的状态/临时文件，HOME 指到应用私有目录，
        // 否则它去碰不存在的 $HOME 会直接失败。
        pb.environment()["HOME"] = coreDir().absolutePath
        pb.environment()["TMPDIR"] = context.cacheDir.absolutePath
        // 传输层的几个开关只在环境变量里（核心没有对应 CLI），见 coreEnv。
        val env = coreEnv(cfg.protocol, h2Fallback)
        if (env.isNotEmpty()) {
            pb.environment().putAll(env)
            LogBus.i("AetherCore", "传输层环境：" + env.entries.joinToString(" ") { "${it.key}=${it.value}" })
        }

        psiphonReady = false
        lastPsiphonLine = ""

        val p = pb.start()
        process = p

        startLogThread(p)

        // ① 先等 warp 隧道：官方要先扫描 + 端到端校验，之后才把 SOCKS 打开。
        //    MASQUE 扫描的官方预算是 120s，所以这里给 180s 而不是 90s
        //    （2026-10-17：90s 会在 MASQUE 扫描还没结束时就被我们掐掉）。
        //
        //    例外是 MASQUE H3：它走 QUIC(UDP/443)，在国内移动网被整段限速/丢包时
        //    核心会一直卡在「深校验」阶段（2026-10-17 实测：候选 rtt 2.9~3.2s，
        //    90s 都没选出网关）。这种情况下干等 180s 没有意义，到点就自动换成
        //    H2 —— 同一条 MASQUE 隧道，只是把传输从 QUIC 换成 TCP/443。
        val tunnelWait =
            if (cfg.protocol == WireProtocol.MASQUE_H3 && !h2Fallback) H3_GATEWAY_WAIT_MS else TUNNEL_WAIT_MS
        try {
            waitForPort(p, warpPort, tunnelWait, "WARP 隧道")
        } catch (e: IllegalStateException) {
            if (cfg.protocol != WireProtocol.MASQUE_H3 || h2Fallback) throw e
            LogBus.w(
                "AetherCore",
                "MASQUE H3 在 ${tunnelWait / 1000}s 内没选出可用网关（QUIC/UDP/443 这条线路不通或极慢）" +
                    "→ 自动改用 MASQUE H2：同一条 MASQUE 隧道，传输换成 TCP/443。",
            )
            Hub.update { it.copy(message = "H3 走不通，正在改用 MASQUE H2（TCP）…") }
            h2Fallback = true
            return try {
                start(cfg, tunFd)
            } finally {
                h2Fallback = false
            }
        }
        // ② 赛风是**隧道内**的第二跳，隧道通了之后才开始拨号，官方默认最多等 180s。
        if (cfg.psiphonExit) {
            waitForPort(p, psiphonPort, PSIPHON_WAIT_MS, "赛风出口")
            // 端口 listen ≠ 能用：还要等核心把 CONNECT 真正转进赛风。
            awaitPsiphonReady(p)
        }

        // 走到这里可能已经过了几分钟：这段时间里用户可能已经点了停止、或者开了
        // 一条新连接（新会话会调 stop()）。此时绝不能把进程交出去 —— 一旦
        // running/engine 被新会话覆盖，这个孤儿进程就再没人杀了（赛风会一直占
        // 着 BoltDB 的锁，下一次带赛风的连接必然 datastore timeout）。
        if (closing) {
            runCatching { destroyChildren(p) }
            runCatching { p.destroy() }
            throw IllegalStateException("连接已被新的会话取代")
        }

        running = true
        val readyPort = if (cfg.psiphonExit) psiphonPort else warpPort
        LogBus.i(
            "AetherCore",
            "已就绪：对外 socks=127.0.0.1:$readyPort" +
                if (cfg.psiphonExit) "（赛风出口 ${cfg.exitRegion.ifBlank { "自动" }}，隧道内第二跳）"
                else "（WARP 出口，http=127.0.0.1:$httpPort）",
        )
        // VPN 模式：核心只开本地 SOCKS5，tun 里的包得由引擎的用户态协议栈接过去。
        if (tunFd != null && tunFd > 0) {
            startSocksBridge(tunFd, readyPort, cfg)
        }
        return EngineEndpoint(readyPort, if (cfg.psiphonExit) null else httpPort)
    }

    /**
     * VPN 模式的最后一公里：tun → gVisor 用户态协议栈 → 本地 SOCKS5（核心出口）。
     *
     * 没有它，VPN 模式下 aether 核心「已连接」也一个包都出不去；Android 的
     * 「系统代理」又只有 Wi-Fi HTTP 代理，绝大多数应用不认，所以这一步必须做。
     */
    private fun startSocksBridge(tunFd: Int, socksPort: Int, cfg: EngineConfig) {
        val dns = cfg.dns.split(',', ' ', ';').firstOrNull { it.isNotBlank() } ?: "1.1.1.1"
        val e = engine.Engine_()
        runCatching { e.setLogFile(File(context.filesDir, "logs/engine.log").absolutePath) }
        runCatching {
            e.setClockOffsetMinutes(
                (java.util.TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000).toLong(),
            )
        }
        LogBus.i(
            "AetherCore",
            "启动 tun→SOCKS 转换：fd=$tunFd → 127.0.0.1:$socksPort mtu=${cfg.mtu} dns=$dns（TCP DNS）",
        )
        e.startSocks("127.0.0.1:$socksPort", tunFd.toLong(), dns, cfg.mtu.toLong())
        bridge = e
        pump = Thread({
            try {
                while (bridge === e) {
                    val text = runCatching { e.drainLogs() }.getOrNull().orEmpty()
                    if (text.isNotBlank()) {
                        text.lineSequence().filter { it.isNotBlank() }.forEach { LogBus.i("Core", it) }
                    }
                    Thread.sleep(500)
                }
            } catch (_: InterruptedException) {
                // stop() 叫停，正常退出
            } catch (t: Throwable) {
                LogBus.w("AetherCore", "转换层日志线程退出：${t.message}")
            }
        }, "socks-tun-log").apply { isDaemon = true }
        pump?.start()
        LogBus.i("AetherCore", "tun 已交由引擎接管（socks-tun）")
    }

    override fun stop() {
        // 先作废：正在跑的 start() 会在下一个检查点自己收手（见 ensureAlive）。
        closing = true
        pump?.interrupt()
        pump = null
        val b = bridge
        bridge = null
        if (b != null) {
            LogBus.i("AetherCore", "停止 tun→SOCKS 转换")
            runCatching { b.stop() }
        }
        val p = process ?: return
        process = null
        running = false
        LogBus.i("AetherCore", "停止核心进程")
        // 赛风是核心的子进程：只杀父进程的话它会被 init 收养继续活着，并且
        // 一直占着 BoltDB 的锁 —— 下一次带赛风的连接就会「datastore timeout」。
        // 先把整棵子进程树拆掉，再杀父进程。
        destroyChildren(p)
        runCatching { p.destroy() }
        runCatching { if (!p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) p.destroyForcibly() }
    }

    /**
     * 核心的传输层环境变量，照电脑版 `internal/vpn/vpn.go` 的 envFor 抄（2.3.0 实测）。
     *
     * 三个都和「连得上/有速度」直接相关，缺一个的表现分别是：
     *
     *  - **MASQUE H2 必须开 ClientHello 分片**：TCP/443 是 TLS 层 DPI 的首要目标，
     *    默认那种 16~32 字节的分片会被 RST；电脑版实测 1~3 字节才过得去。
     *  - **MIM 必须是 H3-in-H3**（`AETHER_MASQUE_HTTP2=0`）：2.3.0 上 H2-in-H2
     *    永远出不了扫描阶段，界面就一直停在「连接中」。
     *  - **WG / GOOL 类的 `--noize` 默认（balanced）在 2.3.0 上不通**：握手有应答、
     *    数据面校验永远超时（`verify timeout`，打完 socks 口也照样没字节）。电脑版
     *    2026-10-18 实测换成 `gfw` 后 HTTP 200 / 5.89 MB/s。这就是「Aether 核心协议
     *    慢」的主因 —— 不是带宽，是数据面根本没验证过。
     *
     * MASQUE H3（含普通 h3）不设：核心自己对 MASQUE 默认就是 firewall profile。
     */
    private fun coreEnv(protocol: WireProtocol, h2Fallback: Boolean): Map<String, String> {
        val env = linkedMapOf<String, String>()
        when {
            h2Fallback || protocol == WireProtocol.MASQUE_H2 -> {
                env["AETHER_MASQUE_HTTP2"] = "1"
                env["AETHER_MASQUE_H2_FRAGMENT"] = "1"
                env["AETHER_MASQUE_H2_FRAGMENT_SIZE"] = "1-3"
                env["AETHER_MASQUE_H2_FRAGMENT_DELAY"] = "5-20"
            }
            protocol == WireProtocol.MASQUE_IN_MASQUE -> {
                // 两层都用 HTTP/3（与电脑版同一对载体）。
                env["AETHER_MASQUE_HTTP2"] = "0"
            }
        }
        // 只有 WireGuard 类吃这个 profile；MASQUE 保持核心自己的 firewall 默认。
        if (protocol == WireProtocol.AETHER_WG || protocol == WireProtocol.AETHER_GOOL) {
            env["AETHER_NOIZE"] = "gfw"
        }
        if (protocol == WireProtocol.AETHER_GOOL) {
            // 2.3.0 改了 --gool 的语义：现在是「MASQUE 里套一层 WG」，老的
            // WireGuard-in-WireGuard 改叫 --gool-classic。界面上这条和原生 GOOL
            // 一样指 WG-in-WG，所以钉住 classic，别让它悄悄换协议。
            env["AETHER_GOOL_MODE"] = "classic"
        }
        // ★ 把 netstack 的 TCP 缓冲（也就是它通告出去的窗口）调大。
        //
        // aether 内部用的是 smoltcp，而 smoltcp 把「socket 接收缓冲剩余空间」
        // 直接当 TCP 窗口通告（aether 源码 sysprofile.rs 的注释就是这么写的）。
        // 所以它这个缓冲就是下载的第二个天花板，同样是 窗口 / RTT：
        //   High 档默认 2MB rx / 512KB tx，在 150ms RTT 上单流上限约 106Mbps，
        //   到了 300ms 就只剩 53Mbps，再叠加链式隧道就更难看。
        // 这就是「aether 核心的 WG / GOOL / MASQUE 比我们原生核心慢」的物理原因
        // ——我们原生核心的 gVisor 栈给的是 8~16MB。
        //
        // 这里取 4MB / 1MB（默认的两倍），是内存和吞吐的折中：这两个缓冲是
        // **每条连接预分配**的（源码注释：both halves are paid for up front on
        // every connection），给到 gVisor 那种 16MB 在手机上会按并发数放大成
        // 几百 MB。要再往上调，先确认目标机型的内存。
        env["AETHER_NETSTACK_TCP_RX"] = (4 * 1024 * 1024).toString()
        env["AETHER_NETSTACK_TCP_TX"] = (1 * 1024 * 1024).toString()
        // 强制高档，免得低端机判定成 Medium/Low 后缓冲被压回 1MB/256KB。
        env["AETHER_PERF_PROFILE"] = "high"
        return env
    }

    /** 界面上的协议 id → 官方 CLI。h2/h3 是 MASQUE 的载体修饰，不是独立协议。 */
    private fun protocolFlags(protocol: WireProtocol): List<String> = when (protocol) {
        WireProtocol.AETHER_WG -> listOf("--protocol", "wg")
        WireProtocol.MASQUE_H2 -> listOf("--protocol", "masque", "--h2")
        WireProtocol.MASQUE_H3 -> listOf("--protocol", "masque", "--h3")
        WireProtocol.AETHER_GOOL -> listOf("--protocol", "gool")
        WireProtocol.MASQUE_IN_MASQUE -> listOf("--protocol", "mim")
        else -> listOf("--protocol", "masque")
    }

    /**
     * 等到本地端口能连上；每 15s 往日志里报一次「还在等」，免得界面一动不动像卡死。
     * 超时就停掉进程并抛出人能看懂的原因。
     */
    private fun waitForPort(p: Process, port: Int, timeoutMs: Long, what: String) {
        val started = System.currentTimeMillis()
        var nextReport = 15_000L
        while (System.currentTimeMillis() - started < timeoutMs) {
            val ok = runCatching {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300) }
            }.isSuccess
            if (ok) return

            val alive = runCatching { p.isAlive }.getOrDefault(false)
            if (!alive) {
                val code = runCatching { p.exitValue() }.getOrNull()
                stop()
                throw IllegalStateException("Aether 核心进程已退出（code=$code），$what 没有起来。看日志里的 AetherCore 输出。")
            }
            val elapsed = System.currentTimeMillis() - started
            if (elapsed >= nextReport) {
                nextReport += 15_000L
                LogBus.i("AetherCore", "仍在等待 $what（127.0.0.1:$port），已 ${elapsed / 1000}s / ${timeoutMs / 1000}s")
            }
            Thread.sleep(250)
        }
        stop()
        throw IllegalStateException(
            "$what 在 ${timeoutMs / 1000}s 内没有监听 127.0.0.1:$port。看日志里的 AetherCore 输出。",
        )
    }

    /**
     * 核心自己的 stdout/stderr 直接进日志：进程崩了要能看到原因。
     *
     * 顺手接住两类东西：
     *  - 「出口」行（ExitLog）：核心是唯一知道包最后落在哪的角色；
     *  - 「psiphon is ready」：赛风第二跳真正可用的唯一信号。
     */
    private fun startLogThread(p: Process) {
        Thread({
            runCatching {
                p.inputStream.bufferedReader().forEachLine { line ->
                    if (line.isBlank()) return@forEachLine
                    LogBus.i("AetherCore", line)
                    if (line.contains("psiphon", ignoreCase = true)) lastPsiphonLine = line
                    if (!psiphonReady && line.contains("psiphon is ready")) {
                        psiphonReady = true
                        LogBus.i("AetherCore", "赛风第二跳已就绪（核心：$line）")
                    }
                    // 上游（我方隧道里的 socks5）根本拨不出去时，赛风会把同一个错误
                    // 刷很多遍，然后一直等到超时。这些行出现多次就说明这条路已经废了，
                    // 立即失败去换端点，别让用户等满 25s×2。
                    if (!psiphonReady && isUpstreamFatal(line)) psiphonFatalHits++
                    ExitLog.parse(line)?.let { exit ->
                        LogBus.i("Exit", "核心上报出口：${exit.ip}（${exit.country.ifBlank { "??" }}）")
                        // 不写核心自报的延迟：那是它建连时一次性量到的握手/探测耗时，
                        // 几千 ms 很正常。界面的延迟统一由 Latency 的 TCP RTT 提供。
                        Hub.exitInfo(exit.ip, exit.country)
                    }
                }
            }
            if (!p.isAlive) LogBus.w("AetherCore", "核心进程已退出，code=${runCatching { p.exitValue() }.getOrNull()}")
        }, "aether-core-log").apply { isDaemon = true }.start()
    }

    /**
     * 只借核心的「赛风」这一半：核心自己不建隧道（--psiphon-only），
     * 赛风的出站全部走 [upstream] —— 那是原生核心隧道里的 socks5。
     *
     * 这样「原生核心 + 赛风出口」就不需要我们自己实现 psiphon 配置/服务器列表：
     *
     *	设备 tun → socks-tun → 赛风 socks(本口) → 赛风客户端 → upstream → wireguard-go → 出口
     *
     * 返回时保证赛风已经 ready（否则调用方接上去就是一片 rep=1）。
     *
     * [healthCheck] 是上游隧道的健康检查：赛风在等服务器列表的这 10~20s 里，
     * 上游隧道可能已经断了（2026-10-18 22:51 的日志：隧道 22:51:21 握手成功、
     * 22:51:38 就「听不到回包」，而赛风还要等满 25s，接着 cdn 再等 25s）。
     * 返回 false 立刻判死，别让用户对着一条已经死掉的隧道干等 50s。
     */
    fun startPsiphonOnly(
        upstreamPort: Int,
        bindPort: Int,
        exitRegion: String,
        healthCheck: (() -> Boolean)? = null,
    ): Int {
        // 先用 auto（能用的网络上更快），拉不起来再换成 cdn：
        // 「只走前置 meek 经 CDN」是国内线路最常活下来的那一档。
        // 反过来（一上来就限死 cdn）会把 auto 本来能通的网络弄死，所以是这个顺序。
        //
        // 两档都只给 25s（原来 auto 45s、cdn 120s，最坏 165s，用户看到的就是
        // 「一直转圈」）。能通的线路 10~20s 就报 ready；拨不出去的会先在
        // awaitPsiphonReady 里被致命行提前判死。
        return try {
            launchPsiphonOnly(
                upstreamPort, bindPort, exitRegion,
                mode = "", readyWaitMs = PSIPHON_AUTO_WAIT_MS, healthCheck = healthCheck,
            )
        } catch (t: Throwable) {
            LogBus.w(
                "AetherCore",
                "赛风 auto 模式 ${PSIPHON_AUTO_WAIT_MS / 1000}s 内没就绪（${t.message}）" +
                    " → 改用 --psiphon-mode cdn（只走前置 meek 经 CDN）重试",
            )
            runCatching { stop() }
            launchPsiphonOnly(
                upstreamPort, bindPort, exitRegion,
                mode = "cdn", readyWaitMs = PSIPHON_CDN_WAIT_MS, healthCheck = healthCheck,
            )
        }
    }

    /** 起一次赛风专用进程；[mode] 非空时带上 --psiphon-mode，返回实际监听的 socks 端口。 */
    private fun launchPsiphonOnly(
        upstreamPort: Int,
        bindPort: Int,
        exitRegion: String,
        mode: String,
        readyWaitMs: Long,
        healthCheck: (() -> Boolean)? = null,
    ): Int {
        if (running) stop()
        val bin = binaryOrNull() ?: throw IllegalStateException(unavailableReason())
        if (!bin.canExecute() && !bin.setExecutable(true, false)) {
            throw IllegalStateException("核心文件不可执行：${bin.absolutePath}")
        }
        val psiphon = psiphonBinary()
        if (!psiphon.isFile) {
            throw IllegalStateException("内置的赛风客户端缺失（${psiphon.absolutePath}），无法走赛风出口。")
        }
        // 电脑版已经验证过的做法：不用 --upstream，而是写一份 overlay 配置
        // （--psiphon-config），里面同时钉 UpstreamProxyURL 和 LimitTunnelProtocols。
        // 只给 --upstream 的话，psiphon 仍可能挑中 QUIC 类协议而绕开隧道。
        clearStalePsiphonLocks()
        val overlay = writePsiphonOverlay(upstreamPort)
        val cmd = mutableListOf(
            bin.absolutePath,
            // 不建核心自己的隧道：出口由我方原生核心提供。
            "--psiphon-only",
            "--bind", "127.0.0.1:$bindPort",
            "--psiphon-config", overlay.absolutePath,
            "--psiphon-dir", psiphonDir().absolutePath,
            "--config", configFile().absolutePath,
            "--psiphon-bin", psiphon.absolutePath,
            "--stats",
        )
        if (mode.isNotBlank()) cmd += listOf("--psiphon-mode", mode)
        if (exitRegion.isNotBlank()) cmd += listOf("--psiphon-region", exitRegion.trim())

        LogBus.i(
            "AetherCore",
            "启动赛风专用模式（" + (if (upstreamPort > 0) "上游=127.0.0.1:$upstreamPort" else "纯直连") +
                "，mode=${mode.ifBlank { "auto" }}）：${cmd.joinToString(" ")}",
        )
        val pb = ProcessBuilder(cmd)
            .directory(coreDir())
            .redirectErrorStream(true)
        pb.environment()["HOME"] = coreDir().absolutePath
        pb.environment()["TMPDIR"] = context.cacheDir.absolutePath

        psiphonReady = false
        lastPsiphonLine = ""
        psiphonFatalHits = 0
        val p = pb.start()
        process = p
        running = true
        startLogThread(p)

        val readyPort = waitAnyPort(p, listOf(bindPort, 1819).distinct(), PSIPHON_WAIT_MS, "赛风出口")
        awaitPsiphonReady(p, readyWaitMs, healthCheck)
        LogBus.i(
            "AetherCore",
            "赛风专用模式就绪：端口 $readyPort，" +
                (if (upstreamPort > 0) "出站已经在我方隧道里" else "纯赛风直连（注册兜底出口）"),
        )
        return readyPort
    }

    /**
     * 纯赛风：不钉任何 upstream，赛风直连自己的服务器。
     *
     * 给「注册 WARP 身份」当兜底出口——api.cloudflareclient.com 被墙时，
     * 直接注册会 TLS 超时，就借赛风把注册请求发出去（DNS+TLS 都在赛风出口侧）。
     */
    fun startPsiphonStandalone(bindPort: Int): Int = startPsiphonOnly(0, bindPort, "")

    /**
     * 等核心把赛风真正拉起来（日志 "psiphon is ready"）。
     *
     * 超时就直接失败，而不是偷偷退回去走 WARP：用户打开赛风出口就是为了换掉
     * WARP 的落地 IP，静默降级等于「开关看着开了、出口还是 WARP」——那个坑踩过。
     */
    private fun awaitPsiphonReady(
        p: Process,
        timeoutMs: Long = PSIPHON_READY_WAIT_MS,
        healthCheck: (() -> Boolean)? = null,
    ) {
        val started = System.currentTimeMillis()
        var nextReport = 15_000L
        var nextHealth = 0L
        while (System.currentTimeMillis() - started < timeoutMs) {
            if (psiphonReady) {
                LogBus.i(
                    "AetherCore",
                    "赛风第二跳已就绪，tun 从现在起才切到赛风端口（等了 ${(System.currentTimeMillis() - started) / 1000}s）",
                )
                return
            }
            if (!runCatching { p.isAlive }.getOrDefault(false)) {
                val code = runCatching { p.exitValue() }.getOrNull()
                stop()
                throw IllegalStateException("Aether 核心进程已退出（code=$code），赛风第二跳没有起来。看日志里的 AetherCore 输出。")
            }
            // 上游隧道已经断了：再等也没有意义（赛风的每条 TCP 都从这条隧道出去）。
            // 每秒查一次就够，别让 IpcGet 跟着 200ms 的轮询一起跑。
            if (healthCheck != null && System.currentTimeMillis() >= nextHealth) {
                nextHealth = System.currentTimeMillis() + 1_000L
                if (!healthCheck()) {
                    stop()
                    throw IllegalStateException(
                        "上游隧道在赛风就绪前就断了（握手 / 回包停了），换端点重试。" +
                            "最后一行赛风日志：$lastPsiphonLine",
                    )
                }
            }
            // 上游彻底拨不出去：别再等满超时，直接判死换端点。
            // 给 6s 宽限，让赛风把服务器列表拉到、真正开始拨号之后再判。
            if (psiphonFatalHits >= PSIPHON_FATAL_HITS &&
                System.currentTimeMillis() - started > 6_000
            ) {
                stop()
                throw IllegalStateException(
                    "赛风的上游（隧道内 socks5）拨不出去：已出现 $psiphonFatalHits 条 " +
                        "connection refused / socks connect 失败。最后一行：$lastPsiphonLine",
                )
            }
            val elapsed = System.currentTimeMillis() - started
            if (elapsed >= nextReport) {
                nextReport += 15_000L
                LogBus.i("AetherCore", "赛风第二跳仍在建立，已 ${elapsed / 1000}s / ${timeoutMs / 1000}s")
            }
            Thread.sleep(200)
        }
        stop()
        throw IllegalStateException(
            "赛风第二跳在 ${timeoutMs / 1000}s 内没有就绪（端口已开，但核心还没把流量转进赛风）。" +
                lastPsiphonLine.takeIf { it.isNotBlank() }?.let { " 最后一行赛风日志：$it" }.orEmpty(),
        )
    }

    /**
     * 拆掉核心的子进程（psiphon）。
     *
     * `Process.toHandle()/descendants()` 是 Java 9 的 API，Android 上不是每个版本
     * 都有，编译期就解析不到，所以走反射：没有就跳过（老系统靠清锁文件兜底）。
     */
    private fun destroyChildren(p: Process) {
        runCatching {
            val handle = Process::class.java.getMethod("toHandle").invoke(p) ?: return@runCatching
            val stream = handle.javaClass.getMethod("descendants").invoke(handle) as? java.util.stream.Stream<*>
                ?: return@runCatching
            val kids = stream.iterator()
            var killed = 0
            while (kids.hasNext()) {
                val child = kids.next() ?: continue
                if (runCatching { child.javaClass.getMethod("destroy").invoke(child) }.isSuccess) killed++
            }
            if (killed > 0) LogBus.i("AetherCore", "已结束 $killed 个核心子进程（赛风）")
        }
    }

    /** 让系统挑一个空闲端口再放掉，交给核心去监听。 */
    private fun pickPort(): Int = java.net.ServerSocket(0).use { it.localPort }

    /** 赛风的状态目录：数据库/服务器列表放这儿，锁文件也在里面。 */
    private fun psiphonDir(): File = File(coreDir(), "psiphon").apply { mkdirs() }

    /**
     * 清掉上一轮残留的 psiphon 锁文件，**数据目录必须留着**。
     *
     * 电脑版踩过：被杀掉的 psiphon 会留下 BoltDB 的 .lock，下一次启动就会
     * `tryDatastoreOpenDB … timeout` → `psiphon stopped before it was ready`，
     * 从此每次带赛风的连接都失败。反过来把整个目录删掉也不行：冷启动要先去
     * S3 拉远程服务器列表，而这条路也是走隧道的，慢线路上直接超时。
     */
    private fun clearStalePsiphonLocks() {
        val locks = runCatching {
            psiphonDir().listFiles()?.filter { it.isFile && it.name.endsWith(".lock", ignoreCase = true) }
        }.getOrNull().orEmpty()
        var removed = 0
        locks.forEach { if (it.delete()) removed++ }
        if (removed > 0) LogBus.i("AetherCore", "清掉 $removed 个残留的 psiphon 锁文件（数据库保留）")
    }

    /**
     * 写赛风的 overlay 配置：把它的出站钉在我方 socks5 上，并把隧道协议收敛到
     * **只用 TCP 的那几个**。
     *
     * 为什么要收敛：psiphon 的 UpstreamProxyURL 只作用于 TCP（net.go 里 UDPDial
     * 根本不读它），而 QUIC-OSSH / FRONTED-MEEK-QUIC-* 这些是走 UDP 直连的 ——
     * 不排除掉，psiphon 可能挑中它们，于是整条赛风就绕开了隧道，变成了
     * 「开关开着、其实没走隧道」。这份列表和电脑版实测可用的那份一致。
     */
    private fun writePsiphonOverlay(upstreamPort: Int): File {
        val overlay = org.json.JSONObject()
        if (upstreamPort > 0) {
            // 隧道内第二跳：出站钉在隧道 socks 上，且只走认 upstream 的 TCP 类，
            // 否则赛风可能挑中 QUIC 类协议绕开隧道。
            overlay.put("UpstreamProxyURL", "socks5://127.0.0.1:$upstreamPort")
            overlay.put("LimitTunnelProtocols", org.json.JSONArray(TCP_ONLY_PSIPHON_PROTOCOLS))
        }
        // upstreamPort==0：纯赛风（注册兜底），不钉 upstream、不限协议，
        // 让赛风用全协议集直连自己的服务器——那才是它抗封锁的形态。
        val f = File(psiphonDir(), "psiphon-overlay.json")
        f.writeText(overlay.toString())
        LogBus.i(
            "AetherCore",
            if (upstreamPort > 0) {
                "赛风 overlay 已写入 ${f.absolutePath}：上游 socks5://127.0.0.1:$upstreamPort，协议限 ${TCP_ONLY_PSIPHON_PROTOCOLS.size} 个 TCP 类"
            } else {
                "赛风 overlay 已写入 ${f.absolutePath}：纯赛风直连（无 upstream、不限协议，注册兜底用）"
            },
        )
        return f
    }

    /**
     * 等这几个端口里**任意一个**开始监听，返回它。
     *
     * 为什么不是直接等指定端口：官方在 only 模式下有过「忽略 --bind、固定用 1819」
     * 的行为（电脑版 2.1.0 实测），2.3.0 的帮助写的是按 --bind。两种都兼容，
     * 才不会因为一个端口猜测把整条链路卡死 180s。
     */
    private fun waitAnyPort(p: Process, ports: List<Int>, timeoutMs: Long, what: String): Int {
        val started = System.currentTimeMillis()
        var nextReport = 15_000L
        while (System.currentTimeMillis() - started < timeoutMs) {
            ports.forEach { port ->
                val ok = runCatching {
                    Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300) }
                }.isSuccess
                if (ok) {
                    if (port != ports.first()) {
                        LogBus.w("AetherCore", "$what 实际监听 $port（不是请求的 ${ports.first()}），按实际端口接")
                    }
                    return port
                }
            }
            if (!runCatching { p.isAlive }.getOrDefault(false)) {
                val code = runCatching { p.exitValue() }.getOrNull()
                stop()
                throw IllegalStateException("Aether 核心进程已退出（code=$code），$what 没有起来。看日志里的 AetherCore 输出。")
            }
            val elapsed = System.currentTimeMillis() - started
            if (elapsed >= nextReport) {
                nextReport += 15_000L
                LogBus.i("AetherCore", "仍在等待 $what（${ports.joinToString { "127.0.0.1:$it" }}），已 ${elapsed / 1000}s / ${timeoutMs / 1000}s")
            }
            Thread.sleep(250)
        }
        stop()
        throw IllegalStateException("$what 在 ${timeoutMs / 1000}s 内没有监听 ${ports.joinToString()}。看日志里的 AetherCore 输出。")
    }

    private companion object {
        /** 随包发布的官方版本，只用于日志对齐。 */
        const val CORE_VERSION = "2.3.0"

        /** 隧道（含 MASQUE 扫描，官方预算 120s）。 */
        const val TUNNEL_WAIT_MS = 180_000L

        /** 隧道内第二跳的赛风（官方 AETHER_PSIPHON_READY_SECS 默认 180）。 */
        const val PSIPHON_WAIT_MS = 180_000L

        /** 端口开listening之后，还要等核心自己报「psiphon is ready」才算能用。 */
        const val PSIPHON_READY_WAIT_MS = 120_000L

        /**
         * auto 模式给多久。psiphon 能起来通常 10~20s 就报 ready，
         * 超过这个数基本就是这条路被掐了，赶紧换 cdn，别让用户干等 2 分钟。
         */
        const val PSIPHON_AUTO_WAIT_MS = 25_000L

        /** cdn 档的等待上限。原来错用了 120s，等于失败也要挂 2 分钟。 */
        const val PSIPHON_CDN_WAIT_MS = 25_000L

        /**
         * 出现多少条「上游拨不出去」（connection refused / socks connect 失败）
         * 就判定这条隧道的上游废了。给 3 条，避免把一次抖动当成故障。
         */
        const val PSIPHON_FATAL_HITS = 3

        /** MASQUE H3 选网关的耐心：正常 5~15s 就能通，超过这个数基本就是 QUIC 被限。 */
        const val H3_GATEWAY_WAIT_MS = 75_000L

        /**
         * 赛风里**只走 TCP、且认 UpstreamProxyURL** 的隧道协议。
         *
         * 顺序就是偏好顺序（psiphon 按列表顺序拨），所以把**快的排在前面**：
         *  - SHADOWSOCKS-OSSH / OSSH / TLS-OSSH 是纯 TCP 字节流，没有 HTTP 封装，
         *    同一条链路上能跑满带宽；
         *  - FRONTED-MEEK-* 是把数据塞进 HTTP 请求里的 meek，**每轮往返只能带
         *    有限数据**，实测就是 1~2Mbps —— 用户看到的「开赛风只剩一两兆」
         *    主要就是它造成的，所以全部排到最后。
         *
         * 之前这份列表是「内置 14 个去掉 3 个 QUIC」的原始顺序，meek 夹在中间，
         * 网络稍差就会先挑中 meek，于是速度被锁死在 1~2Mbps。
         *
         * ★ 2026-10-19 再去掉两个 CDN 变体（FRONTED-MEEK-CDN-OSSH /
         * FRONTED-MEEK-CDN-HTTP-OSSH），依据是对上游源码的比对：
         *  - 官方 psiphon-tunnel-core 的 SupportedTunnelProtocols 只有 13 个，
         *    **不含** FRONTED_MEEK_CDN / _HTTP_CDN / _QUIC_CDN 三个变体；
         *  - 随包 aether 用的 fork（CluvexStudio/psiphon-tunnel-core，分支
         *    shirokhorshid）是 16 个，把这三个保留了下来；
         *  - 也就是说官方已经判定 CDN 前置这一档不再可用，而它又是 meek 里
         *    最慢的一档（每往返一个载荷）。手机日志里出现的
         *    `meek read payload failed` 正是这一类在退让。
         * 这两个名字喂给官方二进制会直接被 Validate 拒绝
         * （invalid tunnel protocol），去掉它们同时也让我们将来能换成官方构建。
         */
        val TCP_ONLY_PSIPHON_PROTOCOLS = listOf(
            "SHADOWSOCKS-OSSH",
            "OSSH",
            "TLS-OSSH",
            "UNFRONTED-MEEK-HTTPS-OSSH",
            "UNFRONTED-MEEK-OSSH",
            "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
            "FRONTED-MEEK-OSSH",
            "SSH",
            "FRONTED-MEEK-HTTP-OSSH",
        )
    }
}
