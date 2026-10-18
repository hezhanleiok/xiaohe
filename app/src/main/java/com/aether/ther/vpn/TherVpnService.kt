package com.aether.ther.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.aether.ther.Hub
import com.aether.ther.MainActivity
import com.aether.ther.R
import com.aether.ther.core.AetherCore
import com.aether.ther.core.CoreEngine
import com.aether.ther.core.EngineConfig
import com.aether.ther.core.EngineEndpoint
import com.aether.ther.core.NativeCore
import com.aether.ther.data.CoreKind
import com.aether.ther.data.LogBus
import com.aether.ther.data.ProxyMode
import com.aether.ther.data.SettingsStore
import com.aether.ther.data.WireProtocol
import com.aether.ther.net.ExitInfo
import com.aether.ther.net.Latency
import com.aether.ther.net.LocalProxy
import com.aether.ther.net.NetInfo
import kotlin.concurrent.thread

/**
 * 会话的真正主人。
 *
 * 三种模式在这里分叉：
 *  - [ProxyMode.System]：**不**建立 VpnService，只把核心的本地 SOCKS 桥到
 *    127.0.0.1:7890，用户在 Wi-Fi 里手动填；
 *  - [ProxyMode.Vpn]：establish() 出 tun，按分应用白/黑名单把流量圈进隧道；
 *  - [ProxyMode.Tun]：establish() 出 tun 并整机接管，fd 直接交给原生核心。
 *
 * ★ 会话隔离（2026-10-17 重写）：每次连接都是一个 [Session]，它拥有自己的
 * engine / tun / 线程。旧会话的收尾**只能动自己那份资源**。
 *
 * 之前这里是一个共享的 `engine`/`tun`/`cancelled` 加「每次 start 就新起一个
 * connect 线程」。用户改一次设置就点一次连接，于是同时存在两条 connect 线程：
 * 旧线程卡在「等赛风就绪（最长 120s）」里，超时后走 teardown，把**新连接**的
 * 引擎和 tun 一起关掉。日志里的证据：22:47:35 新连接开始建隧道，22:47:48 旧
 * 线程超时打印「停止核心进程 / 原生核心已停止」，新连接当场死亡 —— 这就是
 * 「AWG + 赛风一直失败、之前明明能连」的真正原因。
 *
 * 失败口径：任何一步失败都落到 Hub.failed() + 日志，并立刻停止前台服务。
 * 不允许出现「界面已连接、状态栏没钥匙」这种假成功。
 */
class TherVpnService : VpnService() {

    /**
     * 一次连接尝试拥有的全部资源。
     *
     * 线程和资源都挂在会话上，而不是服务上：服务是单例，会话不是。旧会话即使
     * 晚了几十秒才超时，也只能关掉自己已经没人用的那份，碰不到新会话。
     */
    private class Session(val gen: Int) {
        @Volatile var cancelled = false

        @Volatile var engine: CoreEngine? = null

        @Volatile var tun: ParcelFileDescriptor? = null

        @Volatile var bridge: LocalProxy? = null

        /** 出口 socks 端口（赛风/Aether 出口用），0 表示没有。 */
        @Volatile var socksPort: Int = 0

        @Volatile var worker: Thread? = null

        @Volatile var health: Thread? = null

        @Volatile var latency: Thread? = null
    }

    companion object {
        const val ACTION_START = "com.aether.ther.action.START"
        const val ACTION_STOP = "com.aether.ther.action.STOP"
        const val EXTRA_MODE = "mode"

        private const val CHANNEL_ID = "ther_session"
        private const val NOTIFICATION_ID = 1001
        private const val LOCAL_PROXY_PORT = 7890

        /**
         * 一次连接最多试几个端点。
         *
         * 6 是用户实测可用的基线（0.1.5 就是「探活 → 8 个候选 → 试 6 个」）：
         * 这条线路上单个端点握上手的概率只有三成左右，6 个 ≈ 88%，
         * 少试一个就少一截成功率 —— 2026-10-17 那版只留 2 个兜底，
         * 结果就是 WG/AWG/GOOL 一起连不上。
         */
        private const val MAX_ENDPOINT_ATTEMPTS = 6

        /**
         * 多端点时每个端点等握手的预算。
         *
         * 必须盖住 wireguard-go 的**一次握手重传**：RekeyTimeout = 5s 加 ≤334ms
         * jitter，再留 RTT（这条线路 0.5~2s）。原来的 2.5s 假设「能通的话 300ms
         * 就回来了」，实测不成立——第一个包经常被丢，只有重传才有机会。
         */
        private const val ENDPOINT_BUDGET_MS = 7_000L

        /**
         * GOOL 单个端点的预算。外层握手完内层才能开始（引擎里外层最多等 6.5s、
         * 内层起好之后这里再等内层），所以比普通 WG 长。
         */
        private const val GOOL_ENDPOINT_BUDGET_MS = 8_000L

        /**
         * 握手之后的数据面自检预算（TCP 1.1.1.1:443）。
         * 一次往返而已，3s 已经足够；超时就认定这条端点「只会握手」。
         */
        private const val DATA_PLANE_CHECK_MS = 3_000

        /**
         * 断流看门狗的采样间隔。
         *
         * 6s 采样 + 下面的分级阈值，实际判据全部是「连续多少次采样没动静」，
         * 所以时间 = 次数 × 6s。
         */
        private const val HEALTH_INTERVAL_MS = 6_000L

        /**
         * ★ 断流分级（0.1.29）：不再「连续 12s 没数据就拆会话」。
         *
         * 2026-10-19 23:58 的日志把这条钉死了：
         *
         *   23:58:07.618 [Exit] 数据面不通（TCP 1.1.1.1:443，3006ms）
         *   23:58:15.968 [Core] Retrying handshake because we stopped hearing back after 15 seconds
         *   23:58:16.624 [Vpn]  隧道连续 12s 传不动数据，判定断流
         *   23:58:16.626 [Vpn]  自动重连 1/2（重新扫描节点）
         *
         * 引擎在 15s 时**自己开始重握手**（wireguard-go 的 expiredNewHandshake），
         * 而我们在 16.6s 就把整个会话拆了 —— 正好杀掉它唯一能自愈的那次重握手。
         * 拆完重来一遍是 28s（要重新注册/探活/预筛/建 tun），用户看到的就是
         * 「自动断开重连好几次」。
         *
         * 现在的三级阶梯（按**真实静默秒数**算，不是采样次数）：
         *  12s → 只记日志，让引擎自己的 15s 重握手先跑；
         *  18s → 引擎已经试过一次没成功 → **会话内换端点**（设备不重建、不重扫，
         *        换完主动握手，1~2s 见分晓）；
         *  36s → 换端点也救不回来，才整会话重扫。
         */
        private const val STALL_NOTICE_SEC = 12L
        private const val STALL_SWITCH_SEC = 18L
        private const val STALL_DEAD_SEC = 36L

        /** 一次断流里最多在会话内换几个端点，超过就整会话重扫。 */
        private const val MAX_SWITCHES_PER_STALL = 2

        /**
         * 两次「会话内换端点」之间至少隔多久。
         *
         * 换端点之后引擎会主动握手，1~2s 就有结果；但数据面恢复要再多一两秒。
         * 8s 的宽限就是让第一次换端点有机会证明自己，而不是连续换两个都不给时间。
         */
        private const val SWITCH_GRACE_MS = 8_000L

        /** 自动重连最多几次（防止「断流→重连→又断流」无限循环）。 */
        private const val MAX_AUTO_RETRIES = 2

        /**
         * ★ 端点全灭之后最多再来几轮（0.1.27，0.1.29 与 2 分钟预算对齐）。
         *
         * 以前候选试完就 `throw`，用户看到「连接失败」，只能手动再点一次连接 ——
         * 而手动再点一次做的事（重新扫描 + 重新真握手预筛）本来就该自动做。
         * 这条线路上「这一批端点突然全死」是常态（23:12 那次 GOOL 两个外层端点
         * 各试内层落点，17s 就全灭），所以必须自动换一批再来。
         *
         * 每一轮都是完整的「重新扫描 → 重新真握手预筛 → 换一批端点」，而不是
         * 把同一批端点再试一遍。
         */
        private const val MAX_CONNECT_ROUNDS = 4

        /**
         * 整次连接（含所有轮次）的总预算：**2 分钟**。
         *
         * 用户明确要求「时间要控制，不能超过 2 分钟」。原来的 5 分钟等于允许
         * 「扫 3 轮 × 每轮 26s」，用户只会觉得卡死。超过就不再开新一轮，直接把
         * 失败原因交出来；端点循环里也会按这个时间点提前收手（见 connect()）。
         */
        private const val CONNECT_TOTAL_BUDGET_MS = 120_000L

        fun start(context: Context, mode: ProxyMode) {
            val i = Intent(context, TherVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_MODE, mode.id)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(i)
            } else {
                context.startService(i)
            }
        }

        fun stop(context: Context) {
            context.startService(Intent(context, TherVpnService::class.java).apply {
                action = ACTION_STOP
            })
        }
    }

    /** 当前会话；null = 没有会话。所有 UI 更新都以它为准。 */
    @Volatile
    private var current: Session? = null

    private var genCounter = 0

    @Volatile
    private var autoRetries = 0

    /** 本次连接已经用掉几轮「重新扫描 + 重新预筛」（0 = 第一轮，见 MAX_CONNECT_ROUNDS）。 */
    @Volatile
    private var connectRounds = 0

    /** 本次连接开始的时间戳，用来卡 CONNECT_TOTAL_BUDGET_MS。 */
    @Volatile
    private var connectStartedAt = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                LogBus.i("Vpn", "收到停止指令")
                val s = current
                if (s != null) teardown(s) else stopSelf()
                return START_NOT_STICKY
            }

            ACTION_START -> {
                val mode = ProxyMode.byId(intent.getStringExtra(EXTRA_MODE))
                startForegroundCompat(buildNotification("正在连接…", "模式：${mode.title}"))
                autoRetries = 0
                connectRounds = 0
                connectStartedAt = System.currentTimeMillis()
                newSession(mode, auto = false)
                return START_NOT_STICKY
            }

            else -> {
                // 系统重启服务（没有 intent）时无法恢复原模式：直接收摊，别留半截状态。
                LogBus.w("Vpn", "服务被重新创建但没有指令，停止")
                current?.let { teardown(it) } ?: stopSelf()
                return START_NOT_STICKY
            }
        }
    }

    /**
     * 开一个新会话。旧会话先被完整收掉（它的引擎/赛风进程/tun 必须先释放，
     * 否则端口和 psiphon 的 BoltDB 锁会挡住新会话）。
     *
     * 注意分工：**标记取消**在这里同步做（主线程，很快）；**回收资源**放到新
     * 会话的工作线程里做（杀进程树、等 2s，可能阻塞，不能卡主线程）。
     */
    private fun newSession(mode: ProxyMode, auto: Boolean) {
        val s = Session(++genCounter)
        val prev = current
        current = s
        if (prev != null) {
            LogBus.i("Vpn", "开新会话 gen=${s.gen}${if (auto) "（自动重连）" else ""}，先收掉旧会话 gen=${prev.gen}")
            prev.cancelled = true
            prev.health?.interrupt()
            prev.latency?.interrupt()
        }
        s.worker = thread(name = "ther-connect-${s.gen}", isDaemon = true) {
            if (prev != null) reap(prev)
            connect(s, mode)
        }
    }

    /** 关掉一个会话持有的全部系统资源（可重复调用）。 */
    private fun reap(s: Session) {
        runCatching { s.bridge?.stop() }
        s.bridge = null
        runCatching { s.engine?.stop() }
        s.engine = null
        runCatching { s.tun?.close() }
        s.tun = null
    }

    /** 这个会话还是「当前会话」吗？所有 Hub 写入都要先过这一关。 */
    private fun live(s: Session): Boolean = !s.cancelled && current === s

    private fun connect(s: Session, mode: ProxyMode) {
        val settings = SettingsStore.load(this).normalized()
        val protocol = settings.protocol
        val coreKind = settings.core
        // 计时的起点：connectRounds == 0 表示这是「新的一次连接」（用户点的，或断流
        // 后自动重连的），预算从这里开始算；后面每自动重扫一轮只会加 connectRounds。
        if (connectRounds == 0) connectStartedAt = System.currentTimeMillis()
        // 赛风出口现在两种核心都支持，但拓扑不同：
        //  - Aether 核心：它自己就是「隧道内第二跳」（--psiphon）；
        //  - 原生核心：原生隧道先建在用户态协议栈上，赛风（--psiphon-only）
        //    把 upstream 指向隧道里的 socks5，最后 tun 接到赛风。
        val psiphonExit = settings.psiphonExit
        if (psiphonExit) {
            LogBus.i(
                "Vpn",
                "赛风出口：拓扑=" + if (coreKind == CoreKind.Aether) "Aether 核心第二跳" else "原生隧道内第二跳",
            )
        }
        // 启动时已经探到公网 IP；没有才退回内网地址，别把首页那行从公网换回 192.168。
        val localIp = Hub.state.value.localIp.ifBlank { NetInfo.localIpv4(this) }
        if (!live(s)) return
        Hub.connecting(protocol, coreKind, mode, localIp, "正在建立${protocol.title}隧道…")
        // 连接过程中进程如果消失，这个标记会留下来 —— 下次启动首页第一条就是
        // 「上次连接没有正常结束」，不用靠猜。
        LogBus.markSessionStart()
        LogBus.i(
            "Vpn",
            "开始连接 gen=${s.gen}：core=${coreKind.id} protocol=${protocol.id} mode=${mode.id} " +
                "psiphon=${settings.psiphonExit} region=${settings.exitRegion.ifBlank { "auto" }} " +
                "本机=$localIp 网络=${NetInfo.transport(this)}",
        )

        try {
            // 原生核心的实例必须在整次连接里**只有一个**：端点探测结果、要排除出
            // 隧道的 IP 都挂在实例上（以前是静态字段，两条并发连接会互相覆盖，
            // 结果就是「排除错了 IP → 加密包进 tun 打转」）。
            val nativeCore: NativeCore? = if (coreKind == CoreKind.Native) NativeCore(this) else null

            // 端点必须在 establish() **之前**定下来：存活探测是纯 UDP 直连，
            // tun 一建立，本进程的所有包都会被它接管，探测就没意义了。
            if (nativeCore != null) {
                if (!live(s)) return
                Hub.update { it.copy(message = "正在探测 WARP 端点（含真握手验证）…") }
                // nested：GOOL / 赛风出口这两条是「隧道里再套隧道」的路径，候选顺序
                // 与普通 WG/AWG 不同（探活优先、seed 殿后），见 prepareEndpoints。
                val nested = psiphonExit || protocol == WireProtocol.GOOL_NATIVE
                nativeCore.prepareEndpoints(protocol, nested)
            }
            if (!live(s)) return

            val fd: Int = if (mode == ProxyMode.System) {
                // 系统代理模式不碰 VpnService：没有任何 tun 设备。
                0
            } else {
                // 原生核心 + 赛风时本应用也必须整体排除：原生隧道的 UDP 和
                // psiphon 进程的出站都不能进 tun（它们要走物理网络/自己那条隧道）。
                val pfd = establishTun(
                    mode = mode,
                    mtu = settings.mtu,
                    ipv6 = settings.ipv6,
                    coreKind = coreKind,
                    endpointHosts = nativeCore?.endpointHosts().orEmpty(),
                    excludeSelf = coreKind == CoreKind.Aether || (coreKind == CoreKind.Native && psiphonExit),
                ) ?: error("无法建立 VPN 接口（可能未授权）")
                s.tun = pfd
                pfd.fd
            }

            if (!live(s)) {
                runCatching { s.tun?.close() }
                s.tun = null
                return
            }

            // 核心二进制随整包发布，连接时不再联网拉取——没有就是没有，直接报错。
            val core: CoreEngine = nativeCore ?: AetherCore(this)

            if (!core.isAvailable()) {
                throw IllegalStateException(core.unavailableReason())
            }
            s.engine = core

            val cfg = EngineConfig(
                core = coreKind,
                protocol = protocol,
                mode = mode,
                awgI1 = settings.awgI1,
                mtu = settings.mtu,
                ipv6 = settings.ipv6,
                dns = settings.dns,
                keepalive = settings.keepalive,
                psiphonExit = psiphonExit,
                exitRegion = settings.exitRegion,
                selfPackage = packageName,
            )

            // 原生核心：设备起来不等于隧道通了，必须等到**真实握手**才算连上。
            // 端点要逐个试：Cloudflare 的 WARP 有 2408/500/1701/4500 四个 UDP 端口，
            // 运营商经常只拦其中一个甚至换 IP 才通；实测 rxBytes=0 时不是密钥问题，
            // 而是包根本没回来。
            val endpoints: List<String?> =
                if (nativeCore != null && mode != ProxyMode.System) {
                    // 每个端点的代价不一样，按代价给上限（用户对「用时」很敏感）：
                    //  - 普通 WG/AWG：7s 握手 + 3s 数据面 ≈ 10s/端点 → 试满 6 个；
                    //  - GOOL：外层 6.5s + 数据面 4s + 内层探活 1.5s + 内层握手 8s
                    //    ≈ 20s/端点 → 3 个；
                    //  - 赛风出口：隧道 11s + 赛风（auto 25s + cdn 25s，隧道断了会提前判死）
                    //    → 3 个。
                    //
                    // ★ 候选现在都是**真握手预筛**过的（NativeCore.handshakeGate），
                    // 前几个就是刚刚握上的。真正的兜底不是「一轮多试几个」，而是
                    // 一轮全灭之后自动重扫再来一轮（见下面 !handshaken 分支）：
                    // 同一个端点连试两次没有意义，换一批新扫出来的才有。
                    val cap = when {
                        psiphonExit -> 3
                        protocol == WireProtocol.GOOL_NATIVE -> 3
                        else -> MAX_ENDPOINT_ATTEMPTS
                    }
                    nativeCore.candidates().take(cap)
                } else {
                    listOf(null)
                }
            if (nativeCore != null && mode != ProxyMode.System) {
                LogBus.i(
                    "Vpn",
                    "端点候选 ${endpoints.size} 个" +
                        if (connectRounds > 0) "（第 ${connectRounds + 1} 轮，已重新扫描）" else "" +
                        "：${endpoints.joinToString()}",
                )
            }

            var endpoint: EngineEndpoint? = null
            var attempt = 0
            var handshaken = false
            var lastStatus = ""
            // 本进程是否在隧道里：决定「数据面自检」怎么发（直连 vs 走 socks）。
            val appInTunnel = nativeCore != null && !psiphonExit

            // 原生 WG/AWG 全程只建一次设备：换端点只热替换 peer 的 endpoint。
            // 重建一次设备就换一个本地 UDP 源端口（新五元组），而 wireguard-go 的
            // 5s 握手重传只在同一条流上有效 —— 这条线路又恰好爱丢「新流的第一个
            // 包」，重建设备等于主动放弃唯一能救回来的那次重传。
            // GOOL 例外：外层设备封在 goolState 里、内层要重新挂，仍按端点重建。
            val hotSwap = nativeCore != null && protocol != WireProtocol.GOOL_NATIVE
            var deviceUp = false

            for (ep in endpoints) {
                if (!live(s)) return
                // ★ 2 分钟硬预算（0.1.29）：端点循环里也要卡，不能只在「开新一轮」
                // 之前卡。一个 GOOL 端点的最坏耗时是 6.5(外层)+4(数据面)+1.5(落点
                // 验活)+3×4.5(落点握手) ≈ 25s，试满 3 个就是 75s，光靠轮次判断
                // 会直接冲过 2 分钟。
                val spentNow = System.currentTimeMillis() - connectStartedAt
                if (spentNow > CONNECT_TOTAL_BUDGET_MS) {
                    LogBus.w(
                        "Vpn",
                        "已用 ${spentNow / 1000}s，超过 ${CONNECT_TOTAL_BUDGET_MS / 1000}s 预算，停止尝试剩余端点",
                    )
                    break
                }
                attempt++
                Hub.update {
                    it.copy(
                        message = when {
                            endpoints.size == 1 -> "已建立 tun，等待 WireGuard 握手…"
                            attempt == 1 -> "正在握手：$ep"
                            else -> "换端点重试 $attempt/${endpoints.size}：$ep"
                        },
                    )
                }
                if (hotSwap && deviceUp) {
                    val addr = ep ?: continue
                    // 切换失败不判死：还能换下一个端点。
                    try {
                        nativeCore!!.switchEndpoint(addr)
                    } catch (t: Throwable) {
                        lastStatus = t.message ?: "切换端点失败"
                        LogBus.w("Vpn", "端点 $addr 切换失败：${t.message}，换下一个")
                        continue
                    }
                } else {
                    // 启动失败（端点不通、赛风没起来、GOOL 外层没握手）不能直接
                    // 把整次连接判死：候选里还有别的端点，换一个再来。
                    endpoint = try {
                        core.start(cfg.copy(endpoint = ep), if (mode == ProxyMode.System) null else fd)
                    } catch (t: Throwable) {
                        lastStatus = t.message ?: "启动失败"
                        LogBus.w("Vpn", "端点 $ep 启动失败：${t.message}，换下一个")
                        runCatching { core.stop() }
                        continue
                    }
                    s.socksPort = endpoint?.socksPort ?: 0
                    deviceUp = true
                }

                if (nativeCore == null) {
                    handshaken = true
                    break
                }

                // 预算怎么定（2026-10-18 实测修正）：
                //  - 单端点（Aether / 未来其它核心）沿用 15s；
                //  - GOOL：外层握手完内层才可能通，给 8s；
                //  - 其它（原生 WG/AWG 多端点）：7s，盖住 wireguard-go 的一次重传
                //    （RekeyTimeout 5s + jitter ≤334ms + RTT ≤2s）。原来的 2.5s
                //    连第一次重传都等不到。
                val budget =
                    when {
                        endpoints.size == 1 -> 15_000L
                        protocol == WireProtocol.GOOL_NATIVE -> GOOL_ENDPOINT_BUDGET_MS
                        else -> ENDPOINT_BUDGET_MS
                    }
                val deadline = System.currentTimeMillis() + budget
                var hs = false
                while (System.currentTimeMillis() < deadline && live(s)) {
                    if (nativeCore.handshaken()) {
                        hs = true
                        break
                    }
                    Thread.sleep(250)
                }
                // 握手只是门票：必须再做一次真实 TCP 往返，才算「这条端点能用」。
                //
                // 但要用**带重试**的版本（电脑版 verifyDataPlane 同款）：握手刚完成
                // 的那一两秒路由/FIB 还没收敛，单次探测会把好端点判死，六个候选全被
                // 否掉，用户看到的就是「无法连接」。
                if (hs && appInTunnel && !ExitInfo.probeDataPlaneSettled()) {
                    lastStatus = nativeCore.status().toString()
                    LogBus.w("Vpn", "端点 $ep 握手成功但数据面不通，换下一个（$lastStatus）")
                    hs = false
                }
                if (hs) {
                    handshaken = true
                    break
                }
                lastStatus = nativeCore.status().toString()
                LogBus.w("Vpn", "端点 $ep 在 ${budget}ms 内没握手（$lastStatus），换下一个")
                if (!hotSwap) {
                    core.stop()
                    s.socksPort = 0
                }
            }

            if (!live(s)) return

            // 原生核心失败就报错，绝不自动换到 Aether 核心：用哪个核心是用户的选择，
            // 这里只负责把失败原因说清楚。
            if (!handshaken) {
                // ★ 端点用完 ≠ 连接失败（0.1.27）。
                //
                // 以前的写法是：候选 2~3 个试完就 throw，用户看到「连接失败」，
                // 只能手动再点一次连接。而手动再点一次做的正是「重新扫描 + 重新
                // 真握手预筛」—— 这件事本来就该自动做。这条线路上「这一批端点
                // 突然全死」是常态（23:12 那次 GOOL 两个外层端点各试内层落点，
                // 17s 就全灭；赛风路径也只剩 3 个端点）。
                //
                // 现在的做法：开一个新会话再来一轮。新会话的工作线程会先 reap 掉
                // 本会话（关 tun + 引擎），connect() 才会重新 prepareEndpoints ——
                // 扫描必须发生在 establish() 之前，tun 一建立探针就全进隧道了，
                // 所以「重扫」只能靠换会话，不能在本轮循环里做。
                val spent = System.currentTimeMillis() - connectStartedAt
                if (live(s) && connectRounds < MAX_CONNECT_ROUNDS && spent < CONNECT_TOTAL_BUDGET_MS) {
                    connectRounds++
                    // 只作废节点缓存（下一轮因此会重新扫描），**不记身份失败**：
                    // 身份轮换的口径是「用户点一次连接、失败一次」，中间自动重试的
                    // 轮次不该累加，否则一次连接就把 failStreak 顶到 2、下一次连接
                    // 直接注销重注册。
                    nativeCore?.invalidateCache()
                    LogBus.w(
                        "Vpn",
                        "第 $connectRounds/$MAX_CONNECT_ROUNDS 轮：$attempt 个端点全灭，重新扫描端点再来" +
                            "（已用 ${spent / 1000}s；上一轮最后失败：${lastStatus.take(160)}）",
                    )
                    Hub.update {
                        it.copy(message = "端点全灭，重新扫描后重试（第 $connectRounds/$MAX_CONNECT_ROUNDS 轮）…")
                    }
                    newSession(mode, auto = true)
                    return
                }
                // 真的放弃了才记账：连续两次全灭就换一份新 WARP 身份（见 NativeCore.identity）。
                //
                // 只在**真的试过端点**时才记这笔账。一个端点都没试（候选为空）说明
                // 是这条线路整体不通，跟身份没关系；把它算成「身份失败」会连着两次
                // 触发身份轮换——每次都要重新注册一个新账号，既解决不了问题，又让
                // 下一次连接卡在注册上。电脑版从不因为握手失败去换身份。
                if (attempt > 0) {
                    nativeCore?.noteConnectResult(false)
                    if (nativeCore != null && protocol == WireProtocol.GOOL_NATIVE) {
                        nativeCore.noteConnectResult(false, "warp-inner.json")
                    }
                }
                val screened = nativeCore?.screenNote().orEmpty()
                val roundNote = if (connectRounds > 0) {
                    "已试 ${connectRounds + 1} 轮（自动重扫 ${connectRounds} 次）、用时 ${spent / 1000}s"
                } else {
                    ""
                }
                val goolHint = if (protocol == WireProtocol.GOOL_NATIVE) {
                    "GOOL 的内层要穿过外层隧道落到 Cloudflare 自己的另一个边缘。" +
                        "本版会先用 0xcf 探针**在外层隧道里**验活内层落点，只拿真的回了包的落点去握手" +
                        "（见日志「内层落点隧道内验活」）；探针全灭时说明外层隧道不转发 UDP。"
                } else {
                    ""
                }
                throw IllegalStateException(
                    if (attempt == 0) {
                        "没有可用的端点候选（身份里没有端点，探活也没回包）。" +
                            "这条线路很可能整体拦了 WARP 的 UDP，换网络再试。"
                    } else {
                        (if (screened.isNotBlank()) "$screened。" else "") +
                            (if (roundNote.isNotBlank()) "$roundNote，" else "") +
                            "所有端点都没完成握手（最后一轮试了 $attempt 个）。" + goolHint +
                            "最后一次状态：$lastStatus"
                    },
                )
            }
            // 连上了：轮次计数归零，下一次（断流后的自动重连）又能用满额度。
            //
            // ★ 计时起点也要重置（0.1.29）：`connectStartedAt` 原本只在
            // connectRounds == 0 时重置，而连上之后 connectRounds 已经归零，
            // 于是「连上一小时后断流 → 自动重连」会带着一小时前的起点去卡 2 分钟
            // 预算，第一次判断就直接超时、连一轮都不给。断流后的重连是一次新的
            // 连接尝试，预算必须重新起算。
            connectRounds = 0
            connectStartedAt = System.currentTimeMillis()
            if (nativeCore != null) {
                nativeCore.noteConnectResult(true)
                if (protocol == WireProtocol.GOOL_NATIVE) {
                    nativeCore.noteConnectResult(true, "warp-inner.json")
                }
                LogBus.i("Vpn", "WireGuard 握手完成（第 $attempt/${endpoints.size} 个端点）")
            } else {
                LogBus.i("Vpn", "Aether 核心已就绪（扫描 + 端到端校验通过）")
            }

            if (mode == ProxyMode.System) {
                val socksPort = endpoint?.socksPort ?: 0
                s.bridge = LocalProxy(LOCAL_PROXY_PORT, socksPort).also { it.start() }
            }

            // 出口信息必须穿过隧道问，拿不到就保持本机 IP（不编造）。
            // 原生核心通常直连探测（tun 已接管）；但「原生 + 赛风」时本进程被排除
            // 在 tun 之外，直连探测量到的是本机地址，必须穿过赛风去问。
            // 5s 就够：这里只为了首页显示出口 IP，12s 默认值会把「正在连接」
            // 多拖十几秒（19:35 那次就白等了一次 12s 超时）。
            val probe = if (appInTunnel) {
                ExitInfo.probeDirect(timeoutMs = 5_000)
            } else {
                ExitInfo.probeThroughSocks(s.socksPort, timeoutMs = 5_000)
            }
            if (!live(s)) return
            // 探测失败不等于没有出口：核心在日志里报过的话，Hub 已经拿到了，
            // 这里不要再把首页打回「已连接但没有出口」的样子。
            val coreExit = Hub.state.value.exitIp
            // 注意：这里**不**把探测耗时当延迟。那是「一次完整 HTTP 请求」的时间
            // （DNS+TCP+请求+响应），穿隧道时 1~3 秒，首页显示「几千 ms」就是这么来的。
            // 真实 RTT 由 startLatencyLoop 单独量。
            if (probe != null) {
                Hub.connected(probe.ip, probe.country, -1, "已连接 · ${protocol.title}")
                notify(buildNotification("已连接 · ${probe.ip}", "${probe.country} · ${protocol.title} · ${mode.title}"))
            } else if (coreExit.isNotBlank()) {
                Hub.connected("", "", -1, "已连接 · $coreExit（核心上报）")
                notify(buildNotification("已连接 · $coreExit", "${protocol.title} · ${mode.title}"))
            } else {
                Hub.connected("", "", -1, "已连接（出口探测失败，见日志）")
                notify(buildNotification("已连接", "${protocol.title} · ${mode.title}"))
            }
            if (mode == ProxyMode.System) {
                LogBus.i("Vpn", "系统代理模式：请在 Wi-Fi 设置里填 代理=127.0.0.1 端口=$LOCAL_PROXY_PORT（SOCKS5）")
            }

            // 连上之后才开始量延迟 / 盯断流。
            startLatencyLoop(s, if (appInTunnel) 0 else s.socksPort)
            if (nativeCore != null) {
                // 把「会话内换端点」的游标移到当前端点的下一个：连接阶段试过并
                // 失败的那些不该在断流时再试一遍。
                nativeCore.armRecovery()
                startHealthLoop(s, nativeCore, mode, appInTunnel)
            }
        } catch (e: Throwable) {
            if (!live(s)) {
                LogBus.w("Vpn", "会话 gen=${s.gen} 已被新会话取代，忽略它的失败：${e.message}")
                return
            }
            LogBus.e("Vpn", "连接失败：${e.message}")
            Hub.failed(e.message ?: "连接失败")
            teardown(s, keepStatus = true)
        }
    }

    /**
     * 延迟采样：连上之后每 8s 量一次真实 RTT，写进首页。
     *
     * [socksPort] > 0 表示本应用被排除在 tun 之外（Psiphon / Aether 核心），
     * 只能经本地 SOCKS 量；否则直接 connect（流量在 tun 里，天然穿隧道）。
     */
    private fun startLatencyLoop(s: Session, socksPort: Int) {
        val t = thread(name = "latency-${s.gen}", isDaemon = true) {
            try {
                while (live(s)) {
                    val ms = if (socksPort > 0) Latency.throughSocks(socksPort) else Latency.direct()
                    if (!live(s)) break
                    if (ms > 0) {
                        Hub.latency(ms)
                        LogBus.d("Latency", "延迟 ${ms}ms（${if (socksPort > 0) "经 SOCKS 出口" else "穿隧道直连"}）")
                    }
                    Thread.sleep(if (ms > 0) 8_000L else 4_000L)
                }
            } catch (_: InterruptedException) {
                // 会话结束，正常退出
            } catch (t: Throwable) {
                LogBus.w("Latency", "延迟采样线程退出：${t.message}")
            }
        }
        s.latency = t
    }

    /**
     * 断流看门狗（0.1.29 重写为分级恢复）。
     *
     * 「已连接」只代表握手成功过，不代表现在还能传数据：这条线路上出现过
     * 「握手成功 + 出口探测也通，十几秒后整条隧道静默」的端点。
     *
     * 判据（两种，任一看得懂就用哪种）：
     *  - 本进程在隧道里（原生核心，非赛风）→ **主动探测**：每 6s 从隧道里
     *    TCP 连一次 1.1.1.1:443。比看字节数可靠 —— WARP 不一定回 keepalive，
     *    空闲隧道会被误判成断流。
     *  - 本进程在隧道外（带赛风）→ 看隧道自己的下行字节 + 握手时间戳。
     *
     * 判死之后**不立刻拆会话**，而是走三级阶梯（见 [STALL_NOTICE_SEC] /
     * [STALL_SWITCH_SEC] / [STALL_DEAD_SEC]）：
     *
     *  12s → 记日志，让 wireguard-go 自己的 15s 重握手先跑；
     *  18s → 会话内换端点（设备不重建、不重扫，换完主动握手，1~2s 见分晓）；
     *  36s → 换端点也救不回来，才整会话重扫。
     *
     * 为什么必须这样：2026-10-19 23:58:15.968 引擎刚开始重握手，16.624 我们就把
     * 会话拆了 —— 亲手杀掉了它唯一能自愈的那次机会，然后花 28s 重来一遍。
     */
    private fun startHealthLoop(s: Session, core: NativeCore, mode: ProxyMode, appInTunnel: Boolean) {
        val t = thread(name = "tunnel-health-${s.gen}", isDaemon = true) {
            try {
                var lastRx = -1L
                var lastHs = -1L
                // 用**墙钟**而不是采样次数计时：断流时每次主动探测自己还要烧 3s，
                // 按「6s × 次数」算会把 36s 的判死拖成 54s，日志里的秒数也会撒谎。
                var stallSince = 0L
                var lastSwitchAt = 0L
                var switches = 0
                var healthy = 0
                var noticed = false
                while (live(s)) {
                    Thread.sleep(HEALTH_INTERVAL_MS)
                    if (!live(s)) break
                    val st = runCatching { core.status() }.getOrNull() ?: continue
                    if (!st.optBoolean("running", false)) continue

                    // 新握手是一个独立的「活」信号：wireguard-go 自己重握手成功时，
                    // 数据面探测可能还要过一两秒才通，但 last_handshake_time 立刻就变。
                    val hs = if (st.has("lastHandshakeUnix")) st.optLong("lastHandshakeUnix", -1L) else -1L
                    val newHandshake = hs > 0 && lastHs > 0 && hs != lastHs
                    if (hs > 0) lastHs = hs

                    val dataOk = if (appInTunnel) {
                        // 2s 而不是 3s：健康的隧道这里 300~600ms 就回（日志里最长 1398ms），
                        // 而断流时这次探测自己也要占时间 —— 超时越长，判死越慢。
                        ExitInfo.probeDataPlane(2_000)
                    } else {
                        val rx = if (st.has("tunnelRxBytes")) {
                            st.optLong("tunnelRxBytes", -1L)
                        } else {
                            st.optLong("rxBytes", -1L)
                        }
                        val moved = rx >= 0 && (lastRx < 0 || rx != lastRx)
                        if (rx >= 0) lastRx = rx
                        moved
                    }

                    if (dataOk || newHandshake) {
                        if (stallSince > 0) {
                            LogBus.i(
                                "Vpn",
                                "隧道已恢复（${if (newHandshake) "引擎重握手成功" else "数据面重新通了"}，" +
                                    "静默了 ${(System.currentTimeMillis() - stallSince) / 1000}s）",
                            )
                        }
                        stallSince = 0
                        lastSwitchAt = 0L
                        switches = 0
                        noticed = false
                        healthy++
                        // 连续 60s 正常就把自动重连额度还回去：稳定过一次的连接
                        // 不该被很久以前的两次断流永久惩罚。
                        if (healthy == 10 && autoRetries > 0) {
                            autoRetries = 0
                            LogBus.i("Vpn", "隧道已稳定 60s，自动重连额度已恢复")
                        }
                        continue
                    }

                    healthy = 0
                    if (stallSince == 0L) {
                        // 这一次采样失败说明「刚过去的那 6s」也没通，往回补一个周期。
                        stallSince = System.currentTimeMillis() - HEALTH_INTERVAL_MS
                    }
                    val silentSec = (System.currentTimeMillis() - stallSince) / 1000

                    when {
                        silentSec >= STALL_DEAD_SEC -> {
                            LogBus.w(
                                "Vpn",
                                "隧道连续 ${silentSec}s 传不动数据（会话内已换过 $switches 个端点），判定断流",
                            )
                            // 这批节点刚被线路掐掉：作废缓存，下一轮重新扫描 + 重新验证。
                            core.noteConnectResult(false)
                            if (autoRetries < MAX_AUTO_RETRIES) {
                                autoRetries++
                                LogBus.w("Vpn", "自动重连 $autoRetries/$MAX_AUTO_RETRIES（重新扫描节点）")
                                newSession(mode, auto = true)
                            } else {
                                LogBus.e("Vpn", "自动重连次数已用完，判定失败")
                                Hub.failed("隧道反复断流（已重试 $MAX_AUTO_RETRIES 次）。这条线路对当前协议不稳定，换个网络或换协议。")
                                teardown(s, keepStatus = true)
                            }
                            return@thread
                        }

                        silentSec >= STALL_SWITCH_SEC && switches < MAX_SWITCHES_PER_STALL &&
                            System.currentTimeMillis() - lastSwitchAt >= SWITCH_GRACE_MS -> {
                            // 先把「这个端点不行」记下来：它撑不住，下一轮不该排前面。
                            val bad = core.currentEndpoint()
                            if (bad.isNotBlank()) core.markEndpointBad(bad)
                            val next = runCatching { core.recoverEndpoint() }.getOrNull()
                            switches++
                            lastSwitchAt = System.currentTimeMillis()
                            if (next != null) {
                                // ★ 注意：**不重置 stallSince**。判死的那 36s 是「从静默
                                // 开始算」的，换端点只是插进来的自救动作，不能把总时长
                                // 往后推 —— 否则两次换端点就能把 36s 拖成 60s 以上。
                                Hub.update { it.copy(message = "正在换端点恢复（$next）…") }
                                LogBus.w("Vpn", "隧道静默 ${silentSec}s，会话内换端点 → $next（不重扫，恢复更快）")
                            } else {
                                LogBus.w("Vpn", "隧道静默 ${silentSec}s，没有更多候选端点可换，直接判死重扫")
                                stallSince = System.currentTimeMillis() - STALL_DEAD_SEC * 1000L
                            }
                        }

                        silentSec >= STALL_NOTICE_SEC && !noticed -> {
                            noticed = true
                            LogBus.w(
                                "Vpn",
                                "隧道静默 ${silentSec}s —— 先让 wireguard-go 自己重握手" +
                                    "（它的判定是 15s），暂不拆会话",
                            )
                            // ★ 断流现场：把两层各自的收发计数都记下来（0.1.29）。
                            //
                            // 只有内层 rx 冻住时，分不清是「外层被掐」还是「内层落点
                            // 死了」—— 两者处置完全不同（换外层端点 vs 换内层落点）。
                            // 2026-10-19 23:58 那次就卡在这个判断上，日志里只有内层的
                            // userNet 计数，外层的完全是黑的。
                            LogBus.w(
                                "Vpn",
                                "断流现场：endpoint=${core.currentEndpoint()} " +
                                    "内层 rx=${st.optLong("tunnelRxBytes", -1L)} " +
                                    "tx=${st.optLong("tunnelTxBytes", -1L)} " +
                                    "hsAge=${st.optLong("hsAgeSec", -1L)}s " +
                                    "外层 rx=${st.optLong("outerRxBytes", -1L)} " +
                                    "tx=${st.optLong("outerTxBytes", -1L)} " +
                                    "outerHsAge=${st.optLong("outerHsAgeSec", -1L)}s",
                            )
                        }
                    }
                }
            } catch (_: InterruptedException) {
                // 会话结束
            } catch (t: Throwable) {
                LogBus.w("Vpn", "健康监测线程退出：${t.message}")
            }
        }
        s.health = t
    }

    /**
     * 建立 tun 设备。Vpn / Tun 的区别是路由与是否限定应用。
     *
     * [excludeSelf] 给 Aether 核心用：它是独立进程，出站 socket 必须绕过自己的
     * tun。Android 上没有 root 就用不了 fwmark，`VpnService.protect()` 又只对我们
     * 自己进程创建过的 fd 生效，所以只能把整个应用排除在隧道之外——否则 aether
     * 连上游的 TCP/UDP 会被自己的 tun 圈住，转一圈就没了。
     */
    private fun establishTun(
        mode: ProxyMode,
        mtu: Int,
        ipv6: Boolean,
        coreKind: CoreKind,
        endpointHosts: List<String>,
        excludeSelf: Boolean = false,
    ): ParcelFileDescriptor? {
        val settings = SettingsStore.load(this)
        val builder = Builder()
            .setSession("xiaohe")
            .setMtu(if (mtu > 0) mtu else 1280)
            .addAddress("10.7.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")

        // 把 WARP 端点排除出隧道：加密后的 UDP 包如果在 tun 里打转，隧道会自己
        // 把自己包住。Android 13 (API 33) 起有 excludeRoute；更低的版本需要
        // VpnService.protect(fd)，那条路要等 socket 由 Kotlin 侧建好再接进来。
        if (coreKind == CoreKind.Native) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                endpointHosts.forEach { ip ->
                    runCatching {
                        builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName(ip), 32))
                        LogBus.i("Vpn", "端点已排除出隧道：$ip/32")
                    }.onFailure { LogBus.w("Vpn", "排除端点 $ip 失败：${it.message}") }
                }
            } else {
                throw IllegalStateException(
                    "Android 13 以下需要 VpnService.protect 才能让原生核心的 UDP 不被自己的 tun 捕获，" +
                        "该实现尚未接入。请升级系统，或改用 Aether 核心。"
                )
            }
        }

        if (ipv6) {
            runCatching {
                builder.addAddress("fd00::2", 128)
                builder.addRoute("::", 0)
                builder.addDnsServer("2606:4700:4700::1111")
            }
        }

        // 只有「仅代理所选应用」这一种情况本身就把本应用排除在外；其余情况必须显式
        // 排除。注意判据必须是 perAppEnabled && Only —— perAppMode 的默认值就是
        // Only，只看枚举会把「没开分应用」误判成「仅代理所选」，于是跳过这一步，
        // 核心的出站流量被自己的 tun 圈住：注册云 API 的 DNS 直接进 tun 丢掉，
        // 表现为 api.cloudflareclient.com 解析失败、连接必挂（2026-10-17 实测）。
        val onlySelected = settings.perAppEnabled &&
            settings.perAppMode == com.aether.ther.data.PerAppMode.Only
        if (excludeSelf && !onlySelected) {
            runCatching {
                builder.addDisallowedApplication(packageName)
                LogBus.i("Vpn", "本应用已排除出隧道（Aether 核心的出站 socket 不能进 tun）")
            }.onFailure { LogBus.w("Vpn", "排除本应用失败：${it.message}") }
        } else if (excludeSelf) {
            LogBus.i("Vpn", "仅代理所选应用模式：本应用本来就在隧道外，核心出站不会绕圈")
        }
        if (settings.dns.isNotBlank()) {
            settings.dns.split(',', ' ', ';').filter { it.isNotBlank() }.forEach { d ->
                runCatching { builder.addDnsServer(d.trim()) }
            }
        }

        // 分应用：把自己排除掉，否则核心连自己的上游也会被圈进 tun 形成环路。
        if (settings.perAppEnabled && settings.perAppPackages.isNotEmpty()) {
            settings.perAppPackages
                .filter { it != packageName }
                .forEach { pkg ->
                    runCatching {
                        if (settings.perAppMode == com.aether.ther.data.PerAppMode.Only) {
                            builder.addAllowedApplication(pkg)
                        } else {
                            builder.addDisallowedApplication(pkg)
                        }
                    }.onFailure { LogBus.w("Vpn", "分应用设置失败：$pkg（${it.message}）") }
                }
            // 「仅代理所选」时本应用要能联网；但 Aether 核心是独立进程，把它拉进
            // 隧道就等于让核心的出站流量绕自己一圈，所以这里不给它开绿灯。
            if (settings.perAppMode == com.aether.ther.data.PerAppMode.Only && !excludeSelf) {
                runCatching { builder.addAllowedApplication(packageName) }
            }
        }

        LogBus.i("Vpn", "建立 tun：mode=${mode.id} mtu=${if (mtu > 0) mtu else 1280} ipv6=$ipv6 perApp=${settings.perAppEnabled}")
        return builder.establish()
    }

    /**
     * 收掉一个会话。只动它自己的资源；如果它已经不是当前会话，就只做资源回收，
     * 不碰界面、不关前台服务（新会话还要用）。
     *
     * 资源回收放在后台线程：`CoreEngine.stop()` 要杀 psiphon 进程树并等最多 2s，
     * 在主线程上做会直接 ANR。
     */
    private fun teardown(s: Session, keepStatus: Boolean = false) {
        s.cancelled = true
        s.health?.interrupt()
        s.health = null
        s.latency?.interrupt()
        s.latency = null

        val wasCurrent = current === s
        if (wasCurrent) current = null
        thread(name = "reap-${s.gen}", isDaemon = true) { reap(s) }

        if (!wasCurrent) {
            LogBus.i("Vpn", "旧会话 gen=${s.gen} 已回收（当前会话不受影响）")
            return
        }
        LogBus.markSessionEnd()
        if (!keepStatus) {
            Hub.idle()
            // 隧道没了，首页那两行要还原成「本机」，而不是留着上次的出口值。
            NetInfo.refreshLocalIdentity(this)
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        LogBus.i("Vpn", "会话已结束")
    }

    override fun onRevoke() {
        LogBus.w("Vpn", "VPN 权限被系统或其它应用收回，停止连接")
        current?.let { teardown(it) } ?: stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        current?.let { teardown(it) }
        super.onDestroy()
    }

    // ---- 通知 ----

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notify(notification: Notification) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, notification)
    }

    private fun buildNotification(title: String, text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "连接状态", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "彼岸的连接状态与会话通知"
                    setShowBadge(false)
                }
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, TherVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, "断开", stopIntent).build())
            .build()
    }
}
