package com.aether.ther.core

import android.content.Context
import com.aether.ther.data.LogBus
import com.aether.ther.data.WireProtocol
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress

/**
 * 原生核心：wireguard-go 直接读写 VpnService 给的 tun 设备。
 *
 * 与电脑版 `internal/wgtun` 同源：同一份 wireguard-go（带 AWG junk 补丁）、
 * 同一套 UAPI 配置（jc/jmin/jmax/i1）、同样的 MTU/keepalive 语义。差别只在
 * 设备来源——桌面用 wintun 驱动，这边用 VpnService 的 tun fd。
 *
 * 身份（私钥/对端公钥/接口地址）由 Go 引擎向 Cloudflare 注册 WARP 账号得到，
 * 首次连接注册一次，之后缓存在 files/warp.json。
 */
class NativeCore(private val context: Context) : CoreEngine {

    override val id = "native"
    override val displayName = "原生核心"
    override val provider = "wireguard-go + AWG junk · 内置"

    @Volatile
    private var core: engine.Engine_? = null

    @Volatile
    private var pump: Thread? = null

    /** 「原生核心 + 赛风」时借来跑赛风的 Aether 核心实例（psiphon-only）。 */
    @Volatile
    private var psiphonCore: AetherCore? = null

    companion object {
        /**
         * 单次存活探测的超时（ms）。活着的端点 100~200ms 就回了，700ms 足够；
         * 引擎侧到点会按剩余预算再钳一次，所以这里给的是上限。
         */
        private const val PROBE_TIMEOUT_MS = 700L

        /**
         * 第一级扫描的样本量：**小、快**。
         *
         * 引擎侧现在按「标准端口优先」三级扫描（240 → 960 → 高位端口 1200），
         * 每级都有自己的判断，不需要 Kotlin 再补一次「全池 3810 个」——
         * 那一轮在手机上要 23~28s，是 2026-10-19 23:58 那次 gen=2 卡了 23.5s 的
         * 唯一原因（小样本恰好全死 → 退回全池）。
         */
        private const val PROBE_LIMIT_FIRST = 240

        /**
         * 整轮探活的 wall-clock 预算。
         *
         * 三级加起来最多这么多；到点引擎立刻用已有结果返回。这是「首连时间可控」
         * 的硬约束：以前没有任何上限，最坏 28s 全花在探活上。
         */
        private const val PROBE_BUDGET_MS = 8_000L

        /** 一轮验证最多几个候选（并行度 = [VERIFY_WORKERS]）。 */
        private const val VERIFY_BATCH = 12
        private const val VERIFY_WORKERS = 12L

        /**
         * 单个候选的握手验证预算：盖住 wireguard-go 的一次重传（RekeyTimeout 5s）
         * 加 RTT。能通的端点 0.4~1.4s 就回了。
         */
        private const val VERIFY_TIMEOUT_MS = 7_000L

        /**
         * ★ 验证必须带 keepalive：验证用的是「丢弃一切包」的假 tun，而 wireguard-go
         * 只在「有包要发」时才发握手；没有 keepalive 就一个 initiation 都发不出去，
         * 验证结果恒为 0（0.1.17 全协议连不上的根因，实测 keepalive=0 → 发起=0）。
         */
        private const val VERIFY_KEEPALIVE = 5

        /** 验证通过的节点缓存多久。超过就重扫，避免拿隔夜的死节点去连。 */
        private const val NODE_CACHE_TTL_MS = 15 * 60 * 1000L

        /** 本次连接最多带几个已验证节点去试（都是验过的，试起来成功率高）。 */
        private const val MAX_ENDPOINT_CANDIDATES = 6

        /**
         * 「连上没多久就断」的端点记多久。
         *
         * 用户的原话是「保证端点质量，不能连接上几秒钟就断开」。探针和真握手都
         * 只能证明「这一刻能握上」，证明不了「能撑住」；能撑住的证据只有一个 ——
         * 它撑住过。反过来，撑不住的证据也只有一个 —— 它断过。所以这里把断过的
         * 端点记下来，下一轮排序时排到最后（**不删**：线路状态会变，30 分钟后
         * 重新有机会）。
         */
        private const val BAD_ENDPOINT_TTL_MS = 30 * 60 * 1000L

        /**
         * 连续多少次「所有端点都没握上手」就换一份新 WARP 身份。
         *
         * 依据：这份手机上，老身份连续两小时（11:19~13:46）怎么试都是 rx=0，
         * 卸载重装后拿到的**新身份**第一次就 1 秒握手成功。
         * 阈值取 2，且两次轮换之间至少隔 [IDENTITY_ROTATE_COOLDOWN_MS]：
         * 2026-10-18 17:58 的日志里一分钟内连换两次身份（每次都要注册），既没用
         * 又在刷账号。
         */
        private const val IDENTITY_ROTATE_AFTER = 2
        private const val IDENTITY_ROTATE_COOLDOWN_MS = 10 * 60 * 1000L

        /**
         * 嵌套/中继隧道的 keepalive。
         *
         * 必须 ≤10s：wireguard-go 的「听不到回应」判定是 10s+5s=15s，keepalive
         * 比它长就意味着**隧道一空闲必然触发一次重握手**。这条线路上重握手经常
         * 失败，表现就是「连上几十秒后突然全打不开」。引擎侧也会做同样的钳制。
         */
        private const val NESTED_KEEPALIVE = 10

        /**
         * GOOL 外层的 keepalive。
         *
         * 官方核心 `run_warp_in_warp` 建外层时用的就是 5s（内层 20s）。外层要一直
         * 替内层扛着 NAT 映射和边缘会话，越热越不容易被清掉；而外层一旦被清，
         * 内层的握手包就再也出不去（日志里的表现正是「外层握手成功、内层零回包」）。
         */
        private const val GOOL_OUTER_KEEPALIVE = 5

        /**
         * 近期「连上没多久就断」的端点 → 记录时间（进程内，跨会话共享）。
         *
         * 为什么放 companion：一次「断流 → 重连」会新建一个 [NativeCore] 实例，
         * 实例级字段活不过那次重连，而「这个端点上次只撑了 10 秒」这条信息恰恰
         * 是下一轮最需要的。
         */
        private val badEndpoints = HashMap<String, Long>()
    }

    /**
     * 端点解析结果（实例级，不再用 companion 静态字段）。
     *
     * 以前这里是 static：两条并发连接会互相覆盖「要排除出隧道的 IP」和「握手
     * 候选」，结果加密包可能被自己的 tun 圈住。现在一次连接只用一个实例。
     */
    @Volatile
    private var pinnedIp: String = ""

    /** [prepareEndpoints] 算好的端点候选，给 [start] 逐个试。 */
    @Volatile
    private var candidateEndpoints: List<String> = emptyList()

    /**
     * [prepareEndpoints] 里**真握手通过**的端点（按握手耗时升序）。
     *
     * 和 [candidateEndpoints] 的区别：候选只是「可以试」，这个是「刚刚真的握上了」。
     * GOOL 的内层落点必须从这里挑 —— 内层落在「探针通、握手不回」的边缘上时，
     * 外层全好、内层零回包，用户看到的就是「GOOL 连不上」。
     */
    @Volatile
    private var verifiedEndpoints: List<String> = emptyList()

    /** 候选端点的 IP，全部要 excludeRoute 掉（否则加密包会进隧道打转）。 */
    @Volatile
    private var excludeIps: List<String> = emptyList()

    /** GOOL 内层端点（establish 之前解析成字面 IP；tun 起来后解析必失败）。 */
    @Volatile
    private var innerEndpointLiteral: String = ""

    /**
     * 当前真正在用的端点（外层端点，GOOL 时是外层）。
     *
     * 断流时要用它来回答两个问题：「是不是刚换过的那个又死了」、
     * 「换端点要跳过谁」。引擎里的 `status().optString("endpoint")` 也能拿到，
     * 但那是跨 JNI 的一次调用，看门狗每 6s 都要用，不如本地存一份。
     */
    @Volatile
    private var activeEndpoint: String = ""

    /** [recoverEndpoint] 的游标：本会话已经换到第几个候选了。 */
    @Volatile
    private var switchCursor: Int = 0

    /** 预筛的结论，失败时报给用户，别让人以为是密钥问题。 */
    @Volatile
    private var screenNote: String = ""

    /**
     * 本实例已被 [stop] 作废。
     *
     * 为什么需要：一次启动里最长的步骤是「等握手 / 等赛风就绪」，可能几十秒。
     * 这期间用户又点了连接，新会话会先 [stop] 旧实例——但旧实例的 [core] 字段
     * 还没赋值，stop 什么也停不掉，等旧启动走完就把引擎和赛风进程**留在了后台**：
     * 赛风会一直占着 BoltDB 锁和端口，下一次带赛风的连接就起不来。
     * 所以每个耗时步骤之后都要用 [ensureAlive] 检查一次。
     */
    @Volatile
    private var closing = false

    private fun ensureAlive() {
        if (closing) throw IllegalStateException("连接已被新的会话取代")
    }

    override fun isAvailable(): Boolean = true

    override fun unavailableReason(): String = ""

    /** 已缓存的 WARP 身份；没有就现注册一份（直连失败会自动借赛风当出口重试）。 */
    fun identity(fileName: String = "warp.json"): JSONObject {
        val f = File(context.filesDir, fileName)
        // 连续失败太多次：这份身份在边缘节点那边大概率已经废了（症状是探针全通、
        // 握手全 rx=0）。先注销再注册，别拿死身份一遍遍试。
        //
        // 但要有冷却：17:58 的日志里一分钟内连换了两次身份（每次都要注册一个新
        // 账号），既解决不了问题，又在刷 Cloudflare 的注册接口。
        if (f.isFile && failStreak(fileName) >= IDENTITY_ROTATE_AFTER) {
            val lastRotate = runCatching { File(context.filesDir, "$fileName.rotated").readText().trim().toLong() }
                .getOrDefault(0L)
            val since = System.currentTimeMillis() - lastRotate
            if (since < IDENTITY_ROTATE_COOLDOWN_MS) {
                LogBus.w(
                    "NativeCore",
                    "连续 ${failStreak(fileName)} 次没握上手，但 ${since / 1000}s 前刚换过身份，" +
                        "这次先不换（避免刷注册）",
                )
                setFailStreak(fileName, 0)
            } else {
                LogBus.w(
                    "NativeCore",
                    "连续 ${failStreak(fileName)} 次连接没握上手，轮换 WARP 身份（$fileName）",
                )
                runCatching { f.delete() }
                runCatching { File(context.filesDir, "$fileName.rotated").writeText(System.currentTimeMillis().toString()) }
                setFailStreak(fileName, 0)
            }
        }
        if (f.isFile) {
            runCatching {
                val o = JSONObject(f.readText())
                if (o.optString("privateKey").isNotBlank() && o.optString("peerPublicKey").isNotBlank()) {
                    return o
                }
            }.onFailure { LogBus.w("NativeCore", "$fileName 解析失败，重新注册：${it.message}") }
        }
        LogBus.i("NativeCore", "本地没有 WARP 身份（$fileName），向 Cloudflare 注册一份")
        val created = try {
            provisionDirect()
        } catch (t: Throwable) {
            // api.cloudflareclient.com 在很多网络被 TLS 阻断，直接注册就是
            // "TLS handshake timeout"。别在这儿就判死：借赛风当出口再试一次。
            LogBus.w("NativeCore", "直连注册失败（${t.message}），改用赛风出口重试")
            provisionOverPsiphon()
        }
        f.writeText(created)
        LogBus.i("NativeCore", "WARP 身份已保存：${f.absolutePath}")
        return JSONObject(created)
    }

    /** 直连 Cloudflare 注册一份 WARP 身份。 */
    private fun provisionDirect(): String = runBlocking {
        runCatching { engine.Engine_().provisionWARP() }
    }.getOrElse {
        throw IllegalStateException("注册请求失败：${it.message}")
    }

    /** 借赛风（纯模式，直连它自己的服务器）当出口，重新注册一份 WARP 身份。 */
    private fun provisionOverPsiphon(): String {
        val ps = AetherCore(context)
        val port = try {
            ps.startPsiphonStandalone(pickPort())
        } catch (t: Throwable) {
            throw IllegalStateException("注册兜底也失败：赛风没起来（${t.message}）")
        }
        return try {
            runBlocking {
                runCatching { engine.Engine_().provisionWARPOverSocks("127.0.0.1:$port") }
            }.getOrElse {
                throw IllegalStateException("经赛风注册失败：${it.message}")
            }
        } finally {
            runCatching { ps.stop() }
        }
    }

    /**
     * GOOL 的**内层**身份：一份独立的 WARP 注册。
     *
     * 不能和 [identity] 共用：共用一个账号等于两层隧道落在同一个设备上，
     * 出口地址不会变，GOOL 就白做了。
     */
    fun innerIdentity(): JSONObject = identity("warp-inner.json")

    // ------------------------------------------------------------------
    // 身份健康度（连续失败计数 → 轮换身份）
    // ------------------------------------------------------------------

    private fun failFile(fileName: String) = File(context.filesDir, "$fileName.fail")

    private fun failStreak(fileName: String): Int =
        runCatching { failFile(fileName).readText().trim().toInt() }.getOrDefault(0)

    private fun setFailStreak(fileName: String, n: Int) {
        runCatching { failFile(fileName).writeText(n.toString()) }
    }

    /**
     * 一次连接的结果记账：握上手就清零，全部端点失败就累加。
     *
     * 累到 [IDENTITY_ROTATE_AFTER] 次，下次 [identity] 会注销旧身份重新注册。
     * 这不是「重试阶梯」：连接流程一点没变长，只是把一份可能已经失效的账号换掉。
     */
    fun noteConnectResult(handshaken: Boolean, fileName: String = "warp.json") {
        if (handshaken) {
            if (failStreak(fileName) != 0) setFailStreak(fileName, 0)
            return
        }
        // 缓存里的节点在刚才那一次会话里没扛住 → 直接作废，下次重新扫描验证。
        // 「只缓存可用节点」的前提是：不可用的要立刻被踢出去。
        clearVerified()
        val n = failStreak(fileName) + 1
        setFailStreak(fileName, n)
        if (n >= IDENTITY_ROTATE_AFTER) {
            LogBus.w("NativeCore", "已连续 $n 次连接没握上手：下次连接会换一份新 WARP 身份")
        }
    }

    /**
     * 连接前准备端点（2026-10-18 重写）：
     * **扫描 → 真握手验证 → 只把验过的节点写入缓存 → 只用缓存/验过的节点**。
     *
     * 旧逻辑的错误（用户指出的）：0xcf 探针只能证明「这个 IP:端口 有 UDP 回包」，
     * 它跟握手、跟账号毫无关系。把「探活通」当成「节点可用」，等于拿着 8 个
     * 不知道能不能用的地址去逐个硬试；线路一掐，就是 6×7s 全灭，用户还得重来。
     *
     * 新逻辑（每步都写日志，日志里能一路追下来）：
     *  1. 有缓存（只可能来自上一轮**真握手验过**的节点，且 15 分钟内）→ 直接用，
     *     不做扫描（第二次连接因此是秒开）；
     *  2. 没缓存 → 第一轮小样本快速扫描（[PROBE_LIMIT_FIRST] 个地址，700ms 超时）
     *     → 对探到的节点**并行做真握手**（与真实会话同样的配置：AWG 带 junk/i1，
     *     keepalive 必带）→ 只留真的握上手的；
     *  3. 一个都没验过 → 引擎侧会自己扩大样本（标准端口 240 → 960 → 高位端口
     *     1200），整轮受 [PROBE_BUDGET_MS] 约束；
     *  4. 仍然没有 → 明确失败（「扫了 N 个地址，没有一个能完成握手」），
     *     **绝不回退到没验证过的地址**；
     *  5. 验过的写入缓存，下次连接直接复用；连接失败会清掉缓存（见 [noteConnectResult]）。
     *
     * 必须在 establish() 之前调用 —— tun 一建立，本进程的所有 UDP/DNS 都被它
     * 接管，扫描和验证就没法直连发出去了。
     */
    fun prepareEndpoints(protocol: WireProtocol? = null, nested: Boolean = false): List<String> {
        val id = identity()
        var registeredInnerEndpoint = ""
        if (protocol == WireProtocol.GOOL_NATIVE) {
            // 内层身份要在 establish() 之前准备好：注册要走 HTTPS，
            // 而 tun 一建立，本进程的 DNS 就进了隧道（那时还没有握手可用）。
            val inner = innerIdentity()
            registeredInnerEndpoint = endpointLiteral(inner.optString("endpoint"))
            innerEndpointLiteral = registeredInnerEndpoint
        }

        screenNote = ""
        // ★ 候选列表与电脑版 internal/wgtun 的 buildCandidates 保持同一个结构：
        //   seed（身份里登记的端点）→ 探活到的端点 → 缓存。
        //
        // seed 必须永远在里面。以前这里只放「探活结果」，探活一个都没回就直接
        // 返回空列表、上层随即报「扫了 N 个地址一个都没回包」——可是 WARP 的
        // 0xcf 存活探针和「这条线能不能跑 WireGuard」是两件事：探针被丢、握手
        // 却能通的网络真实存在。电脑版从不会因为探活为空就拒绝连接，它一定先
        // 拿 seed 去握一次手，握不上再扫全池。这里照做。
        val seed = endpointLiteral(id.optString("endpoint"))
        val cached = loadVerified(protocol)
        var live: List<String> = emptyList()
        // 嵌套路径（GOOL / 赛风出口）永远重扫一次：它们对外层的要求是「握手 + 真转发」，
        // 缓存里那批只能证明当时探活通过，而这类路径每个端点要烧 10s 以上，拿旧缓存
        // 逐个试的代价比扫一遍探针（≈2s）高得多。
        if (cached.isEmpty() || nested) {
            // 冷路径才扫。电脑版的热路径（有缓存/seed）同样**不做 UDP 扫描**：
            // 每次连接都撒一遍探针，既慢又在给这条线路增加可被识别的流量特征。
            //
            // 分级（标准端口优先 → 扩大样本 → 高位端口兜底）和 wall-clock 预算都在
            // 引擎里（ProbeEndpoints），这里只给一个总预算。以前这里还有一条
            // 「小样本为空就扫全池 3810 个」的兜底，在手机上要 23~28s ——
            // 2026-10-19 23:58 那次 gen=2 的 23.5s 全部花在这条兜底上。
            live = probeLive(PROBE_LIMIT_FIRST, PROBE_BUDGET_MS)
        }
        if (live.isEmpty() && cached.isEmpty()) {
            screenNote = "Cloudflare 边缘地址一个都没有回探针"
            LogBus.w("NativeCore", screenNote + "；仍会用 seed 端点试一次握手")
        }

        val ordered = LinkedHashSet<String>()
        if (nested) {
            // ★ 嵌套隧道把探活结果排前面、seed 殿后。
            //
            // 电脑版的 seed 是 aether.toml 里**这个账号被分配到的**端点；我们这边
            // seed 只是 engage.cloudflareclient.com 这个通用入口。这条线路上它
            // 恰恰最容易被拦：握手能回、数据却不转发（外层 6.5s 握手 + 4s 数据面
            // 全白烧），而 GOOL/赛风每个端点只给 2~3 次机会，第一发打在它身上
            // 基本等于把整次连接送掉。探活到的边缘是刚用 0xcf 探针确认过活的，
            // 排在前面才有意义。
            live.forEach { ordered += it }
            cached.forEach { ordered += it }
            if (seed.isNotBlank()) ordered += seed
        } else {
            if (seed.isNotBlank()) ordered += seed
            live.forEach { ordered += it }
            cached.forEach { ordered += it }
        }
        // ★ 近期断过的端点排到最后（0.1.29）。
        //
        // 用户的原话：「保证端点质量，不能连接上几秒就断开」。探针通、真握手过，
        // 都只能证明「这一刻能握上」；能撑住的唯一证据是它撑住过。反过来也成立：
        // 断过的端点，下一轮不该再排到第一个去浪费一个候选位。
        // 注意只是**降序**，不是删除 —— 线路状态会变，30 分钟后重新有机会。
        val pool = reorderByHealth(ordered.toList())
        // ★ 真握手闸门（0.1.26）：探针通 ≠ 能握手。
        //
        // 2026-10-18 22:46~22:52 的真机日志把这条线钉死了：162.159.192.1:2408 和
        // 整个 162.159.193.x 段探针都回（165~203ms），握手 0/6 全灭；而 8.x 段的
        // 8.39.214.201:3854 / 8.39.214.53:8886 / 8.6.112.247:1180 / 8.39.214.103:7559
        // 全部 0.26~0.35s 握手成功。探活排序只看 RTT，而 RTT 全挤在 165~203ms 之间，
        // 等于随机 —— 每次连接都有一半概率把有限的机会全砸在死段上。
        //
        // 用户报的三件事其实是同一件事：AWG+赛风第一次失败（候选 2 个都是 193.x）、
        // 第二次 WG/AWG 都失败（又是 193.x）、GOOL 内层零回包（内层落点 193.238）。
        verifiedEndpoints = handshakeGate(protocol, nested, pool.take(VERIFY_BATCH))

        val finalOrder = LinkedHashSet<String>()
        verifiedEndpoints.forEach { finalOrder += it }
        pool.forEach { finalOrder += it }
        candidateEndpoints = finalOrder.take(MAX_ENDPOINT_CANDIDATES)

        // 缓存只累积，不用这一轮的结果把旧条目冲掉（电脑版 recordProbed 同理）。
        // 有验过的就只缓存验过的：下一轮拿它当 seed，第二次连接才能秒开。
        if (verifiedEndpoints.isNotEmpty()) {
            saveVerified(protocol, (verifiedEndpoints + cached).distinct())
        } else if (live.isNotEmpty()) {
            saveVerified(protocol, (live + cached).distinct())
        }

        LogBus.i(
            "NativeCore",
            "端点候选 ${candidateEndpoints.size} 个（${if (nested) "嵌套：探活优先" else "seed 优先"}，" +
                "seed=${seed.ifBlank { "无" }}，探活 ${live.size}，缓存 ${cached.size}，" +
                "真握手 ${verifiedEndpoints.size}）：" + candidateEndpoints.joinToString(),
        )
        if (protocol == WireProtocol.GOOL_NATIVE) {
            // 内层端点必须在 establish() 之前就定下来（tun 一起，DNS 就进隧道了），
            // 这里先算一个默认值；每次真正启动时 goolInnerConfig 会按当时的外层重算。
            val outerIp = candidateEndpoints.firstOrNull()?.substringBeforeLast(':')
            innerEndpointLiteral = pickInnerEndpoint(outerIp) ?: registeredInnerEndpoint
            LogBus.i(
                "NativeCore",
                "GOOL 内层端点候选：$innerEndpointLiteral（外层 $outerIp，" +
                    if (innerEndpointLiteral == registeredInnerEndpoint) "注册默认入口" else "扫描到的另一个边缘" +
                    "）",
            )
        }
        // 只排除字面 IPv4：seed 在 DNS 解析失败时会退回域名，域名塞进
        // excludeRoute 只会让建接口失败。
        excludeIps = candidateEndpoints
            .map { it.substringBeforeLast(':') }
            .filter { it.matches(Regex("^[0-9.]+$")) }
            .distinct()
        return candidateEndpoints
    }

    /**
     * ★ 真握手闸门：拿**真实会话的同一份配置**（同样的私钥、同样的 junk/i1、
     * keepalive=5）对候选各发一次真握手，只留下真的回了 handshake response 的。
     *
     * 引擎侧的 hsprobe.go 早就实现了（假 tun + 真 wireguard-go + UAPI 里的
     * last_handshake_time_sec），但 Kotlin 这边一直没接上——VERIFY_* 那几个常量
     * 声明了却没人用，等于每次连接都在拿 0xcf 探针的结果当「节点可用」。
     *
     * 为什么不能只靠探针（0xcf 64 字节包）：它跟账号、密钥、握手毫无关系，只证明
     * 「这个 IP:端口 有 UDP 回包」。2026-10-18 的真机日志里，162.159.192.1:2408
     * 和整个 162.159.193.x 段探针全回、握手 0/6；8.x 段握手全过。探活排序只看
     * RTT，而 RTT 全挤在 165~203ms，等于随机 —— 这是「连不上」的主要来源。
     *
     * 失败不判死：返回空时上层会退回「探活顺序逐个硬试」，只是慢一点。
     */
    private fun handshakeGate(protocol: WireProtocol?, nested: Boolean, cands: List<String>): List<String> {
        if (cands.isEmpty()) return emptyList()
        val id = identity()
        // 混淆必须和真实会话一致：这条线路上「明文握手」和「junk 握手」能放行的
        // 端点集合不同，用干净握手替 AWG 排序会挑出实际握不上的端点。
        // 嵌套路径（GOOL 外层 / 赛风上游）无论选 WG 还是 AWG，隧道都带 junk。
        val useJunk = protocol == WireProtocol.AWG || nested
        val cfg = JSONObject().apply {
            put("privateKey", id.optString("privateKey"))
            put("peerPublicKey", id.optString("peerPublicKey"))
            put("endpoint", cands.first())
            put("mtu", 1280)
            put("keepalive", VERIFY_KEEPALIVE)
            put("address", id.optString("ipv4"))
            put("dns", "1.1.1.1")
            if (useJunk) {
                put("junkCount", 6)
                put("junkMinSize", 10)
                put("junkMaxSize", 50)
            }
        }
        val e = engine.Engine_()
        runCatching { e.setLogFile(File(context.filesDir, "logs/engine.log").absolutePath) }
        runCatching {
            e.setClockOffsetMinutes(
                (java.util.TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000).toLong(),
            )
        }
        val started = System.currentTimeMillis()
        val raw = runCatching {
            e.probeHandshake(cfg.toString(), JSONArray(cands).toString(), VERIFY_TIMEOUT_MS, VERIFY_WORKERS)
        }.onFailure {
            LogBus.w("NativeCore", "握手预筛调用失败：${it.message}")
        }.getOrNull().orEmpty()
        val cost = System.currentTimeMillis() - started

        // 返回格式（纯文本，避免 gomobile/org.json 的空结果坑）：
        //   第一行：通过数量 n；之后 n 行：`ip:port<TAB>握手耗时ms`，按耗时升序。
        val ok = ArrayList<String>()
        raw.lineSequence().drop(1).forEach { line ->
            val addr = line.substringBefore('\t').trim()
            if (addr.isNotBlank()) ok += addr
        }
        if (ok.isEmpty()) {
            LogBus.w(
                "NativeCore",
                "握手预筛：${cands.size} 个候选全部没握上手（${cost}ms，junk=${useJunk}）—— " +
                    "退回按探活顺序逐个硬试",
            )
        } else {
            LogBus.i(
                "NativeCore",
                "握手预筛：${cands.size} 个候选里 ${ok.size} 个真握手通过（${cost}ms，junk=${useJunk}）：" +
                    ok.joinToString(),
            )
        }
        return ok
    }

    /** 预筛的结论（空 = 没发现问题），给失败文案用。 */
    fun screenNote(): String = screenNote

    // ------------------------------------------------------------------
    // 端点健康度（「连上几秒就断」的端点要记住）
    // ------------------------------------------------------------------

    /** 这个端点最近是不是「连上没多久就断」过（TTL 内）。 */
    private fun isBadEndpoint(addr: String): Boolean {
        val at = synchronized(badEndpoints) { badEndpoints[addr] } ?: return false
        if (System.currentTimeMillis() - at > BAD_ENDPOINT_TTL_MS) {
            synchronized(badEndpoints) { badEndpoints.remove(addr) }
            return false
        }
        return true
    }

    /** 把候选列表里近期断过的端点挪到末尾，其余顺序不变。 */
    private fun reorderByHealth(cands: List<String>): List<String> {
        if (cands.isEmpty()) return cands
        val (bad, good) = cands.partition { isBadEndpoint(it) }
        if (bad.isEmpty()) return cands
        LogBus.i("NativeCore", "近期短命的端点排到最后 ${bad.size} 个：${bad.joinToString().take(160)}")
        return good + bad
    }

    /**
     * 记下「这个端点连上没多久就断了」。
     *
     * 调用点：断流看门狗判定断流时（见 TherVpnService.startHealthLoop）。判据是
     * 「本次连接用掉的时间 < [BAD_ENDPOINT_TTL_MS] 里定义的短命窗口」，由调用方
     * 决定传不传 —— 撑了十分钟才断的端点不该被记仇。
     */
    fun markEndpointBad(addr: String) {
        val a = addr.trim()
        if (a.isBlank()) return
        synchronized(badEndpoints) { badEndpoints[a] = System.currentTimeMillis() }
        LogBus.w("NativeCore", "端点 $a 连上没多久就断了，记下来：下一轮排到最后（30 分钟内）")
    }

    /** 当前在用的端点（外层端点，GOOL 时是外层）。 */
    fun currentEndpoint(): String = activeEndpoint

    /**
     * 连上之后调一次：把「会话内换端点」的游标移到当前端点的**下一个**。
     *
     * 不这么做的话，第一次断流会把候选列表的第 0 个又试一遍 —— 而第 0 个恰恰
     * 是刚才连接阶段已经失败过的那个（2026-10-19 23:57 那次：候选
     * [8.39.214.39:3854 失败, 8.39.214.25:1002 失败, 8.39.214.237:955 成功]，
     * 断流后重试第 0 个等于白烧 6.5s）。
     */
    fun armRecovery() {
        val i = candidateEndpoints.indexOf(activeEndpoint)
        switchCursor = if (i >= 0) i + 1 else 0
    }

    /**
     * ★ 会话内换端点（0.1.29）：不重建设备、不重扫节点、不换会话。
     *
     * 为什么这是「减少自动断开重连」的关键：以前的断流处理只有一条路 ——
     * `newSession()` 重来一遍，而重来一遍要重新注册/读身份 + 重新探活 + 重新
     * 真握手预筛 + 重新建 tun，2026-10-19 的日志里是 26~28s。用户看到的就是
     * 「自动断开重连好几次」。
     *
     * 而「断流」的绝大多数情况只是**这一台边缘不转发了**，换一台就行：设备不用
     * 重建（本地 UDP 源端口不变），只改 peer 的 endpoint，再主动发一次握手，
     * 1~2s 就能知道新端点行不行（引擎的 SwitchEndpoint 会顺手 ForceHandshake）。
     *
     * 返回新端点；没有更多候选（或全部切换失败）返回 null，由调用方退回整会话重扫。
     */
    fun recoverEndpoint(): String? {
        val e = core ?: return null
        val pool = candidateEndpoints
        if (pool.isEmpty()) return null
        while (switchCursor < pool.size) {
            val addr = pool[switchCursor]
            switchCursor++
            if (addr == activeEndpoint) continue
            try {
                e.switchEndpoint(addr)
                activeEndpoint = addr
                LogBus.i("NativeCore", "会话内换端点 → $addr（设备不重建，已主动发起握手）")
                return addr
            } catch (t: Throwable) {
                LogBus.w("NativeCore", "会话内换端点 $addr 失败：${t.message}，换下一个")
                markEndpointBad(addr)
            }
        }
        return null
    }

    // ------------------------------------------------------------------
    // 节点扫描 + 缓存
    // ------------------------------------------------------------------

    private fun nodesFile(protocol: WireProtocol?): File =
        File(context.filesDir, "nodes-${protocol?.id ?: "wg"}.json")

    /** 读缓存：只认 15 分钟内验过的节点。 */
    private fun loadVerified(protocol: WireProtocol?): List<String> = runCatching {
        val f = nodesFile(protocol)
        if (!f.isFile) return emptyList()
        val o = JSONObject(f.readText())
        val at = o.optLong("at", 0L)
        if (System.currentTimeMillis() - at > NODE_CACHE_TTL_MS) {
            LogBus.i("NativeCore", "节点缓存已过期（${(System.currentTimeMillis() - at) / 1000}s 前），重新扫描")
            f.delete()
            return emptyList()
        }
        val arr = o.optJSONArray("nodes") ?: return emptyList()
        (0 until arr.length()).mapNotNull { arr.optString(it).takeIf { s -> s.isNotBlank() } }
    }.getOrElse { emptyList() }

    private fun cachedAgeText(protocol: WireProtocol?): String = runCatching {
        val at = JSONObject(nodesFile(protocol).readText()).optLong("at", 0L)
        "${(System.currentTimeMillis() - at) / 1000}s "
    }.getOrDefault("")

    private fun saveVerified(protocol: WireProtocol?, nodes: List<String>) {
        runCatching {
            // 手工拼：Android 的 org.json 里 `JSONArray(Collection)` 会命中
            // `JSONArray(Object)` 重载并抛「cannot be converted to JSONArray」。
            val arr = JSONArray()
            nodes.forEach { arr.put(it) }
            val o = JSONObject().apply {
                put("at", System.currentTimeMillis())
                put("protocol", protocol?.id ?: "wg")
                put("nodes", arr)
            }
            nodesFile(protocol).writeText(o.toString())
        }.onFailure { LogBus.w("NativeCore", "节点缓存写入失败：${it.message}") }
    }

    /** 连接失败 / 身份轮换时清掉缓存：那些节点在刚才那次会话里没扛住。 */
    private fun clearVerified() {
        runCatching { WireProtocol.entries.forEach { nodesFile(it).delete() } }
        LogBus.i("NativeCore", "节点缓存已清空，下次连接重新扫描")
    }

    /**
     * 只作废节点缓存，**不记身份失败**。
     *
     * 给「一轮端点全灭 → 自动重扫再来一轮」用（见 TherVpnService 的 MAX_CONNECT_ROUNDS）：
     * 下一轮必须重新扫描，但身份轮换的口径是「用户点一次连接失败一次」，中间自动
     * 重试的轮次不该把 failStreak 顶到阈值、让下一次连接直接注销重注册。
     */
    fun invalidateCache() = clearVerified()

    /** WARP 存活探测：Cloudflare 对探针回 0xcf 标记，跟账号密钥无关。 */
    private fun probeLive(limit: Int = PROBE_LIMIT_FIRST, budgetMs: Long = PROBE_BUDGET_MS): List<String> {
        val e = engine.Engine_()
        runCatching { e.setLogFile(File(context.filesDir, "logs/engine.log").absolutePath) }
        runCatching {
            e.setClockOffsetMinutes(
                (java.util.TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000).toLong(),
            )
        }
        val started = System.currentTimeMillis()
        val json = runCatching { e.probeEndpoints(PROBE_TIMEOUT_MS, limit.toLong(), budgetMs) }
            .onFailure { LogBus.w("NativeCore", "端点探测失败：${it.message}") }
            .getOrNull()
            .orEmpty()
        val live = runCatching {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { i ->
                arr.optJSONObject(i)?.optString("addr")?.takeIf { it.isNotBlank() }
            }
        }.getOrDefault(emptyList())
        val cost = System.currentTimeMillis() - started
        if (live.isEmpty()) {
            LogBus.w("NativeCore", "WARP 端点池一个都没探活（${cost}ms，本网络很可能整体拦了 WARP 的 UDP）")
        } else {
            LogBus.i("NativeCore", "探活到 ${live.size} 个端点（${cost}ms，标准端口优先），最快 ${live.first()}")
        }
        return live
    }

    /** 本次连接要排除出隧道的 IP，否则加密包会绕回自己。 */
    fun endpointHosts(): List<String> = excludeIps.ifEmpty {
        val ep = identity().optString("endpoint")
        resolveIpv4(ep.substringBeforeLast(':'))
    }

    /**
     * 按验证顺序排好的 `ip:port` 列表，由 connect() 逐个试握手。
     *
     * **不再有兜底**：以前探活为空时会退回「注册端点 + 常见 anycast IP」，那些
     * 地址一个都没验证过，等于拿用户的时间去赌。现在空就是空，上层会直接报
     * 「扫描 N 个地址没有一个能握手」。
     */
    fun candidates(): List<String> = candidateEndpoints

    /**
     * 不重建设备，把对端热切换到 [addr]（B 方案）。
     *
     * 保留同一个 device 的意义：本地 UDP 源端口不变 = 同一条五元组，wireguard-go
     * 的 5s 握手重传会继续发到新端点上。每重建一次设备就换一个源端口，等于主动
     * 丢掉重传机会——而这条线路上「新流的第一个包被丢」是常态。
     */
    fun switchEndpoint(addr: String) {
        val e = core ?: throw IllegalStateException("原生核心未启动，无法切换端点")
        e.switchEndpoint(addr)
        activeEndpoint = addr
    }

    /**
     * 把引擎环形缓冲里的日志**立刻**倒进应用日志。
     *
     * 为什么必须显式做：引擎日志是每 500ms 由 [startLogPump] 拉一次的，而
     * `start()` / `startGool()` 失败时上层紧接着就 `stop()` 把引擎关掉、泵线程
     * 也随之退出 —— 失败那一次的现场（哪一步没握手、UAPI 报了什么）全丢。
     * 2026-10-19 23:57 的日志里，前两个外层端点各失败 6.5s，但一个字的原因都
     * 没留下，只能靠猜。
     */
    private fun drainEngineLogs(e: engine.Engine_) {
        val text = runCatching { e.drainLogs() }.getOrNull().orEmpty()
        if (text.isNotBlank()) {
            text.lineSequence().filter { it.isNotBlank() }.forEach { LogBus.i("Core", it) }
        }
    }

    private fun resolveIpv4(host: String): List<String> = runCatching {
        InetAddress.getAllByName(host)
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .distinct()
    }.getOrElse {
        LogBus.w("NativeCore", "解析端点 $host 失败：${it.message}")
        emptyList()
    }

    /**
     * 端点必须用**字面 IP** 交给 wireguard-go。
     *
     * 原因：device.IpcSet 在处理 `endpoint=` 时会立刻解析域名，而这时 tun 已经
     * 建好、默认路由已经指向隧道——DNS 查询进了隧道，可握手还没发生，于是必然
     * 解析失败、握手永远不启动。所以域名必须在 establish() 之前解析好
     * （[endpointHosts] 正是在那个时候被调的），这里只负责把结果取出来拼成
     * `ip:port`。
     */
    private fun pinnedEndpoint(raw: String): String {
        if (raw.isBlank()) return raw
        val host = raw.substringBeforeLast(':')
        val port = raw.substringAfterLast(':', "2408")
        if (host.matches(Regex("^[0-9.]+$"))) return "$host:$port"
        if (pinnedIp.isBlank()) pinnedIp = resolveIpv4(host).firstOrNull().orEmpty()
        if (pinnedIp.isBlank()) {
            LogBus.w("NativeCore", "端点 $host 没有解析出 IPv4，退回域名（可能解析失败）")
            return raw
        }
        return "$pinnedIp:$port"
    }

    /** 同 [pinnedEndpoint]，但不复用/不覆盖共享缓存（给内层用）。 */
    private fun endpointLiteral(raw: String): String {
        if (raw.isBlank()) return raw
        val host = raw.substringBeforeLast(':')
        val port = raw.substringAfterLast(':', "2408")
        if (host.matches(Regex("^[0-9.]+$"))) return "$host:$port"
        val ip = resolveIpv4(host).firstOrNull().orEmpty()
        return if (ip.isBlank()) raw else "$ip:$port"
    }

    override fun start(cfg: EngineConfig, tunFd: Int?): EngineEndpoint {
        closing = false
        if (tunFd == null) {
            throw IllegalStateException(
                "系统代理模式需要用户态 netstack（把本地 SOCKS 装进隧道），" +
                    "当前版本只在 VPN / Tun 模式下使用原生核心。"
            )
        }
        if (cfg.protocol.core != com.aether.ther.data.CoreKind.Native) {
            throw IllegalStateException("${cfg.protocol.title} 不属于原生核心")
        }
        if (!cfg.protocol.implemented) {
            throw IllegalStateException(
                "原生核心的 ${cfg.protocol.title} 传输还没接入（当前只有 WireGuard / AWG 可用）"
            )
        }

        // GOOL + 赛风：内层不接设备 tun，而是挂到用户态协议栈上并在隧道里开 socks，
        // 由 startWithPsiphon 走 startGoolTunnel 那条路（见下）。

        // GOOL：两层 WireGuard，外层只负责出得去，内层才是设备的隧道。
        if (cfg.protocol == WireProtocol.GOOL_NATIVE) return startGool(cfg, tunFd)

        // 赛风出口：原生隧道先建在用户态协议栈上（不接管 tun），
        // 让赛风从隧道里出去，再把设备 tun 接到赛风的 socks。
        if (cfg.psiphonExit) return startWithPsiphon(cfg, tunFd)

        // 原生侧：AWG 就是 WireGuard + junk 混淆，同一个引擎，只是配置不同。
        // 混淆与否完全由协议决定（选 AWG 就混淆、选 WireGuard 就不混淆），
        // 所以设置里没有单独的「Junk」开关。
        val useJunk = cfg.protocol == WireProtocol.AWG
        val identity = identity()
        val uapi = JSONObject().apply {
            put("privateKey", identity.optString("privateKey"))
            put("peerPublicKey", identity.optString("peerPublicKey"))
            put("endpoint", cfg.endpoint ?: pinnedEndpoint(identity.optString("endpoint")))
            put("mtu", cfg.mtu)
            put("keepalive", if (cfg.keepalive > 0) cfg.keepalive else 25)
            if (useJunk) {
                // 与电脑版同默认：6 个随机包，10~50 字节；i1 有填就用填的。
                put("junkCount", 6)
                put("junkMinSize", 10)
                put("junkMaxSize", 50)
                if (cfg.awgI1.isNotBlank()) put("junkI1", cfg.awgI1.trim())
            }
        }

        val e = engine.Engine_()
        // 让 Go 侧的日志同步落盘：原生崩溃时进程直接消失，环形缓冲里的现场也跟
        // 着没了，只有文件能留下「死在 start 的哪一步」。
        runCatching { e.setLogFile(File(context.filesDir, "logs/engine.log").absolutePath) }
            .onFailure { LogBus.w("NativeCore", "引擎日志落盘不可用：${it.message}") }
        // 安卓上的 Go 拿不到系统时区，会把时间打成 UTC（比北京时间早 8 小时），
        // 和 Java 侧日志对不上，所以把偏移显式告诉它。
        runCatching {
            e.setClockOffsetMinutes(
                (java.util.TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000).toLong(),
            )
        }
        // 这一行能证明 .so 加载与 JNI 都正常：它后面直接调用 start()，一旦进程
        // 在这里之后消失，问题就在 Go 侧的 start 里。
        LogBus.i("NativeCore", "引擎对象已创建：${runCatching { e.version() }.getOrNull() ?: "版本未知"}")
        LogBus.i(
            "NativeCore",
            "启动原生核心：protocol=${cfg.protocol.id} fd=$tunFd endpoint=${uapi.optString("endpoint")} " +
                "mtu=${cfg.mtu} keepalive=${uapi.optInt("keepalive")} junk=$useJunk " +
                "keyLen=${uapi.optString("privateKey").length} peerLen=${uapi.optString("peerPublicKey").length}",
        )
        try {
            e.start(uapi.toString(), tunFd.toLong())
        } catch (t: Throwable) {
            // 失败现场只有引擎自己的环形缓冲里有，先倒出来再关。
            drainEngineLogs(e)
            runCatching { e.stop() }
            throw t
        }
        LogBus.i("NativeCore", "引擎 start() 已返回")
        // 启动期间可能已经被新会话 stop 掉了：这时引擎虽然起来了，但没人会用它，
        // 必须自己关掉，否则它和它的 tun fd 会一直留在后台。
        if (closing) {
            runCatching { e.stop() }
            throw IllegalStateException("连接已被新的会话取代")
        }
        core = e
        activeEndpoint = uapi.optString("endpoint")
        startLogPump(e)
        LogBus.i("NativeCore", "原生核心已接管 tun fd=$tunFd")
        return EngineEndpoint(socksPort = 0)
    }

    // ------------------------------------------------------------------
    // GOOL：wireguard in wireguard
    // ------------------------------------------------------------------

    /** 用户设的 DNS 里第一个可用地址；没设就用 1.1.1.1（隧道内解析也用它）。 */
    private fun tunnelDns(cfg: EngineConfig): String =
        cfg.dns.split(',', ' ', ';').firstOrNull { it.isNotBlank() }?.trim() ?: "1.1.1.1"

    /** GOOL 外层配置：能被运营商看见、只负责「出得去」的那一层。 */
    private fun goolOuterConfig(cfg: EngineConfig): JSONObject {
        val outer = identity()
        val endpoint = cfg.endpoint ?: pinnedEndpoint(outer.optString("endpoint"))
        val o = JSONObject().apply {
            put("privateKey", outer.optString("privateKey"))
            put("peerPublicKey", outer.optString("peerPublicKey"))
            put("endpoint", endpoint)
            // 外层要多装：内层 WireGuard 头 32B + IP/UDP 头 28B。
            put("mtu", cfg.mtu + 140)
            // 外层 keepalive 用 5s（官方核心 run_warp_in_warp 里外层就是 5）：
            // 外层要一直替内层扛着 NAT/边缘会话，越热越不容易被清掉。
            put("keepalive", GOOL_OUTER_KEEPALIVE)
            put("address", outer.optString("ipv4"))
            put("dns", tunnelDns(cfg))
            // ★ 外层必须带 AWG junk。
            //
            // 以前这里写的是「外层不用 junk，GOOL 的意义是双层不是混淆」——错的。
            // 官方核心 run_warp_in_warp 建外层时 obfuscate=true，而我们的实测日志
            // （.tmp/gool3.log）正好是反面教材：裸 WG 外层握手成功、数据面自检也过，
            // 之后 userNet rx 一直是 0、内层握手一个回包都没有 —— 典型「被识别后
            // 静默丢弃」。junk 只是握手前多发几个随机包，标准 WireGuard 对端
            // （WARP 也是）不受影响，所以对外层只会更安全。
            put("junkCount", 6)
            put("junkMinSize", 10)
            put("junkMaxSize", 50)
            if (cfg.awgI1.isNotBlank()) put("junkI1", cfg.awgI1.trim())
        }
        if (o.optString("address").isBlank()) {
            throw IllegalStateException("WARP 身份里没有 ipv4 地址，GOOL 外层协议栈没法发包")
        }
        return o
    }

    /** GOOL 内层配置：真正给设备走的那一层，用一份独立注册的身份。 */
    private fun goolInnerConfig(cfg: EngineConfig): JSONObject {
        val inner = innerIdentity()
        // 每次都按**这一轮真正用的外层端点**重新挑内层：外层会在候选间轮换，
        // 写死一个内层就可能和外层撞到同一个 IP 上（那样出口地址不会变，GOOL 白做）。
        val outerIp = cfg.endpoint?.substringBeforeLast(':')
        val endpoint = pickInnerEndpoint(outerIp)
            ?: innerEndpointLiteral.ifBlank { endpointLiteral(inner.optString("endpoint")) }
        val o = JSONObject().apply {
            put("privateKey", inner.optString("privateKey"))
            put("peerPublicKey", inner.optString("peerPublicKey"))
            put("endpoint", endpoint)
            // 内层落点备选：引擎会逐个等真握手（见 gool.go 的 innerCandidates）。
            put("innerCandidates", JSONArray(pickInnerCandidates(outerIp)))
            put("mtu", cfg.mtu)
            put("keepalive", NESTED_KEEPALIVE)
            put("address", inner.optString("ipv4"))
            put("dns", tunnelDns(cfg))
        }
        if (o.optString("address").isBlank()) {
            throw IllegalStateException("内层 WARP 身份里没有 ipv4 地址")
        }
        return o
    }

    /**
     * 给 GOOL 内层挑一个和外层**不在同一个边缘**的端点。
     *
     * 电脑版核心的示例就是跨段的两个地址、且都用 2408 这个标准入口：
     *   aether --gool --wiw-outer 162.159.192.1:2408 --wiw-inner 188.114.96.1:2408
     *
     * 同一个 IP 上内外两层没有意义（出口地址不会变），同一 /24 的邻居也常被同一个
     * 边缘聚合。所以优先跨 /24 + 标准端口，其次跨 /24，再次跨 IP；都没有就返回
     * null，由调用方退回注册默认入口。
     *
     * ★ 优先从 [verifiedEndpoints]（刚真握手通过的）里挑：内层落点落在「探针通、
     * 握手不回」的边缘上时，表现就是外层全好、内层零回包——0.1.25 的日志里内层
     * 挑的正是 162.159.193.238:968，那台机器做外层也握不上手。
     */
    private fun pickInnerEndpoint(outerIp: String?): String? {
        fun netOf(ep: String) = ep.substringBeforeLast(':').substringBeforeLast('.')
        val outerNet = outerIp?.substringBeforeLast('.')
        for (pool in listOf(verifiedEndpoints, candidateEndpoints)) {
            val others = pool.filter { it.substringBeforeLast(':') != outerIp }
            if (others.isEmpty()) continue
            val crossNet = others.filter { outerNet != null && netOf(it) != outerNet }
            return crossNet.firstOrNull { it.endsWith(":2408") }
                ?: crossNet.firstOrNull()
                ?: others.firstOrNull { it.endsWith(":2408") }
                ?: others.first()
        }
        return null
    }

    /**
     * GOOL 内层可以依次尝试的落点（引擎侧 `innerCandidates`）。
     *
     * 外层是好的、内层落点不通时，换落点比把整条 GOOL 拆掉重来便宜得多。给 3 个：
     * 引擎会先用 0xcf 探针**在外层隧道里**验活（见 gool.go），验出来的那个一般
     * 一次就握上；给 3 个是为了探针全灭时还有退路。
     */
    private fun pickInnerCandidates(outerIp: String?, limit: Int = 3): List<String> {
        val out = LinkedHashSet<String>()
        pickInnerEndpoint(outerIp)?.let { out += it }
        for (pool in listOf(verifiedEndpoints, candidateEndpoints)) {
            for (ep in pool) {
                if (out.size >= limit) return out.toList()
                if (ep.substringBeforeLast(':') != outerIp) out += ep
            }
        }
        return out.toList()
    }

    private fun startGool(cfg: EngineConfig, tunFd: Int): EngineEndpoint {
        val outerCfg = goolOuterConfig(cfg)
        val innerCfg = goolInnerConfig(cfg)

        val e = newEngine()
        LogBus.i(
            "NativeCore",
            "GOOL 启动：外层 ${outerCfg.optString("endpoint")}（接口 ${outerCfg.optString("address")}）" +
                " → 内层 ${innerCfg.optString("endpoint")}（接口 ${innerCfg.optString("address")}）",
        )
        try {
            e.startGool(outerCfg.toString(), innerCfg.toString(), tunFd.toLong())
        } catch (t: Throwable) {
            drainEngineLogs(e)
            runCatching { e.stop() }
            throw t
        }
        if (closing) {
            runCatching { e.stop() }
            throw IllegalStateException("连接已被新的会话取代")
        }
        core = e
        activeEndpoint = outerCfg.optString("endpoint")
        startLogPump(e)
        LogBus.i("NativeCore", "GOOL 已接管 tun fd=$tunFd（内层握手完成才算连上）")
        return EngineEndpoint(socksPort = 0)
    }

    // ------------------------------------------------------------------
    // 原生核心 + 赛风出口
    // ------------------------------------------------------------------

    /**
     * 原生隧道 + 赛风第二跳。
     *
     * 赛风只carry TCP，塞不进 IP 层，所以这里换了个拓扑：
     *  1. 原生 WireGuard 挂在用户态协议栈上（不接管 tun），并在隧道里开一个 socks5；
     *  2. 用 Aether 核心的 `--psiphon-only` 只跑赛风，`--upstream` 指向那个 socks5 ——
     *     赛风的每一条 TCP 都从原生隧道里出去（这是「赛风在隧道内」的关键）；
     *  3. 最后把设备 tun 通过 socks-tun 接到赛风的 socks。
     *
     * 这样既不用自己实现赛风的配置/服务器列表，也不存在「开关开了、出口还是 WARP」。
     */
    private fun startWithPsiphon(cfg: EngineConfig, tunFd: Int): EngineEndpoint {
        val identity = identity()
        val endpoint = cfg.endpoint ?: pinnedEndpoint(identity.optString("endpoint"))
        val upPort = pickPort()
        // 必须和隧道内 socks 的端口不同（见 [pickPort]）。
        val psPort = pickPort(avoid = setOf(upPort))
        val dns = tunnelDns(cfg)
        val tunnelCfg = JSONObject().apply {
            put("privateKey", identity.optString("privateKey"))
            put("peerPublicKey", identity.optString("peerPublicKey"))
            put("endpoint", endpoint)
            put("mtu", cfg.mtu)
            // 只给赛风做出站的这条隧道空闲窗口必须短（见 NESTED_KEEPALIVE）。
            put("keepalive", NESTED_KEEPALIVE)
            put("address", identity.optString("ipv4"))
            // 隧道内 socks 收到的是域名，解析必须在隧道里做，否则拿到污染地址。
            put("dns", dns)
            // ★ 这条隧道**永远**带 AWG junk，跟用户选的是 WG 还是 AWG 无关。
            //
            // 它是赛风的载体：一旦被识别，表现就是「握手成功、数据面自检也过，
            // 之后一条 TCP 都拨不出去」——赛风的每条连接都会变成 connection
            // refused / i/o timeout，界面上就是「赛风出口无法连接」。junk 只是
            // 握手前多几个随机包，WARP 作为标准 WireGuard 对端不受影响。
            put("junkCount", 6)
            put("junkMinSize", 10)
            put("junkMaxSize", 50)
            if (cfg.awgI1.isNotBlank()) put("junkI1", cfg.awgI1.trim())
        }
        if (tunnelCfg.optString("address").isBlank()) {
            throw IllegalStateException("WARP 身份里没有 ipv4 地址，赛风没有可用的隧道上游")
        }

        val e = newEngine()
        try {
            if (cfg.protocol == WireProtocol.GOOL_NATIVE) {
                // GOOL 的隧道形态：内外两层，内层挂协议栈 + 隧道内 socks。
                val outerCfg = goolOuterConfig(cfg)
                val innerCfg = goolInnerConfig(cfg)
                LogBus.i(
                    "NativeCore",
                    "GOOL + Psiphon：外层 ${outerCfg.optString("endpoint")} → 内层 ${innerCfg.optString("endpoint")}，" +
                        "隧道内 socks=127.0.0.1:$upPort",
                )
                e.startGoolTunnel(outerCfg.toString(), innerCfg.toString(), "127.0.0.1:$upPort")
            } else {
                LogBus.i(
                    "NativeCore",
                    "原生核心 + Psiphon：先建隧道 $endpoint（接口 ${tunnelCfg.optString("address")}），" +
                        "隧道内 socks=127.0.0.1:$upPort",
                )
                e.startTunnel(tunnelCfg.toString(), "127.0.0.1:$upPort")
            }
        } catch (t: Throwable) {
            drainEngineLogs(e)
            runCatching { e.stop() }
            throw t
        }
        activeEndpoint = endpoint

        val status = runCatching { JSONObject(e.statusJSON()) }.getOrNull()
        val handed = status?.optBoolean("handshaken", false) == true ||
            status?.optBoolean("tunnelHandshaken", false) == true
        if (!handed) {
            runCatching { e.stop() }
            throw IllegalStateException("原生隧道 7s 内没有完成握手，赛风出不去（换端点或换网络再试）")
        }
        ensureAlive()

        val ps = AetherCore(context)
        val readyPort = try {
            ps.startPsiphonOnly(upPort, psPort, cfg.exitRegion) {
                // 上游隧道还活着吗？这条隧道 keepalive=10s，健康时 hsAgeSec 永远 ≤10；
                // 超过 18s 说明对端已经不回包了（wireguard-go 自己在 15s 就开始重握手）。
                // 隧道断了还让赛风等满 25s+25s，就是用户看到的「一直转圈然后失败」。
                val st = runCatching { JSONObject(e.statusJSON()) }.getOrNull()
                val hsAge = st?.optLong("hsAgeSec", -1L) ?: -1L
                hsAge in 0..18
            }
        } catch (t: Throwable) {
            runCatching { ps.stop() }
            runCatching { e.stop() }
            throw t
        }
        psiphonCore = ps
        // 赛风进程起得来但会话已经作废：必须把它关掉，否则它一直占着数据库锁和端口。
        if (closing) {
            runCatching { ps.stop() }
            runCatching { e.stop() }
            psiphonCore = null
            throw IllegalStateException("连接已被新的会话取代")
        }

        LogBus.i("NativeCore", "赛风第二跳已就绪，把设备 tun 接到赛风 socks 127.0.0.1:$readyPort")
        e.startSocks("127.0.0.1:$readyPort", tunFd.toLong(), dns, cfg.mtu.toLong())
        core = e
        startLogPump(e)
        LogBus.i("NativeCore", "原生核心 + 赛风已接管 tun fd=$tunFd")
        return EngineEndpoint(socksPort = readyPort)
    }

    /** 统一的引擎初始化（日志落盘 + 时钟偏移），新路径都用它，避免漏配。 */
    private fun newEngine(): engine.Engine_ {
        val e = engine.Engine_()
        runCatching { e.setLogFile(File(context.filesDir, "logs/engine.log").absolutePath) }
            .onFailure { LogBus.w("NativeCore", "引擎日志落盘不可用：${it.message}") }
        runCatching {
            e.setClockOffsetMinutes(
                (java.util.TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60_000).toLong(),
            )
        }
        LogBus.i("NativeCore", "引擎对象已创建：${runCatching { e.version() }.getOrNull() ?: "版本未知"}")
        return e
    }

    /**
     * 挑一个空闲端口。
     *
     * [avoid] 里的端口绝不能再返回：`ServerSocket(0)` 关掉之后系统会立刻把同一个
     * 端口复用给下一次调用，而「赛风出口」这条路径要同时占两个端口——隧道内 socks
     * 和赛风自己的监听。两者撞上时，赛风 bind 失败，但 [AetherCore.waitAnyPort]
     * 看到那个端口**我们自己**在 listen，会误判成「赛风已就绪」，然后白等 25s×2
     * 才报一个和真实原因无关的超时。
     */
    private fun pickPort(avoid: Set<Int> = emptySet()): Int {
        repeat(12) {
            val p = runCatching { java.net.ServerSocket(0).use { it.localPort } }.getOrDefault(0)
            if (p > 0 && p !in avoid) return p
        }
        return runCatching { java.net.ServerSocket(0).use { it.localPort } }.getOrDefault(0)
    }

    /** 引擎日志要进应用日志：Go 侧写环形缓冲，这边定时取。 */
    private fun startLogPump(e: engine.Engine_) {
        pump = Thread({
            // 整个循环包一层：这个线程上抛出的任何异常都会走 Android 的默认
            // UncaughtExceptionHandler，而它的处理是 Process.killProcess(自己)。
            // 之前 stop() 里的 pump.interrupt() 让 Thread.sleep 抛 InterruptedException
            // 逃出去，于是「连接失败」变成了「APP 直接消失」——就是用户看到的闪退。
            try {
                while (core === e) {
                    val text = runCatching { e.drainLogs() }.getOrNull().orEmpty()
                    if (text.isNotBlank()) {
                        text.lineSequence().filter { it.isNotBlank() }.forEach { LogBus.i("Core", it) }
                    }
                    Thread.sleep(500)
                }
            } catch (_: InterruptedException) {
                // stop() 把我们叫停了，正常退出，绝不往外抛。
            } catch (t: Throwable) {
                LogBus.w("NativeCore", "引擎日志线程退出：${t.message}")
            }
        }, "native-core-log").apply { isDaemon = true }
        pump?.start()
    }

    /** 握手是否完成——这是「隧道真的通了」的唯一信号。 */
    fun status(): JSONObject {
        val e = core ?: return JSONObject().put("running", false)
        val s = runCatching { e.statusJSON() }.getOrNull().orEmpty()
        return runCatching { JSONObject(s) }.getOrElse { JSONObject().put("running", false) }
    }

    fun handshaken(): Boolean = status().optBoolean("handshaken", false)

    override fun stop() {
        // 先作废：正在跑的 start 会在下一个检查点自己收手（见 ensureAlive）。
        closing = true
        val e = core
        core = null
        val ps = psiphonCore
        psiphonCore = null
        if (e != null) runCatching { e.stop() }
        if (ps != null) {
            LogBus.i("NativeCore", "停止赛风（psiphon-only 进程）")
            runCatching { ps.stop() }
        }
        pump?.interrupt()
        pump = null
        LogBus.i("NativeCore", "原生核心已停止")
    }
}
