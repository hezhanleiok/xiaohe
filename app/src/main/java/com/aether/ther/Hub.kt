package com.aether.ther

import com.aether.ther.data.CoreKind
import com.aether.ther.data.ProxyMode
import com.aether.ther.data.WireProtocol
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** 连接阶段。UI 只认这一个状态机，避免首页和通知栏各说一套。 */
enum class Phase { Idle, Connecting, Connected, Failed }

data class ConnectionState(
    val phase: Phase = Phase.Idle,
    val protocol: WireProtocol = WireProtocol.WG,
    val core: CoreKind = CoreKind.Native,
    val mode: ProxyMode = ProxyMode.Vpn,
    /** 本机地址（连上之后首页那行会换成出口地址）。 */
    val localIp: String = "",
    /** 本机所在国家（启动时直连探测得到，不穿隧道）。 */
    val localCountry: String = "",
    val exitIp: String = "",
    /** ISO-3166-1 alpha-2，用于国旗与英文国名。 */
    val country: String = "",
    val latencyMs: Long = -1,
    val message: String = "",
    val since: Long = 0,
) {
    val displayIp: String get() = if (exitIp.isNotBlank()) exitIp else localIp

    /** 首页那行的标题：显示的是本机地址就写「本机 IP」，是出口地址就写「出口 IP」。 */
    val ipLabel: String get() = if (exitIp.isNotBlank()) "出口 IP" else "本机 IP"

    /** 状态卡「国家 / 地区」要显示的那个：有出口国家就是出口，没有才是本机。 */
    val shownCountry: String
        get() = if (country.isNotBlank()) country else localCountry

    val isBusy: Boolean get() = phase == Phase.Connecting
    val isOn: Boolean get() = phase == Phase.Connected
}

/**
 * 前台服务与 UI 之间唯一的共享点。
 *
 * 之所以不用 bind + 回调：VpnService 在进程被杀后要能自己恢复，绑定式回调
 * 会把「界面在不在」变成连接能否存活的前提。StateFlow 谁写谁读都行。
 */
object Hub {
    private val _state = MutableStateFlow(ConnectionState())
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    fun update(block: (ConnectionState) -> ConnectionState) {
        _state.update(block)
    }

    fun reset() {
        _state.update { ConnectionState(phase = Phase.Idle) }
    }

    /**
     * 本机身份（公网 IP + 所在国家）。启动时直连探一次，断开隧道后也用它把
     * 首页那两行还原成「本机」，不要留着上一次的出口值。
     */
    fun local(ip: String, country: String) {
        _state.update {
            it.copy(
                localIp = ip.ifBlank { it.localIp },
                localCountry = country.ifBlank { it.localCountry },
            )
        }
    }

    fun connecting(
        protocol: WireProtocol,
        core: CoreKind,
        mode: ProxyMode,
        localIp: String,
        message: String,
    ) {
        _state.update {
            it.copy(
                phase = Phase.Connecting,
                protocol = protocol,
                core = core,
                mode = mode,
                localIp = localIp,
                exitIp = "",
                country = "",
                latencyMs = -1,
                message = message,
                since = System.currentTimeMillis(),
            )
        }
    }

    fun connected(exitIp: String, country: String, latencyMs: Long, message: String = "") {
        _state.update {
            it.copy(
                phase = Phase.Connected,
                // 探测失败时不要抹掉核心自己上报的出口（核心会打
                // "… exit: <ip>, <CC> via <colo>"，见 ExitLog；它比我们探测可靠）。
                exitIp = exitIp.ifBlank { it.exitIp },
                country = country.ifBlank { it.country },
                latencyMs = if (latencyMs >= 0) latencyMs else it.latencyMs,
                message = message,
                since = System.currentTimeMillis(),
            )
        }
    }

    /**
     * 核心自己上报的出口（由 [com.aether.ther.core.ExitLog] 从核心 stdout 里解析）。
     *
     * 为什么不用自己的探测当唯一来源：核心的 SOCKS 对某些目标会回 rep=1，
     * 于是「已连接但首页还是本机 IP」。核心既然把出口 IP/国家/到 Cloudflare 的
     * 延迟都打出来了，就先用它，探测只当补充。
     */
    fun exitInfo(ip: String, country: String, latencyMs: Long = -1) {
        if (ip.isBlank()) return
        _state.update {
            // 断开之后迟到的核心日志不能把出口又塞回首页（那时那行是「本机 IP」）。
            if (it.phase != Phase.Connecting && it.phase != Phase.Connected) return@update it
            it.copy(
                exitIp = ip,
                country = country.ifBlank { it.country },
                latencyMs = if (latencyMs >= 0) latencyMs else it.latencyMs,
            )
        }
    }

    fun failed(message: String) {
        _state.update { it.copy(phase = Phase.Failed, message = message) }
    }

    /**
     * 首页「延迟」的唯一写入点：真实 RTT（TCP 握手一个来回），由
     * [com.aether.ther.net.Latency] 在连接后周期采样。
     *
     * 为什么单独一个入口而不是复用 [connected]：延迟会变，出口 IP 不会。
     * 之前把「一次完整 HTTP 请求的耗时」当延迟写进来，于是首页长期是几千 ms。
     */
    fun latency(ms: Long) {
        if (ms <= 0) return
        _state.update {
            if (it.phase != Phase.Connected) it else it.copy(latencyMs = ms)
        }
    }

    fun idle() {
        _state.update {
            it.copy(
                phase = Phase.Idle,
                exitIp = "",
                country = "",
                latencyMs = -1,
                message = "",
            )
        }
    }
}
