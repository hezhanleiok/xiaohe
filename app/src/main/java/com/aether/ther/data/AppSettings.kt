package com.aether.ther.data

import org.json.JSONArray
import org.json.JSONObject

/**
 * 数据面由哪个核心承载。设置里选它，首页的协议列表随之变化。
 *
 * 和电脑版的区别：电脑版有一个独立的「Warp-in-Warp 双层」开关，手机端按需求
 * 取消；原生这一侧就只剩 WG / AWG / GOOL 三个协议。
 */
enum class CoreKind(val id: String, val title: String, val detail: String) {
    /** 原生加速：wireguard-go + tun fd，和电脑版 internal/wgtun 同源。 */
    Native("native", "原生加速", "WireGuard / AWG / GOOL · 内核级隧道"),
    /** Aether 核心：官方二进制，协议由核心自己承载。 */
    Aether("aether", "Aether 核心", "WireGuard / MASQUE / GOOL · 官方核心");

    companion object {
        fun byId(id: String?): CoreKind = entries.firstOrNull { it.id == id } ?: Native
    }
}

/**
 * 首页那个下拉里的一项。
 *
 * [carriedByCore] 是「这一项到底由谁干活」：
 *  - 原生核心只有 WG / AWG 是真接通的；
 *  - Aether 核心的协议全部交给核心进程，应用只负责传参数。
 */
enum class WireProtocol(
    val id: String,
    val title: String,
    val core: CoreKind,
    val detail: String,
    val implemented: Boolean,
) {
    WG("wg", "WireGuard", CoreKind.Native, "UDP · 标准握手", true),
    AWG("awg", "AWG", CoreKind.Native, "AmneziaWG 混淆（Junk / I1）", true),
    GOOL_NATIVE("gool-native", "GOOL", CoreKind.Native, "双层 WireGuard（隧道内再握手）", true),

    AETHER_WG("aether-wg", "WireGuard", CoreKind.Aether, "由 Aether 核心承载", true),
    MASQUE_H2("h2", "MASQUE H2", CoreKind.Aether, "HTTP/2 封装", true),
    MASQUE_H3("h3", "MASQUE H3", CoreKind.Aether, "HTTP/3 封装", true),
    AETHER_GOOL("gool", "GOOL", CoreKind.Aether, "核心 GOOL", true),
    MASQUE_IN_MASQUE("mim", "MASQUE in MASQUE", CoreKind.Aether, "双层 MASQUE", true);

    companion object {
        /** 设置里换了核心之后，首页只留这个核心支持的协议。 */
        fun forCore(core: CoreKind): List<WireProtocol> = entries.filter { it.core == core }

        fun byId(id: String?): WireProtocol? = entries.firstOrNull { it.id == id }

        /** 换核心时的默认协议：各自列表的第一项。 */
        fun defaultFor(core: CoreKind): WireProtocol = forCore(core).first()
    }
}

/** 连接方式。安卓上这三者的区别是「谁来接住流量」。 */
enum class ProxyMode(val id: String, val title: String, val detail: String) {
    /** 只起本地 HTTP/SOCKS 代理，不改系统路由。 */
    System("system", "系统代理", "本地代理 127.0.0.1:7890，手动填进 Wi-Fi 设置"),
    /** VpnService，按分应用白/黑名单决定谁进隧道。 */
    Vpn("vpn", "VPN 模式", "系统级 VPN，按分应用与规则转发"),
    /** VpnService 全量接管 + tun fd 直接交给原生核心。 */
    Tun("tun", "Tun 模式", "接管整机流量，内核级 tun 设备");

    companion object {
        fun byId(id: String?): ProxyMode = entries.firstOrNull { it.id == id } ?: Vpn
    }
}

/** 分应用的两种语义。 */
enum class PerAppMode(val id: String, val title: String) {
    Only("only", "仅代理所选应用"),
    Except("except", "所选应用直连");

    companion object {
        fun byId(id: String?): PerAppMode = entries.firstOrNull { it.id == id } ?: Only
    }
}

/**
 * 全部可持久化的设置。
 *
 * 刻意不用 kotlinx.serialization：字段不多，org.json 手写一遍比多一个编译器插件
 * 和一份 @Serializable 注解更省事，也不会因为改字段名把旧配置读崩。
 */
data class AppSettings(
    // 默认就用 VPN 模式：系统代理模式下没有任何东西能拦住流量，用户点连接时
    // 期望看到的是系统那条「VPN 连接请求」，而不是一句"请手动填 Wi-Fi 代理"。
    val mode: ProxyMode = ProxyMode.Vpn,
    val core: CoreKind = CoreKind.Native,
    val protocol: WireProtocol = WireProtocol.WG,

    // 原生核心
    /** AWG 的 I1 定制包；是否混淆由首页选的协议决定（AWG = 混淆，WG = 不混淆）。 */
    val awgI1: String = "",
    val mtu: Int = 1280,
    val ipv6: Boolean = true,
    val dns: String = "",
    val keepalive: Int = 12,

    // Aether 核心：二进制随整包发布，应用不做「单独更新核心」，所以这里只留一个
    // 调试用的路径覆盖（留空 = files/core/aether-core）。
    val aetherCorePath: String = "",

    // 出口（赛风；Tor 已按需求去掉）
    val psiphonExit: Boolean = false,
    /** "" = 自动（由赛风决定）；否则 ISO-3166-1 alpha-2。 */
    val exitRegion: String = "",

    // 规则与分应用
    val rulesEnabled: Boolean = true,
    val ruleUrls: List<String> = emptyList(),
    val perAppEnabled: Boolean = false,
    val perAppMode: PerAppMode = PerAppMode.Only,
    val perAppPackages: Set<String> = emptySet(),

    // 版本更新（占位符仓库地址）
    val updateRepo: String = "https://github.com/OWNER/ther-android",

    // 界面与日志
    val logLevel: String = "info",
    val autoConnect: Boolean = false,
) {
    /** 协议必须属于当前核心；旧配置里对不上时回落到该核心的第一项。 */
    fun normalized(): AppSettings {
        val p = WireProtocol.byId(protocol.id) ?: WireProtocol.defaultFor(core)
        return if (p.core == core) this else copy(core = p.core, protocol = p)
    }

    fun toJson(): JSONObject = JSONObject().apply {
        put("mode", mode.id)
        put("core", core.id)
        put("protocol", protocol.id)
        put("awgI1", awgI1)
        put("mtu", mtu)
        put("ipv6", ipv6)
        put("dns", dns)
        put("keepalive", keepalive)
        put("aetherCorePath", aetherCorePath)
        put("psiphonExit", psiphonExit)
        put("exitRegion", exitRegion)
        put("rulesEnabled", rulesEnabled)
        put("ruleUrls", JSONArray(ruleUrls))
        put("perAppEnabled", perAppEnabled)
        put("perAppMode", perAppMode.id)
        put("perAppPackages", JSONArray(perAppPackages.toList()))
        put("updateRepo", updateRepo)
        put("logLevel", logLevel)
        put("autoConnect", autoConnect)
    }

    companion object {
        fun fromJson(o: JSONObject): AppSettings {
            val d = AppSettings()
            val core = CoreKind.byId(o.optString("core", d.core.id))
            val protocol = WireProtocol.byId(o.optString("protocol", d.protocol.id))
                ?.takeIf { it.core == core }
                ?: WireProtocol.defaultFor(core)
            return AppSettings(
                mode = ProxyMode.byId(o.optString("mode", d.mode.id)),
                core = core,
                protocol = protocol,
                awgI1 = o.optString("awgI1", d.awgI1),
                mtu = o.optInt("mtu", d.mtu),
                ipv6 = o.optBoolean("ipv6", d.ipv6),
                dns = o.optString("dns", d.dns),
                keepalive = o.optInt("keepalive", d.keepalive),
                aetherCorePath = o.optString("aetherCorePath", d.aetherCorePath),
                psiphonExit = o.optBoolean("psiphonExit", d.psiphonExit),
                exitRegion = o.optString("exitRegion", d.exitRegion),
                rulesEnabled = o.optBoolean("rulesEnabled", d.rulesEnabled),
                ruleUrls = o.optJSONArray("ruleUrls").toStringList(),
                perAppEnabled = o.optBoolean("perAppEnabled", d.perAppEnabled),
                perAppMode = PerAppMode.byId(o.optString("perAppMode", d.perAppMode.id)),
                perAppPackages = o.optJSONArray("perAppPackages").toStringList().toSet(),
                updateRepo = o.optString("updateRepo", d.updateRepo),
                logLevel = o.optString("logLevel", d.logLevel),
                autoConnect = o.optBoolean("autoConnect", d.autoConnect),
            )
        }

        private fun JSONArray?.toStringList(): List<String> {
            if (this == null) return emptyList()
            val out = ArrayList<String>(length())
            for (i in 0 until length()) {
                val v = optString(i, "")
                if (v.isNotBlank()) out.add(v)
            }
            return out
        }
    }
}
