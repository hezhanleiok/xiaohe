package com.aether.ther.core

import com.aether.ther.data.CoreKind
import com.aether.ther.data.ProxyMode
import com.aether.ther.data.WireProtocol

/**
 * 一次连接需要的全部输入。
 *
 * 刻意做成 flat 的 data class：两个核心（原生 / Aether）拿到的是同一份配置，
 * 由各自决定哪些字段有意义，调用方不需要知道「谁支持什么」。
 */
data class EngineConfig(
    val core: CoreKind,
    val protocol: WireProtocol,
    val mode: ProxyMode,
    /** AWG 的 I1 定制包（可选）；混淆开关本身由协议决定，见 [NativeCore.start]。 */
    val awgI1: String,
    val mtu: Int,
    val ipv6: Boolean,
    val dns: String,
    val keepalive: Int,
    val psiphonExit: Boolean,
    val exitRegion: String,
    /** 本应用的包名 —— 分应用规则里永远要排除自己，否则代理连不上自己的上游。 */
    val selfPackage: String,
    /**
     * 本次要用的端点 `ip:port`。null = 由核心按身份里的默认端点自己决定。
     * 原生核心会按候选列表逐个重试，每次传一个。
     */
    val endpoint: String? = null,
)

/** 核心提供的本地代理端口；原生核心（tun 模式）不需要。 */
data class EngineEndpoint(val socksPort: Int, val httpPort: Int? = null)

/**
 * 数据面核心的统一接口。
 *
 * 两个实现：
 *  - [NativeCore]：wireguard-go 直接读写 VpnService 的 tun fd；
 *  - [AetherCore]：官方 Aether 核心，独立进程 + 本地端口。
 *
 * 约束：start() 是阻塞的，调用方负责放到 IO 线程；失败必须带上人能看懂的
 * 原因（会原样写进日志和首页错误条）。
 */
interface CoreEngine {
    val id: String
    val displayName: String
    val provider: String

    fun isAvailable(): Boolean
    fun unavailableReason(): String

    fun start(cfg: EngineConfig, tunFd: Int?): EngineEndpoint

    fun stop()
}
