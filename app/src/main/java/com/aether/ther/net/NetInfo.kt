package com.aether.ther.net

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import com.aether.ther.Hub
import com.aether.ther.Phase
import com.aether.ther.data.LogBus
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections
import kotlin.concurrent.thread

object NetInfo {

    /**
     * 启动后（以及断开隧道后）在后台补一份本机身份：公网 IP + 所在国家。
     *
     * 为什么必须直连探：接口里读到的是 192.168.x.x 这种内网地址，国家也无从得知。
     * 探失败就退回到内网 IP，至少「本机 IP」那行不是空的。
     *
     * 隧道在跑的时候不探——那时的出口探测走的是隧道，会把「本机」写成出口。
     */
    fun refreshLocalIdentity(context: Context) {
        if (Hub.state.value.phase == Phase.Connected || Hub.state.value.phase == Phase.Connecting) {
            LogBus.d("Net", "连接中/已连接，跳过本机身份探测")
            return
        }
        thread(name = "local-identity", isDaemon = true) {
            // 后台线程上任何漏出去的异常都会走默认 handler → Process.killProcess，
            // 也就是「APP 自己消失了」。这里全部兜住。
            runCatching {
                val probe = ExitInfo.probeLocal(timeoutMs = 5_000)
                if (probe != null) {
                    Hub.local(probe.ip, probe.country)
                    LogBus.i("Net", "本机 ${probe.ip}（${probe.country.ifBlank { "??" }}）")
                } else {
                    val lan = localIpv4(context)
                    if (lan.isNotBlank()) {
                        Hub.local(lan, "")
                        LogBus.i("Net", "公网探测失败，本机内网地址 $lan")
                    } else {
                        LogBus.w("Net", "本机 IP 探测失败：既没有公网也没有内网地址")
                    }
                }
            }.onFailure { LogBus.w("Net", "本机身份探测异常：${it.message}") }
        }
    }

    /** 当前物理网络的类型（只用于日志：同一条线路 Wi-Fi 和流量经常表现完全不同）。 */
    fun transport(context: Context): String {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return "?"
        val caps = runCatching { cm.getNetworkCapabilities(cm.activeNetwork) }.getOrNull() ?: return "?"
        val kind = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "eth"
            else -> "other"
        }
        return if (cm.isActiveNetworkMetered) "$kind/metered" else kind
    }

    /** 当前物理网络上的本机 IPv4；VPN 起来之前首页显示的就是它。 */
    fun localIpv4(context: Context): String {
        runCatching {
            val cm = context.getSystemService(ConnectivityManager::class.java)
            val props: LinkProperties? = cm?.activeNetwork?.let { cm.getLinkProperties(it) }
            props?.linkAddresses?.firstOrNull { it.address is Inet4Address && !it.address.isLoopbackAddress }
                ?.let { return it.address.hostAddress ?: "" }
        }
        runCatching {
            Collections.list(NetworkInterface.getNetworkInterfaces()).forEach { nif ->
                if (!nif.isUp || nif.isLoopback) return@forEach
                nif.inetAddresses.toList().forEach { addr ->
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        return addr.hostAddress ?: ""
                    }
                }
            }
        }.onFailure { LogBus.d("Net", "读取本机 IP 失败：${it.message}") }
        return ""
    }
}
