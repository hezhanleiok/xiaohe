package com.aether.ther

import android.app.Application
import com.aether.ther.data.CoreKind
import com.aether.ther.data.LogBus
import com.aether.ther.data.ProxyMode
import com.aether.ther.data.SettingsStore
import com.aether.ther.net.NetInfo

class TherApp : Application() {
    override fun onCreate() {
        super.onCreate()
        LogBus.init(this)
        installCrashHandler()
        val s = SettingsStore.load(this)
        LogBus.i("App", "彼岸启动 · version=${BuildConfig.VERSION_NAME}(${BuildConfig.VERSION_CODE})")
        LogBus.i("App", "当前设置：mode=${s.mode.id} protocol=${s.protocol.id} psiphon=${s.psiphonExit} region=${s.exitRegion.ifBlank { "auto" }}")
        // 存档里可能留着上一版本的 psiphon=true：那时原生核心会静默忽略它，出口实际
        // 还是 WARP。启动就说清楚，别让人对着「已开启」的开关查为什么出口没变。
        if (s.psiphonExit && s.core != CoreKind.Aether) {
            LogBus.w("App", "赛风出口需要 Aether 核心，当前核心=${s.core.id} 不使用该设置（开关已置灰）")
        }
        // 首屏那两行（本机 IP / 国家地区）不能等连接才有值：启动就直连探一次。
        NetInfo.refreshLocalIdentity(this)
    }

    /**
     * 把 Java 层的未捕获异常也落到日志文件里。
     *
     * 原生崩溃（SIGSEGV / Go panic）走不到这里，但那种情况下日志文件里会停在上
     * 一条记录的下一行，同样能定位。两者都靠 [LogBus] 的落盘兜住。
     */
    private fun installCrashHandler() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            runCatching {
                LogBus.e("Crash", "未捕获异常（线程 ${thread.name}）：${error.stackTraceToString()}")
            }
            previous?.uncaughtException(thread, error)
        }
    }
}
