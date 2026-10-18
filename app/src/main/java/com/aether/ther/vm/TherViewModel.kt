package com.aether.ther.vm

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aether.ther.Hub
import com.aether.ther.core.UpdateChecker
import com.aether.ther.data.AppCatalog
import com.aether.ther.data.AppSettings
import com.aether.ther.data.InstalledApp
import com.aether.ther.data.LogBus
import com.aether.ther.data.CoreKind
import com.aether.ther.data.ProxyMode
import com.aether.ther.data.SettingsStore
import com.aether.ther.data.WireProtocol
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 界面状态的唯一持有者。
 *
 * 连接本身在 [com.aether.ther.vpn.TherVpnService] 里跑，这里只负责：改设置、
 * 拉应用列表、触发更新检查，以及把 Hub / LogBus 的流暴露给 Compose。
 */
class TherViewModel(app: Application) : AndroidViewModel(app) {

    private val _settings = MutableStateFlow(SettingsStore.load(app))
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    val connection = Hub.state
    val logs = LogBus.entries

    private val _apps = MutableStateFlow<List<InstalledApp>>(emptyList())
    val apps: StateFlow<List<InstalledApp>> = _apps.asStateFlow()

    private val _note = MutableStateFlow("")
    val note: StateFlow<String> = _note.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    fun update(block: (AppSettings) -> AppSettings) {
        val next = block(_settings.value)
        SettingsStore.save(getApplication(), next)
        _settings.value = next
        LogBus.d("Settings", "设置已更新：mode=${next.mode.id} protocol=${next.protocol.id} psiphon=${next.psiphonExit} region=${next.exitRegion.ifBlank { "auto" }}")
    }

    /**
     * 换协议：协议自己带着它归属的核心，所以 core 跟着一起改。
     * 手机端没有独立的「Warp-in-Warp」开关，双层 MASQUE 就是协议列表里的一项。
     */
    fun setProtocol(protocol: WireProtocol) = update {
        it.copy(protocol = protocol, core = protocol.core)
    }

    /** 换核心：旧协议若不属于新核心，回落到该核心的第一项。 */
    fun setCore(core: CoreKind) = update {
        val p = if (it.protocol.core == core) it.protocol else WireProtocol.defaultFor(core)
        it.copy(core = core, protocol = p)
    }

    fun toggleApp(pkg: String) = update {
        val next = if (it.perAppPackages.contains(pkg)) it.perAppPackages - pkg else it.perAppPackages + pkg
        it.copy(perAppPackages = next, perAppEnabled = true)
    }

    fun addRule(url: String) = update { it.copy(ruleUrls = it.ruleUrls + url, rulesEnabled = true) }

    fun removeRule(url: String) = update { it.copy(ruleUrls = it.ruleUrls - url) }

    fun loadApps() {
        if (_apps.value.isNotEmpty()) return
        viewModelScope.launch {
            val loaded = AppCatalog.load(getApplication())
            _apps.value = loaded
            LogBus.i("Apps", "已识别 ${loaded.size} 个可启动应用")
        }
    }

    fun checkUpdate() {
        if (_busy.value) return
        viewModelScope.launch {
            _busy.value = true
            _note.value = ""
            val repo = _settings.value.updateRepo
            val result = UpdateChecker.latest(repo)
            _note.value = result.fold(
                onSuccess = { info ->
                    val current = com.aether.ther.BuildConfig.VERSION_NAME
                    if (UpdateChecker.isNewer(info.tag, current)) {
                        "发现新版本 ${info.tag}（当前 $current）\n发布时间：${info.publishedAt.take(10)}\n资产：${
                            info.assets.joinToString { it.name }.ifBlank { "无" }
                        }\n\n${info.notes.take(400)}"
                    } else {
                        "已是最新版本（当前 $current，远端 ${info.tag}）"
                    }
                },
                onFailure = { it.message ?: "检查失败" },
            )
            _busy.value = false
        }
    }

    fun setMode(mode: ProxyMode) = update { it.copy(mode = mode) }
}
