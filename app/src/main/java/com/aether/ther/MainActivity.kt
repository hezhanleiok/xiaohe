package com.aether.ther

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.core.content.FileProvider
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aether.ther.core.AetherCore
import com.aether.ther.data.CoreKind
import com.aether.ther.data.CountryCatalog
import com.aether.ther.data.LogBus
import com.aether.ther.data.ProxyMode
import com.aether.ther.data.SettingsStore
import com.aether.ther.data.WireProtocol
import com.aether.ther.ui.AboutScreen
import com.aether.ther.ui.AppPickerScreen
import com.aether.ther.ui.CoreKindScreen
import com.aether.ther.ui.ExitRegionScreen
import com.aether.ther.ui.HomeScreen
import com.aether.ther.ui.IosTheme
import com.aether.ther.ui.LogsScreen
import com.aether.ther.ui.ModeScreen
import com.aether.ther.ui.ProtocolScreen
import com.aether.ther.ui.RulesScreen
import com.aether.ther.ui.SettingsScreen
import com.aether.ther.ui.UpdateScreen
import com.aether.ther.vm.TherViewModel
import com.aether.ther.vpn.TherVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** 页面栈用最简单的形式：一个枚举 + 一个 List。 */
enum class Route { Home, Settings, Mode, Protocol, CoreKind, Rules, Apps, Logs, Update, ExitRegion, About }

class MainActivity : ComponentActivity() {

    private var pendingMode: ProxyMode? = null

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val mode = pendingMode
        pendingMode = null
        if (result.resultCode == RESULT_OK && mode != null) {
            TherVpnService.start(this, mode)
        } else {
            LogBus.w("App", "用户拒绝了 VPN 授权")
            Hub.failed("没有 VPN 授权，无法建立隧道")
        }
    }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (!granted) LogBus.w("App", "通知权限被拒绝：前台服务通知可能不可见")
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            IosTheme {
                AppRoot(
                    onConnect = ::connect,
                    onDisconnect = {
                        TherVpnService.stop(this)
                        Hub.idle()
                    },
                )
            }
        }
    }

    private fun connect(mode: ProxyMode) {
        if (mode == ProxyMode.System) {
            // 系统代理模式不需要 VpnService 授权
            TherVpnService.start(this, mode)
            return
        }
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingMode = mode
            vpnPermission.launch(intent)
        } else {
            TherVpnService.start(this, mode)
        }
    }
}

@Composable
private fun AppRoot(onConnect: (ProxyMode) -> Unit, onDisconnect: () -> Unit) {
    val vm: TherViewModel = viewModel()
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()

    val settings by vm.settings.collectAsState()
    val connection by vm.connection.collectAsState()
    val logs by vm.logs.collectAsState()
    val apps by vm.apps.collectAsState()
    val note by vm.note.collectAsState()
    val busy by vm.busy.collectAsState()

    val stack = remember { mutableStateListOf(Route.Home) }
    val current = stack.last()
    fun push(route: Route) = stack.add(route)
    fun pop() {
        if (stack.size > 1) stack.removeAt(stack.lastIndex)
    }

    // 返回键：弹栈，回到首页后交还系统
    androidx.activity.compose.BackHandler(enabled = stack.size > 1) { pop() }

    fun copyLogs() {
        val text = LogBus.exportText()
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("彼岸日志", text))
        Toast.makeText(ctx, "日志已复制（${text.lines().size} 行）", Toast.LENGTH_SHORT).show()
    }

    fun exportLogs() {
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching {
                    val dir = File(ctx.cacheDir, "exports").apply { mkdirs() }
                    val f = File(dir, "ther-${System.currentTimeMillis()}.log")
                    f.writeText(LogBus.exportText())
                    val uri: Uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.fileprovider", f)
                    val share = Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_STREAM, uri)
                        putExtra(Intent.EXTRA_SUBJECT, "彼岸日志")
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    ctx.startActivity(Intent.createChooser(share, "导出日志"))
                    true
                }.getOrElse { false }
            }
            if (!ok) Toast.makeText(ctx, "导出失败（见日志）", Toast.LENGTH_SHORT).show()
        }
    }

    // Hub 里的 protocol 只在真正发起连接时写入；未连接时首页那颗按钮要显示
    // 「设置里选中的协议」，否则刚改完协议回到首页还是旧的。
    val homeState =
        if (connection.phase == Phase.Connected || connection.phase == Phase.Connecting) connection
        else connection.copy(protocol = settings.protocol)

    when (current) {
        Route.Home -> HomeScreen(
            state = homeState,
            logs = logs,
            protocols = WireProtocol.forCore(settings.core),
            onToggle = {
                when (connection.phase) {
                    Phase.Connected, Phase.Connecting -> onDisconnect()
                    else -> onConnect(settings.mode)
                }
            },
            onOpenSettings = { push(Route.Settings) },
            onOpenLogs = { push(Route.Logs) },
            onProtocolChange = { vm.setProtocol(it) },
            onCopyLogs = { copyLogs() },
            onExportLogs = { exportLogs() },
        )

        Route.Settings -> {
            // Psiphon 需要随包发布的 aether 二进制来承载（原生核心模式下用它跑
            // --psiphon-only）：二进制不在位时开关才置灰，和选的是哪种核心无关。
            val psiphonReady = remember { AetherCore(ctx).isAvailable() }
            SettingsScreen(
                settings = settings,
                psiphonAvailable = psiphonReady,
                update = { next -> vm.update { next } },
                onOpenMode = { push(Route.Mode) },
                onOpenProtocol = { push(Route.Protocol) },
                onOpenCoreKind = { push(Route.CoreKind) },
                onOpenRules = { push(Route.Rules) },
                onOpenApps = {
                    vm.loadApps()
                    push(Route.Apps)
                },
                onOpenExitRegion = { push(Route.ExitRegion) },
                onOpenUpdate = { push(Route.Update) },
                onOpenLogs = { push(Route.Logs) },
                onOpenAbout = { push(Route.About) },
                onBack = { pop() },
            )
        }

        Route.Mode -> ModeScreen(
            selected = settings.mode,
            onSelect = {
                vm.setMode(it)
                pop()
            },
            onBack = { pop() },
        )

        Route.Protocol -> ProtocolScreen(
            selected = settings.protocol,
            core = settings.core,
            onSelect = {
                vm.setProtocol(it)
                pop()
            },
            onBack = { pop() },
        )

        Route.CoreKind -> {
            // 核心二进制随整包发布：没有内置就不该让用户以为选上就能用。
            val aetherReady = remember { AetherCore(ctx).isAvailable() }
            CoreKindScreen(
                selected = settings.core,
                unavailable = if (aetherReady) emptySet() else setOf(CoreKind.Aether),
                onSelect = {
                    vm.setCore(it)
                    pop()
                },
                onBack = { pop() },
            )
        }

        Route.Rules -> RulesScreen(
            urls = settings.ruleUrls,
            enabled = settings.rulesEnabled,
            onToggle = { on -> vm.update { it.copy(rulesEnabled = on) } },
            onAdd = { vm.addRule(it) },
            onRemove = { vm.removeRule(it) },
            onBack = { pop() },
        )

        Route.Apps -> AppPickerScreen(
            apps = apps,
            selected = settings.perAppPackages,
            enabled = settings.perAppEnabled,
            mode = settings.perAppMode,
            onToggleEnabled = { on -> vm.update { it.copy(perAppEnabled = on) } },
            onModeChange = { m -> vm.update { it.copy(perAppMode = m) } },
            onToggleApp = { vm.toggleApp(it) },
            onBack = { pop() },
        )

        Route.Logs -> LogsScreen(
            logs = logs,
            onCopy = { copyLogs() },
            onExport = { exportLogs() },
            onClear = {
                LogBus.clear()
                LogBus.i("App", "日志已清空")
            },
            onBack = { pop() },
        )

        Route.Update -> UpdateScreen(
            currentVersion = BuildConfig.VERSION_NAME,
            repo = settings.updateRepo,
            note = note,
            busy = busy,
            onRepoChange = { repo -> vm.update { s -> s.copy(updateRepo = repo) } },
            onCheck = { vm.checkUpdate() },
            onOpenRepo = {
                runCatching {
                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(settings.updateRepo)))
                }
            },
            onBack = { pop() },
        )

        Route.ExitRegion -> ExitRegionScreen(
            regions = CountryCatalog.psiphonFallback,
            selected = settings.exitRegion,
            onSelect = { iso ->
                vm.update { s -> s.copy(exitRegion = iso) }
                pop()
            },
            onBack = { pop() },
        )

        Route.About -> AboutScreen(version = BuildConfig.VERSION_NAME, onBack = { pop() })
    }
}
