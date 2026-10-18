package com.aether.ther.ui

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Layers
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.SettingsEthernet
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.SystemUpdate
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.aether.ther.data.AppSettings
import com.aether.ther.data.CountryCatalog
import com.aether.ther.data.PerAppMode
import com.aether.ther.data.ProxyMode

@Composable
fun SettingsScreen(
    settings: AppSettings,
    /** 赛风出口是否真的可用（= Aether 核心在位）。false 时开关置灰并说明原因。 */
    psiphonAvailable: Boolean,
    update: (AppSettings) -> Unit,
    onOpenMode: () -> Unit,
    onOpenProtocol: () -> Unit,
    onOpenCoreKind: () -> Unit,
    onOpenRules: () -> Unit,
    onOpenApps: () -> Unit,
    onOpenExitRegion: () -> Unit,
    onOpenUpdate: () -> Unit,
    onOpenLogs: () -> Unit,
    onOpenAbout: () -> Unit,
    onBack: () -> Unit,
) {
    val c = LocalIos.current
    IosPage(title = "设置", onBack = onBack) {
        item { SectionHeader("网络") }
        item {
            IosCard {
                IosRow(
                    title = "连接方式",
                    subtitle = settings.mode.detail,
                    value = settings.mode.title,
                    icon = Icons.Rounded.SettingsEthernet,
                    iconTint = c.blue,
                    showChevron = true,
                    onClick = onOpenMode,
                )
                IosSeparator(startIndent = 56.dp)
                IosRow(
                    title = "协议",
                    subtitle = settings.protocol.detail,
                    value = settings.protocol.title,
                    icon = Icons.Rounded.Layers,
                    iconTint = c.purple,
                    showChevron = true,
                    onClick = onOpenProtocol,
                )
            }
        }

        item { SectionHeader("核心") }
        item {
            IosCard {
                IosRow(
                    title = "核心",
                    subtitle = settings.core.detail,
                    value = settings.core.title,
                    icon = Icons.Rounded.Memory,
                    iconTint = c.purple,
                    showChevron = true,
                    onClick = onOpenCoreKind,
                )
            }
        }

        item { SectionHeader("出口") }
        item {
            // 两种核心都能承载 Psiphon：Aether 核心是「隧道内第二跳」，原生核心是
            // 「原生隧道里的第二跳」。唯一的前提是随包发布的 psiphon 组件在位。
            val psiphonOn = psiphonAvailable && settings.psiphonExit
            IosCard {
                IosSwitchRow(
                    title = "Psiphon 出口",
                    subtitle = if (psiphonAvailable) {
                        "最后一跳交给 Psiphon；Tor 出口已移除"
                    } else {
                        "内置的 Psiphon 组件缺失（重装应用）"
                    },
                    checked = psiphonOn,
                    onCheckedChange = { update(settings.copy(psiphonExit = it)) },
                    enabled = psiphonAvailable,
                )
                IosSeparator(startIndent = 16.dp)
                IosRow(
                    title = "出口地区",
                    subtitle = when {
                        !psiphonAvailable -> "Psiphon 不可用时无法选择"
                        psiphonOn -> "由 Psiphon 上报的可用地区"
                        else -> "开启 Psiphon 出口后可选"
                    },
                    value = CountryCatalog.label(settings.exitRegion),
                    icon = Icons.Rounded.Language,
                    iconTint = c.green,
                    showChevron = psiphonOn,
                    onClick = if (psiphonOn) onOpenExitRegion else null,
                )
            }
        }

        item { SectionHeader("分流") }
        item {
            IosCard {
                IosSwitchRow(
                    title = "规则分流",
                    subtitle = "按网址决定直连还是走代理",
                    checked = settings.rulesEnabled,
                    onCheckedChange = { update(settings.copy(rulesEnabled = it)) },
                )
                IosSeparator(startIndent = 16.dp)
                IosRow(
                    title = "规则设置",
                    subtitle = if (settings.ruleUrls.isEmpty()) "还没有网址规则" else "${settings.ruleUrls.size} 条网址规则",
                    icon = Icons.Rounded.Dns,
                    iconTint = c.blue,
                    showChevron = true,
                    onClick = onOpenRules,
                )
                IosSeparator(startIndent = 56.dp)
                IosRow(
                    title = "分应用设置",
                    subtitle = when {
                        !settings.perAppEnabled -> "全部应用走代理"
                        settings.perAppMode == PerAppMode.Only -> "仅 ${settings.perAppPackages.size} 个应用走代理"
                        else -> "${settings.perAppPackages.size} 个应用直连，其余走代理"
                    },
                    icon = Icons.Rounded.Shield,
                    iconTint = c.purple,
                    showChevron = true,
                    onClick = onOpenApps,
                )
            }
        }

        item { SectionHeader("其它") }
        item {
            IosCard {
                IosRow(
                    title = "版本更新",
                    subtitle = "从 GitHub 仓库检查新版本",
                    icon = Icons.Rounded.SystemUpdate,
                    iconTint = c.orange,
                    showChevron = true,
                    onClick = onOpenUpdate,
                )
                IosSeparator(startIndent = 56.dp)
                IosRow(
                    title = "日志",
                    icon = Icons.Rounded.Terminal,
                    iconTint = c.secondaryLabel,
                    showChevron = true,
                    onClick = onOpenLogs,
                )
                IosSeparator(startIndent = 56.dp)
                IosRow(
                    title = "关于",
                    icon = Icons.Rounded.Info,
                    iconTint = c.secondaryLabel,
                    showChevron = true,
                    onClick = onOpenAbout,
                )
            }
        }
        item { Spacer(Modifier.height(20.dp)) }
    }
}
