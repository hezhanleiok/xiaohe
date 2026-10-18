package com.aether.ther.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import com.aether.ther.data.CountryCatalog
import com.aether.ther.data.InstalledApp
import com.aether.ther.data.LogEntry
import com.aether.ther.data.PerAppMode
import com.aether.ther.data.CoreKind
import com.aether.ther.data.ProxyMode
import com.aether.ther.data.WireProtocol

// ---------------------------------------------------------------------------
// 通用：单选页
// ---------------------------------------------------------------------------

@Composable
fun <T> ChoiceScreen(
    title: String,
    subtitle: String?,
    options: List<T>,
    selected: T,
    label: (T) -> String,
    detail: (T) -> String?,
    onSelect: (T) -> Unit,
    onBack: () -> Unit,
    enabled: (T) -> Boolean = { true },
) {
    val c = LocalIos.current
    IosPage(title = title, subtitle = subtitle, onBack = onBack) {
        item {
            IosCard {
                options.forEachIndexed { index, option ->
                    if (index > 0) IosSeparator(startIndent = 16.dp)
                    val usable = enabled(option)
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable(enabled = usable) { onSelect(option) }
                            .padding(horizontal = 16.dp, vertical = 13.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                label(option),
                                style = IosType.body,
                                color = if (usable) c.label else c.tertiaryLabel,
                            )
                            detail(option)?.let {
                                Text(it, style = IosType.footnote, color = c.secondaryLabel)
                            }
                        }
                        if (option == selected) {
                            Icon(Icons.Rounded.Check, contentDescription = null, tint = c.blue, modifier = Modifier.size(20.dp))
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ModeScreen(selected: ProxyMode, onSelect: (ProxyMode) -> Unit, onBack: () -> Unit) = ChoiceScreen(
    title = "连接方式",
    subtitle = "谁来接住流量",
    options = ProxyMode.entries,
    selected = selected,
    label = { it.title },
    detail = { it.detail },
    onSelect = onSelect,
    onBack = onBack,
)

/** 协议列表只给出当前核心支持的项：原生看得到 WG/AWG/GOOL，Aether 看得到 MASQUE 全套。 */
@Composable
fun ProtocolScreen(
    selected: WireProtocol,
    core: CoreKind,
    onSelect: (WireProtocol) -> Unit,
    onBack: () -> Unit,
) = ChoiceScreen(
    title = "协议",
    subtitle = "${core.title} · 数据面走哪条路",
    options = WireProtocol.forCore(core),
    selected = selected,
    label = { it.title },
    detail = { if (it.implemented) it.detail else "${it.detail} · 未接入" },
    onSelect = onSelect,
    onBack = onBack,
    enabled = { it.implemented },
)

@Composable
fun CoreKindScreen(
    selected: CoreKind,
    unavailable: Set<CoreKind> = emptySet(),
    onSelect: (CoreKind) -> Unit,
    onBack: () -> Unit,
) = ChoiceScreen(
    title = "核心",
    subtitle = "谁来承载数据面",
    options = CoreKind.entries,
    selected = selected,
    label = { it.title },
    detail = { if (it in unavailable) "${it.detail} · 本次构建未内置" else it.detail },
    onSelect = onSelect,
    onBack = onBack,
    enabled = { it !in unavailable },
)

// ---------------------------------------------------------------------------
// 规则设置
// ---------------------------------------------------------------------------

@Composable
fun RulesScreen(
    urls: List<String>,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
    onAdd: (String) -> Unit,
    onRemove: (String) -> Unit,
    onBack: () -> Unit,
) {
    val c = LocalIos.current
    var input by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    IosPage(title = "规则设置", subtitle = "按网址决定直连还是走代理", onBack = onBack) {
        item {
            IosCard {
                IosSwitchRow(
                    title = "启用规则分流",
                    checked = enabled,
                    onCheckedChange = onToggle,
                )
            }
        }
        item {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = input,
                    onValueChange = {
                        input = it
                        error = null
                    },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("example.com 或 https://example.com/path", style = IosType.footnote) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Uri,
                        imeAction = ImeAction.Done,
                    ),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = c.blue,
                        unfocusedBorderColor = c.separator,
                    ),
                )
                Spacer(Modifier.width(8.dp))
                Box(
                    Modifier
                        .size(48.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(c.blue)
                        .clickable {
                            val normalized = normalizeUrl(input)
                            when {
                                normalized == null -> error = "填一个网址，例如 example.com"
                                urls.contains(normalized) -> error = "这条已经在列表里了"
                                else -> {
                                    onAdd(normalized)
                                    input = ""
                                }
                            }
                        },
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Rounded.Add, contentDescription = "添加", tint = androidx.compose.ui.graphics.Color.White)
                }
            }
            error?.let {
                Text(it, style = IosType.footnote, color = c.red, modifier = Modifier.padding(start = 4.dp, top = 6.dp))
            }
        }
        item { SectionHeader("已添加 ${urls.size} 条") }
        if (urls.isEmpty()) {
            item {
                IosCard {
                    Box(Modifier.fillMaxWidth().padding(16.dp)) {
                        Text(
                            "还没有网址规则。加上之后，命中的网址走代理，其余按连接方式处理。",
                            style = IosType.footnote,
                            color = c.secondaryLabel,
                        )
                    }
                }
            }
        } else {
            item {
                IosCard {
                    urls.forEachIndexed { index, url ->
                        if (index > 0) IosSeparator()
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(start = 16.dp, end = 8.dp, top = 12.dp, bottom = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                url,
                                style = IosType.body,
                                color = c.label,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f),
                            )
                            Box(
                                Modifier
                                    .size(34.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable { onRemove(url) },
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(Icons.Rounded.Delete, contentDescription = "删除", tint = c.red, modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

/** 输入容错：允许带协议与路径，只保留 host（规则按域名匹配）。 */
private fun normalizeUrl(raw: String): String? {
    val s = raw.trim()
    if (s.isBlank()) return null
    val host = s.removePrefix("https://").removePrefix("http://").substringBefore('/').substringBefore(':')
    if (host.isBlank() || !host.contains('.')) return null
    if (host.any { it.isWhitespace() }) return null
    return host.lowercase()
}

// ---------------------------------------------------------------------------
// 分应用设置
// ---------------------------------------------------------------------------

@Composable
fun AppPickerScreen(
    apps: List<InstalledApp>,
    selected: Set<String>,
    enabled: Boolean,
    mode: PerAppMode,
    onToggleEnabled: (Boolean) -> Unit,
    onModeChange: (PerAppMode) -> Unit,
    onToggleApp: (String) -> Unit,
    onBack: () -> Unit,
) {
    val c = LocalIos.current
    var query by remember { mutableStateOf("") }
    val filtered = remember(apps, query) {
        if (query.isBlank()) apps
        else apps.filter { it.label.contains(query, true) || it.pkg.contains(query, true) }
    }

    IosPage(
        title = "分应用设置",
        subtitle = "选择哪些应用走代理",
        onBack = onBack,
    ) {
        item {
            IosCard {
                IosSwitchRow(
                    title = "启用分应用分流",
                    subtitle = "关闭时全部应用按连接方式处理",
                    checked = enabled,
                    onCheckedChange = onToggleEnabled,
                )
                IosSeparator(startIndent = 16.dp)
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    PerAppMode.entries.forEach { m ->
                        val on = m == mode
                        Box(
                            Modifier
                                .weight(1f)
                                .padding(end = 8.dp)
                                .clip(RoundedCornerShape(9.dp))
                                .background(if (on) c.blue else c.fill)
                                .clickable { onModeChange(m) }
                                .padding(vertical = 8.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                m.title,
                                style = IosType.footnote,
                                color = if (on) androidx.compose.ui.graphics.Color.White else c.label,
                            )
                        }
                    }
                }
            }
        }

        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 14.dp),
                placeholder = { Text("搜索应用", style = IosType.footnote) },
                leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null, tint = c.secondaryLabel) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = c.blue,
                    unfocusedBorderColor = c.separator,
                ),
            )
        }

        item { SectionHeader("已安装应用 ${filtered.size}") }
        item {
            IosCard {
                if (filtered.isEmpty()) {
                    Box(Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("没有匹配的应用（列表加载中或系统限制）", style = IosType.footnote, color = c.secondaryLabel)
                    }
                } else {
                    filtered.forEachIndexed { index, app ->
                        if (index > 0) IosSeparator(startIndent = 56.dp)
                        AppRow(
                            app = app,
                            checked = selected.contains(app.pkg),
                            onToggle = { onToggleApp(app.pkg) },
                        )
                    }
                }
            }
        }
        item { Spacer(Modifier.height(24.dp)) }
    }
}

@Composable
private fun AppRow(app: InstalledApp, checked: Boolean, onToggle: () -> Unit) {
    val c = LocalIos.current
    val bitmap = remember(app.pkg) {
        runCatching { app.icon?.toBitmap(96, 96)?.asImageBitmap() }.getOrNull()
    }
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onToggle() }
            .padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (bitmap != null) {
            Image(
                bitmap = bitmap,
                contentDescription = null,
                modifier = Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(8.dp)),
            )
        } else {
            Box(
                Modifier
                    .size(34.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .background(c.fill)
            )
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                app.label,
                style = IosType.body,
                color = c.label,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                if (app.system) "${app.pkg} · 系统" else app.pkg,
                style = IosType.footnote,
                color = c.secondaryLabel,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Checkbox(
            checked = checked,
            onCheckedChange = { onToggle() },
            colors = CheckboxDefaults.colors(
                checkedColor = c.blue,
                uncheckedColor = c.tertiaryLabel,
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

@Composable
fun LogsScreen(
    logs: List<LogEntry>,
    onCopy: () -> Unit,
    onExport: () -> Unit,
    onClear: () -> Unit,
    onBack: () -> Unit,
) {
    val c = LocalIos.current
    IosPage(
        title = "日志",
        subtitle = "共 ${logs.size} 条 · 重启不会清除，点垃圾桶才删",
        onBack = onBack,
        trailing = {
            Row {
                Icon(
                    Icons.Rounded.ContentCopy,
                    contentDescription = "复制",
                    tint = c.blue,
                    modifier = Modifier
                        .size(24.dp)
                        .clickable { onCopy() },
                )
                Spacer(Modifier.width(14.dp))
                Icon(
                    Icons.Rounded.FileDownload,
                    contentDescription = "导出",
                    tint = c.blue,
                    modifier = Modifier
                        .size(24.dp)
                        .clickable { onExport() },
                )
                Spacer(Modifier.width(14.dp))
                Icon(
                    Icons.Rounded.Delete,
                    contentDescription = "清空",
                    tint = c.red,
                    modifier = Modifier
                        .size(24.dp)
                        .clickable { onClear() },
                )
            }
        },
    ) {
        item {
            IosCard {
                if (logs.isEmpty()) {
                    Box(Modifier.fillMaxWidth().padding(16.dp)) {
                        Text("还没有日志", style = IosType.footnote, color = c.secondaryLabel)
                    }
                } else {
                    Column(Modifier.padding(12.dp)) {
                        logs.takeLast(400).forEach { entry ->
                            Text(
                                entry.line(),
                                style = IosType.mono,
                                color = when (entry.level) {
                                    "ERROR" -> c.red
                                    "WARN" -> c.orange
                                    else -> c.secondaryLabel
                                },
                            )
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 版本更新
// ---------------------------------------------------------------------------

@Composable
fun UpdateScreen(
    currentVersion: String,
    repo: String,
    note: String,
    busy: Boolean,
    onRepoChange: (String) -> Unit,
    onCheck: () -> Unit,
    onOpenRepo: () -> Unit,
    onBack: () -> Unit,
) {
    val c = LocalIos.current
    var input by remember { mutableStateOf(repo) }
    IosPage(title = "版本更新", subtitle = "从 GitHub 仓库获取最新版本", onBack = onBack) {
        item {
            IosCard {
                IosValueRow("当前版本", currentVersion)
                IosSeparator()
                IosValueRow("更新源", "GitHub Releases")
            }
        }
        item { SectionHeader("仓库地址（占位符，待替换）") }
        item {
            Column {
                OutlinedTextField(
                    value = input,
                    onValueChange = {
                        input = it
                        onRepoChange(it)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    placeholder = { Text("https://github.com/OWNER/REPO", style = IosType.footnote) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = c.blue,
                        unfocusedBorderColor = c.separator,
                    ),
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "换成真实仓库后，「检查更新」会读取 latest release 的版本号与资产。",
                    style = IosType.footnote,
                    color = c.secondaryLabel,
                )
            }
        }
        item {
            Spacer(Modifier.height(16.dp))
            PrimaryButton(text = if (busy) "检查中…" else "检查更新", enabled = !busy, onClick = onCheck)
            Spacer(Modifier.height(10.dp))
            SecondaryButton(text = "在浏览器中打开仓库", onClick = onOpenRepo)
        }
        if (note.isNotBlank()) {
            item {
                Spacer(Modifier.height(14.dp))
                IosCard {
                    Box(Modifier.fillMaxWidth().padding(14.dp)) {
                        Text(note, style = IosType.footnote, color = c.label)
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 出口地区
// ---------------------------------------------------------------------------

@Composable
fun ExitRegionScreen(
    regions: List<String>,
    selected: String,
    onSelect: (String) -> Unit,
    onBack: () -> Unit,
) {
    val c = LocalIos.current
    val list = remember(regions) { (if (regions.isEmpty()) CountryCatalog.psiphonFallback else regions).distinct().sorted() }
    IosPage(
        title = "出口地区",
        subtitle = "列表来自赛风上报的可用地区",
        onBack = onBack,
    ) {
        item {
            IosCard {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable { onSelect("") }
                        .padding(horizontal = 16.dp, vertical = 13.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("自动（由赛风决定）", style = IosType.body, color = c.label, modifier = Modifier.weight(1f))
                    if (selected.isBlank()) {
                        Icon(Icons.Rounded.Check, contentDescription = null, tint = c.blue, modifier = Modifier.size(20.dp))
                    }
                }
            }
        }
        item { SectionHeader("国家 / 地区") }
        item {
            IosCard {
                list.forEachIndexed { index, iso ->
                    if (index > 0) IosSeparator()
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(iso) }
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(CountryCatalog.flag(iso), style = IosType.body)
                        Spacer(Modifier.width(10.dp))
                        Text(
                            CountryCatalog.englishName(iso),
                            style = IosType.body,
                            color = c.label,
                            modifier = Modifier.weight(1f),
                        )
                        Text(iso, style = IosType.footnote, color = c.secondaryLabel)
                        if (selected.equals(iso, true)) {
                            Spacer(Modifier.width(8.dp))
                            Icon(Icons.Rounded.Check, contentDescription = null, tint = c.blue, modifier = Modifier.size(20.dp))
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 关于
// ---------------------------------------------------------------------------

@Composable
fun AboutScreen(version: String, onBack: () -> Unit) {
    val c = LocalIos.current
    IosPage(title = "关于", onBack = onBack) {
        item {
            Column(
                Modifier
                    .fillMaxWidth()
                    .padding(vertical = 18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Box(
                    Modifier
                        .size(72.dp)
                        .clip(RoundedCornerShape(18.dp))
                        .background(c.blue),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("彼", style = IosType.largeTitle, color = androidx.compose.ui.graphics.Color.White)
                }
                Spacer(Modifier.height(10.dp))
                Text("彼岸 · Ther", style = IosType.title, color = c.label)
                Text("版本 $version", style = IosType.footnote, color = c.secondaryLabel)
            }
        }
        item {
            IosCard {
                IosValueRow("连接方式", "系统代理 / VPN / Tun")
                IosSeparator()
                IosValueRow("核心", "原生核心 + Aether 核心")
                IosSeparator()
                IosValueRow("出口", "Aether / 赛风")
                IosSeparator()
                IosValueRow("开源许可", "见仓库 THIRD-PARTY-NOTICES")
            }
        }
        item {
            Spacer(Modifier.height(12.dp))
            Text(
                "本应用只做流量转发，不收集任何个人信息；日志保存在应用私有目录，可随时清空。",
                style = IosType.footnote,
                color = c.secondaryLabel,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// 按钮
// ---------------------------------------------------------------------------

@Composable
fun PrimaryButton(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    val c = LocalIos.current
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(if (enabled) c.blue else c.fill)
            .clickable(enabled = enabled) { onClick() }
            .padding(vertical = 14.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = IosType.headline, color = if (enabled) androidx.compose.ui.graphics.Color.White else c.secondaryLabel)
    }
}

@Composable
fun SecondaryButton(text: String, onClick: () -> Unit) {
    val c = LocalIos.current
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(c.fill)
            .clickable { onClick() }
            .padding(vertical = 14.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = IosType.headline, color = c.blue)
    }
}
