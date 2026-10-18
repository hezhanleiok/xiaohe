package com.aether.ther.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.unit.dp
import com.aether.ther.ConnectionState
import com.aether.ther.Phase
import com.aether.ther.data.CountryCatalog
import com.aether.ther.data.LogEntry
import com.aether.ther.data.WireProtocol

@Composable
fun HomeScreen(
    state: ConnectionState,
    logs: List<LogEntry>,
    protocols: List<WireProtocol>,
    onToggle: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenLogs: () -> Unit,
    onProtocolChange: (WireProtocol) -> Unit,
    onCopyLogs: () -> Unit,
    onExportLogs: () -> Unit,
) {
    val c = LocalIos.current
    HomeBackground {
        Column(
            Modifier
                .fillMaxSize()
                .windowInsetsPadding(WindowInsets.statusBars)
                .windowInsetsPadding(WindowInsets.navigationBars)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text("xiaohe", style = IosType.largeTitle, color = c.label)
                    Text(
                        when (state.phase) {
                            Phase.Idle -> "未连接"
                            Phase.Connecting -> "正在连接…"
                            Phase.Connected -> "已连接"
                            Phase.Failed -> "连接失败"
                        },
                        style = IosType.footnote,
                        color = when (state.phase) {
                            Phase.Connected -> c.green
                            Phase.Failed -> c.red
                            Phase.Connecting -> c.orange
                            Phase.Idle -> c.secondaryLabel
                        },
                    )
                }
                Box(
                    Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(c.card)
                        .clickable { onOpenSettings() },
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(Icons.Rounded.Settings, contentDescription = "设置", tint = c.label, modifier = Modifier.size(19.dp))
                }
            }

            Spacer(Modifier.height(10.dp))
            ConnectRing(state = state, onToggle = onToggle)
            Spacer(Modifier.height(10.dp))
            ProtocolPill(current = state.protocol, protocols = protocols, onChange = onProtocolChange)
            Spacer(Modifier.height(16.dp))
            StatusCard(state = state)
            Spacer(Modifier.height(12.dp))
            LogsCard(
                logs = logs,
                onOpenLogs = onOpenLogs,
                onCopy = onCopyLogs,
                onExport = onExportLogs,
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** 圆形连接按钮：外圈呼吸/进度，内圈是可按的实体按钮。 */
@Composable
private fun ConnectRing(state: ConnectionState, onToggle: () -> Unit) {
    val c = LocalIos.current
    val accent = when (state.phase) {
        Phase.Idle -> c.blue
        Phase.Connecting -> c.orange
        Phase.Connected -> c.green
        Phase.Failed -> c.red
    }
    val transition = rememberInfiniteTransition(label = "ring")
    val rotation by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1400, easing = LinearEasing), RepeatMode.Restart),
        label = "rotation",
    )
    val breathe by transition.animateFloat(
        initialValue = 0.94f,
        targetValue = 1.03f,
        animationSpec = infiniteRepeatable(tween(1600), RepeatMode.Reverse),
        label = "breathe",
    )

    Box(
        Modifier
            .fillMaxWidth()
            .height(206.dp),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(196.dp)) {
            val r = size.minDimension / 2f
            drawCircle(color = accent.copy(alpha = 0.07f), radius = r)
            drawCircle(color = accent.copy(alpha = 0.12f), radius = r * 0.88f)
            if (state.phase == Phase.Connecting) {
                rotate(rotation) {
                    drawArc(
                        color = accent,
                        startAngle = -90f,
                        sweepAngle = 100f,
                        useCenter = false,
                        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round),
                    )
                }
            }
            if (state.isOn) {
                drawCircle(
                    color = accent.copy(alpha = 0.5f * breathe),
                    radius = r * 0.66f,
                    style = Stroke(width = 1.5.dp.toPx()),
                )
            }
        }

        Box(
            Modifier
                .size(142.dp)
                .clip(CircleShape)
                .background(Brush.radialGradient(listOf(accent, accent.copy(alpha = 0.84f))))
                .clickable { onToggle() },
            contentAlignment = Alignment.Center,
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Rounded.PowerSettingsNew,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(30.dp),
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    when (state.phase) {
                        Phase.Idle -> "连接"
                        Phase.Connecting -> "取消"
                        Phase.Connected -> "断开"
                        Phase.Failed -> "重试"
                    },
                    style = IosType.headline,
                    color = Color.White,
                )
                Text(
                    state.protocol.title,
                    style = IosType.footnote,
                    color = Color.White.copy(alpha = 0.85f),
                )
            }
        }
    }
}

@Composable
private fun ProtocolPill(
    current: WireProtocol,
    protocols: List<WireProtocol>,
    onChange: (WireProtocol) -> Unit,
) {
    val c = LocalIos.current
    var open by remember { mutableStateOf(false) }
    Box {
        Row(
            Modifier
                .clip(RoundedCornerShape(20.dp))
                .background(c.card)
                .clickable { open = true }
                .padding(horizontal = 16.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(current.title, style = IosType.headline, color = c.label)
            Spacer(Modifier.width(4.dp))
            Icon(Icons.Rounded.ExpandMore, contentDescription = "切换协议", tint = c.secondaryLabel, modifier = Modifier.size(18.dp))
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            protocols.forEach { p ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(p.title, style = IosType.body, color = c.label)
                            Text(
                                if (p.implemented) p.detail else "${p.detail} · 未接入",
                                style = IosType.footnote,
                                color = c.secondaryLabel,
                            )
                        }
                    },
                    enabled = p.implemented,
                    onClick = {
                        open = false
                        onChange(p)
                    },
                )
            }
        }
    }
}

@Composable
private fun StatusCard(state: ConnectionState) {
    val c = LocalIos.current
    IosCard {
        // 同一行：连上之前标题是「本机 IP」，连上之后同一个位置变成「出口 IP」。
        IosRow(
            title = state.ipLabel,
            value = state.displayIp.ifBlank { "—" },
        )
        IosSeparator()
        IosRow(
            title = "国家 / 地区",
            value = CountryCatalog.shortLabel(state.shownCountry).ifBlank { "—" },
        )
        IosSeparator()
        IosRow(
            title = "延迟",
            value = if (state.latencyMs >= 0) "${state.latencyMs} ms" else "—",
        )
        if (state.message.isNotBlank()) {
            IosSeparator()
            Row(Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
                Text(
                    state.message,
                    style = IosType.footnote,
                    color = if (state.phase == Phase.Failed) c.red else c.secondaryLabel,
                )
            }
        }
    }
}

@Composable
private fun LogsCard(
    logs: List<LogEntry>,
    onOpenLogs: () -> Unit,
    onCopy: () -> Unit,
    onExport: () -> Unit,
) {
    val c = LocalIos.current
    IosCard {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 8.dp, top = 10.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Rounded.Terminal, contentDescription = null, tint = c.secondaryLabel, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(6.dp))
            Text("日志", style = IosType.headline, color = c.label, modifier = Modifier.weight(1f))
            IconAction(Icons.Rounded.ContentCopy, "复制") { onCopy() }
            IconAction(Icons.Rounded.FileDownload, "导出") { onExport() }
        }
        IosSeparator()
        Box(
            Modifier
                .fillMaxWidth()
                .height(120.dp)
                .clickable { onOpenLogs() }
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            if (logs.isEmpty()) {
                Text("还没有日志", style = IosType.footnote, color = c.tertiaryLabel)
            } else {
                Text(
                    logs.takeLast(8).joinToString("\n") { it.line() },
                    style = IosType.mono,
                    color = c.secondaryLabel,
                    maxLines = 8,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.End,
        ) {
            Text(
                "查看全部 ›",
                style = IosType.footnote,
                color = c.blue,
                modifier = Modifier.clickable { onOpenLogs() },
            )
        }
    }
}

@Composable
private fun IconAction(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDescription: String,
    onClick: () -> Unit,
) {
    Box(
        Modifier
            .size(32.dp)
            .clip(RoundedCornerShape(8.dp))
            .clickable { onClick() },
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = contentDescription, tint = LocalIos.current.blue, modifier = Modifier.size(17.dp))
    }
}
