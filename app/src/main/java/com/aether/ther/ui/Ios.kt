package com.aether.ther.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBackIosNew
import androidx.compose.material.icons.rounded.ChevronRight
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ---------------------------------------------------------------------------
// 主题：iOS 的「分组列表」语法 —— 浅灰底、白色圆角卡片、内缩分隔线、
// 蓝色强调色、绿色开关。深色模式跟随系统。
// ---------------------------------------------------------------------------

@androidx.compose.runtime.Immutable
data class IosColors(
    val groupedBg: Color,
    val card: Color,
    val fill: Color,
    val label: Color,
    val secondaryLabel: Color,
    val tertiaryLabel: Color,
    val separator: Color,
    val blue: Color,
    val green: Color,
    val orange: Color,
    val red: Color,
    val purple: Color,
)

val IosLight = IosColors(
    groupedBg = Color(0xFFF2F2F7),
    card = Color(0xFFFFFFFF),
    fill = Color(0xFFE9E9EE),
    label = Color(0xFF000000),
    secondaryLabel = Color(0xFF8E8E93),
    tertiaryLabel = Color(0xFFC7C7CC),
    separator = Color(0xFFD8D8DE),
    blue = Color(0xFF0A84FF),
    green = Color(0xFF34C759),
    orange = Color(0xFFFF9F0A),
    red = Color(0xFFFF3B30),
    purple = Color(0xFF5E5CE6),
)

val IosDark = IosColors(
    groupedBg = Color(0xFF000000),
    card = Color(0xFF1C1C1E),
    fill = Color(0xFF2C2C2E),
    label = Color(0xFFFFFFFF),
    secondaryLabel = Color(0xFF8E8E93),
    tertiaryLabel = Color(0xFF48484A),
    separator = Color(0xFF38383A),
    blue = Color(0xFF0A84FF),
    green = Color(0xFF30D158),
    orange = Color(0xFFFF9F0A),
    red = Color(0xFFFF453A),
    purple = Color(0xFF5E5CE6),
)

val LocalIos = staticCompositionLocalOf { IosLight }

@Composable
fun IosTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) IosDark else IosLight
    CompositionLocalProvider(LocalIos provides colors, content = content)
}

// 常用文本样式
// 必须是具名的 object：匿名 object 类型只有本文件可见，跨文件引用会出现
// "Unresolved reference 'body'" —— 这些样式正是跨文件用的。
object IosType {
    // 34sp 是 iOS 大标题的标准值，但手机竖屏 + 中文时它会把一行占满，
    // 再用 34 会顶到状态栏下面显得比例失真，这里收到 28。
    val largeTitle = TextStyle(fontSize = 28.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.3).sp)
    val title = TextStyle(fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
    val headline = TextStyle(fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
    val body = TextStyle(fontSize = 17.sp, fontWeight = FontWeight.Normal)
    val footnote = TextStyle(fontSize = 13.sp, fontWeight = FontWeight.Normal)
    val sectionHeader = TextStyle(fontSize = 13.sp, fontWeight = FontWeight.Normal)
    val mono = TextStyle(fontSize = 11.sp, fontFamily = FontFamily.Monospace, lineHeight = 15.sp)
}

// ---------------------------------------------------------------------------
// 基础容器
// ---------------------------------------------------------------------------

@Composable
fun ScreenBackground(content: @Composable () -> Unit) {
    val c = LocalIos.current
    Box(
        Modifier
            .fillMaxSize()
            .background(c.groupedBg)
    ) { content() }
}

/**
 * 页面骨架：大标题 + 可选返回键 + 滚动内容。
 * iOS 的导航栏是「标题跟着内容滚动」，这里用固定头 + 列表内边距近似。
 */
@Composable
fun IosPage(
    title: String,
    onBack: (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
    subtitle: String? = null,
    content: LazyListScope.() -> Unit,
) {
    val c = LocalIos.current
    ScreenBackground {
        Column(
            Modifier
                .fillMaxSize()
                // 内容必须让开状态栏/挖孔，否则大标题会被顶到屏幕外（截图里
                // 「彼岸」贴着顶部就是这个原因）。
                .windowInsetsPadding(WindowInsets.statusBars)
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(start = 20.dp, end = 16.dp, top = 10.dp, bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (onBack != null) {
                    Icon(
                        imageVector = Icons.Rounded.ArrowBackIosNew,
                        contentDescription = "返回",
                        tint = c.blue,
                        modifier = Modifier
                            .size(22.dp)
                            .clip(CircleShape)
                            .clickable { onBack() }
                            .padding(2.dp),
                    )
                    Spacer(Modifier.width(10.dp))
                }
                Column(Modifier.weight(1f)) {
                    Text(title, style = IosType.largeTitle, color = c.label)
                    if (subtitle != null) {
                        Text(subtitle, style = IosType.footnote, color = c.secondaryLabel)
                    }
                }
                trailing?.invoke()
            }
            LazyColumn(
                Modifier
                    .fillMaxSize()
                    .windowInsetsPadding(WindowInsets.navigationBars),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(0.dp),
                content = content,
            )
        }
    }
}

/** 分组标题（灰字小写大写字距）。 */
@Composable
fun SectionHeader(text: String, modifier: Modifier = Modifier) {
    val c = LocalIos.current
    Text(
        text.uppercase(),
        style = IosType.sectionHeader,
        color = c.secondaryLabel,
        modifier = modifier.padding(start = 16.dp, top = 22.dp, bottom = 7.dp),
    )
}

/** 白色圆角卡片；children 之间由调用方决定是否画分隔线。 */
@Composable
fun IosCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    val c = LocalIos.current
    Column(
        modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(c.card),
        content = content,
    )
}

@Composable
fun IosSeparator(startIndent: androidx.compose.ui.unit.Dp = 16.dp) {
    val c = LocalIos.current
    Box(
        Modifier
            .fillMaxWidth()
            .padding(start = startIndent)
            .height(0.6.dp)
            .background(c.separator)
    )
}

// ---------------------------------------------------------------------------
// 行
// ---------------------------------------------------------------------------

@Composable
fun IosRow(
    title: String,
    subtitle: String? = null,
    value: String? = null,
    icon: ImageVector? = null,
    iconTint: Color? = null,
    showChevron: Boolean = false,
    destructive: Boolean = false,
    onClick: (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
) {
    val c = LocalIos.current
    Row(
        Modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            Box(
                Modifier
                    .size(28.dp)
                    .clip(RoundedCornerShape(7.dp))
                    .background((iconTint ?: c.blue)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = Color.White, modifier = Modifier.size(17.dp))
            }
            Spacer(Modifier.width(12.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(
                title,
                style = IosType.body,
                color = if (destructive) c.red else c.label,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (subtitle != null) {
                Text(
                    subtitle,
                    style = IosType.footnote,
                    color = c.secondaryLabel,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (value != null) {
            Text(
                value,
                style = IosType.body,
                color = c.secondaryLabel,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 12.dp),
            )
        }
        trailing?.let {
            Spacer(Modifier.width(8.dp))
            it()
        }
        if (showChevron) {
            Spacer(Modifier.width(6.dp))
            Icon(
                Icons.Rounded.ChevronRight,
                contentDescription = null,
                tint = c.tertiaryLabel,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

@Composable
fun IosSwitchRow(
    title: String,
    subtitle: String? = null,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true,
) {
    val c = LocalIos.current
    Row(
        Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 12.dp, top = 10.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = IosType.body, color = if (enabled) c.label else c.secondaryLabel)
            if (subtitle != null) {
                Text(subtitle, style = IosType.footnote, color = c.secondaryLabel)
            }
        }
        Spacer(Modifier.width(12.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            enabled = enabled,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = c.green,
                uncheckedThumbColor = Color.White,
                uncheckedTrackColor = c.tertiaryLabel,
                uncheckedBorderColor = Color.Transparent,
            ),
        )
    }
}

/** 一组开关里的纯信息行（如「当前版本」）。 */
@Composable
fun IosValueRow(title: String, value: String) {
    val c = LocalIos.current
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, style = IosType.body, color = c.label, modifier = Modifier.weight(1f))
        Text(value, style = IosType.body, color = c.secondaryLabel)
    }
}

/** 顶部渐变背景，仅首页使用。 */
@Composable
fun HomeBackground(content: @Composable () -> Unit) {
    val c = LocalIos.current
    val top = if (c.groupedBg == IosDark.groupedBg) Color(0xFF0B1220) else Color(0xFFEAF1FF)
    Box(
        Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(0f to top, 0.45f to c.groupedBg, 1f to c.groupedBg))
    ) { content() }
}
