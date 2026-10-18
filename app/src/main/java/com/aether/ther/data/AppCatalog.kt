package com.aether.ther.data

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import androidx.core.graphics.drawable.toBitmap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledApp(
    val pkg: String,
    val label: String,
    val system: Boolean,
    val icon: Drawable?,
) {
    /** 分应用列表里只用得到很小的一张图，缓存一份缩略图省内存。 */
    val thumb: Drawable? by lazy {
        icon
    }
}

/**
 * 已安装应用清单。
 *
 * 只查「有启动图标」的应用（Manifest 里声明了 LAUNCHER 的 <queries>），
 * 不申请 QUERY_ALL_PACKAGES：分应用分流的意义就是给用户看得见的应用，
 * 系统里那些没有界面的包进这个列表只会制造误选。
 */
object AppCatalog {

    suspend fun load(context: Context): List<InstalledApp> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = runCatching {
            pm.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        }.getOrElse { emptyList() }

        resolved.asSequence()
            .mapNotNull { it.activityInfo?.applicationInfo }
            .distinctBy { it.packageName }
            .map { info ->
                InstalledApp(
                    pkg = info.packageName,
                    label = runCatching { pm.getApplicationLabel(info).toString() }
                        .getOrDefault(info.packageName),
                    system = (info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0,
                    icon = runCatching { pm.getApplicationIcon(info) }.getOrNull(),
                )
            }
            .sortedWith(compareBy({ it.system }, { it.label.lowercase() }))
            .toList()
    }

    fun selfPackage(context: Context): String = context.packageName
}
