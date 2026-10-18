package com.aether.ther.core

import com.aether.ther.data.LogBus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

data class ReleaseAsset(val name: String, val downloadUrl: String, val size: Long)

data class UpdateInfo(
    val tag: String,
    val name: String,
    val notes: String,
    val publishedAt: String,
    val assets: List<ReleaseAsset>,
    val htmlUrl: String,
)

/**
 * 「版本更新」/「Aether 核心」共用的 GitHub Releases 读取器。
 *
 * 仓库地址目前是占位符（`https://github.com/OWNER/...`），所以正常路径是
 * 直接报「请先在设置里填真实仓库」——占位符不会被当成真实请求发出去，
 * 免得 GitHub 返回 404 让人误以为是网络问题。
 */
object UpdateChecker {

    private const val API = "https://api.github.com/repos"

    suspend fun latest(repoUrl: String): Result<UpdateInfo> = withContext(Dispatchers.IO) {
        val slug = parseSlug(repoUrl)
            ?: return@withContext Result.failure(
                IllegalArgumentException("仓库地址还不是真实的：$repoUrl（请把 OWNER/REPO 换成实际地址）")
            )
        runCatching {
            val conn = (URL("$API/$slug/releases/latest").openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 20_000
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("User-Agent", "ther-android")
            }
            try {
                if (conn.responseCode != 200) {
                    throw IllegalStateException("GitHub 返回 ${conn.responseCode}（$slug）")
                }
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                parseRelease(JSONObject(body))
            } finally {
                conn.disconnect()
            }
        }.onFailure {
            LogBus.w("Update", "读取最新版本失败：${it.message}")
        }
    }

    /** 下载一个 release 资产到目标文件，返回字节数。 */
    suspend fun download(asset: ReleaseAsset, target: java.io.File): Result<Long> =
        withContext(Dispatchers.IO) {
            runCatching {
                target.parentFile?.mkdirs()
                val conn = (URL(asset.downloadUrl).openConnection() as HttpURLConnection).apply {
                    connectTimeout = 15_000
                    readTimeout = 60_000
                    instanceFollowRedirects = true
                    setRequestProperty("User-Agent", "ther-android")
                }
                try {
                    if (conn.responseCode !in 200..299) {
                        throw IllegalStateException("下载失败：HTTP ${conn.responseCode}")
                    }
                    var total = 0L
                    conn.inputStream.use { input ->
                        target.outputStream().use { output ->
                            val buf = ByteArray(64 * 1024)
                            while (true) {
                                val n = input.read(buf)
                                if (n <= 0) break
                                output.write(buf, 0, n)
                                total += n
                            }
                        }
                    }
                    total
                } finally {
                    conn.disconnect()
                }
            }.onFailure {
                LogBus.w("Update", "下载 ${asset.name} 失败：${it.message}")
            }
        }

    /** 只接受 https://github.com/<owner>/<repo> 这种形态。 */
    fun parseSlug(repoUrl: String): String? {
        val cleaned = repoUrl.trim().removeSuffix("/").removeSuffix(".git")
        val m = Regex("""^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$""")
            .find(cleaned) ?: return null
        val owner = m.groupValues[1]
        val repo = m.groupValues[2]
        if (owner.equals("OWNER", ignoreCase = true)) return null
        return "$owner/$repo"
    }

    private fun parseRelease(o: JSONObject): UpdateInfo {
        val assets = ArrayList<ReleaseAsset>()
        o.optJSONArray("assets")?.let { arr ->
            for (i in 0 until arr.length()) {
                val a = arr.optJSONObject(i) ?: continue
                val url = a.optString("browser_download_url")
                if (url.isBlank()) continue
                assets.add(ReleaseAsset(a.optString("name"), url, a.optLong("size")))
            }
        }
        return UpdateInfo(
            tag = o.optString("tag_name"),
            name = o.optString("name"),
            notes = o.optString("body"),
            publishedAt = o.optString("published_at"),
            assets = assets,
            htmlUrl = o.optString("html_url"),
        )
    }

    /** 版本比较：只比数字段，容忍 v 前缀。 */
    fun isNewer(remote: String, current: String): Boolean {
        fun parts(s: String) = s.trim().removePrefix("v").removePrefix("V")
            .split('.', '-', '+')
            .mapNotNull { it.toIntOrNull() }
        val a = parts(remote)
        val b = parts(current)
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }
}
