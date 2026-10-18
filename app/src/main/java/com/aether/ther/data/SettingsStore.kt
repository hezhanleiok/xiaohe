package com.aether.ther.data

import android.content.Context
import androidx.core.content.edit
import org.json.JSONObject

/**
 * 设置的唯一落盘入口。
 *
 * 用一个 JSON 字符串塞进 SharedPreferences，而不是给每个字段建一个键：
 * 字段还在快速变动期，逐键迁移会在改结构时留下半新半旧的配置。
 */
object SettingsStore {
    private const val PREFS = "ther_settings"
    private const val KEY = "settings_json"

    @Volatile
    private var cached: AppSettings? = null

    fun load(context: Context): AppSettings {
        cached?.let { return it }
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val raw = prefs.getString(KEY, null)
        val parsed = if (raw.isNullOrBlank()) {
            AppSettings()
        } else {
            runCatching { AppSettings.fromJson(JSONObject(raw)) }.getOrElse {
                LogBus.w("Settings", "配置解析失败，回退默认值：${it.message}")
                AppSettings()
            }
        }
        cached = parsed
        return parsed
    }

    fun save(context: Context, settings: AppSettings) {
        cached = settings
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit { putString(KEY, settings.toJson().toString()) }
    }

    /** 只给单元测试/清空数据用。 */
    fun resetCache() {
        cached = null
    }
}
