package com.aether.ther.data

/**
 * 国旗 + 英文国名。
 *
 * 国家列表不是写死的业务集合，而是「赛风上次上报的可用出口」——所以这里只负责
 * 把 ISO-3166-1 alpha-2 变成旗帜和英文名；具体有哪些国家由 Psiphon 决定
 * （见 LogBus 里 `psiphon can leave from:` 那一行）。
 */
object CountryCatalog {

    /** 赛风 2026-10-17 上报过的出口地区（来自桌面版日志），作为首屏兜底列表。 */
    val psiphonFallback: List<String> = listOf(
        "AT", "AU", "BE", "BR", "CA", "CH", "CZ", "DE", "DK", "ES", "FI", "FR",
        "GB", "ID", "IE", "IN", "IT", "JP", "KR", "LT", "NL", "NO", "PL", "RO",
        "RS", "SE", "SG", "US",
    )

    private val names = mapOf(
        "AT" to "Austria", "AU" to "Australia", "BE" to "Belgium", "BR" to "Brazil",
        "CA" to "Canada", "CH" to "Switzerland", "CN" to "China", "CZ" to "Czechia",
        "DE" to "Germany", "DK" to "Denmark", "ES" to "Spain", "FI" to "Finland",
        "FR" to "France", "GB" to "United Kingdom", "HK" to "Hong Kong", "ID" to "Indonesia",
        "IE" to "Ireland", "IN" to "India", "IT" to "Italy", "JP" to "Japan",
        "KR" to "South Korea", "LT" to "Lithuania", "MO" to "Macao", "MY" to "Malaysia",
        "NL" to "Netherlands", "NO" to "Norway", "NZ" to "New Zealand", "PH" to "Philippines",
        "PL" to "Poland", "RO" to "Romania", "RS" to "Serbia", "RU" to "Russia",
        "SE" to "Sweden", "SG" to "Singapore", "TH" to "Thailand", "TR" to "Türkiye",
        "TW" to "Taiwan", "UA" to "Ukraine", "US" to "United States", "VN" to "Vietnam",
        "ZA" to "South Africa", "AE" to "United Arab Emirates", "AR" to "Argentina",
        "CL" to "Chile", "CO" to "Colombia", "MX" to "Mexico", "IL" to "Israel",
        "SA" to "Saudi Arabia", "EG" to "Egypt", "NG" to "Nigeria", "KZ" to "Kazakhstan",
    )

    /** ISO2 → 国旗 emoji（区域指示符），未知则返回空串。 */
    fun flag(iso2: String?): String {
        val code = iso2?.uppercase()?.takeIf { it.length == 2 && it.all { c -> c in 'A'..'Z' } }
            ?: return ""
        val base = 0x1F1E6
        val first = base + (code[0] - 'A')
        val second = base + (code[1] - 'A')
        return String(Character.toChars(first)) + String(Character.toChars(second))
    }

    /** ISO2 → 英文国名；未知时原样返回代码，避免界面出现空白。 */
    fun englishName(iso2: String?): String {
        val code = iso2?.uppercase().orEmpty()
        if (code.isEmpty()) return "Unknown"
        return names[code] ?: code
    }

    /** "🇯🇵 Japan" 这种最常用的展示形态。 */
    fun label(iso2: String?): String {
        if (iso2.isNullOrBlank()) return "自动 · Automatic"
        return "${flag(iso2)} ${englishName(iso2)}"
    }

    /** "🇨🇳 CN"：首页状态卡用这个，国旗 + 代码比英文全名更好认。 */
    fun shortLabel(iso2: String?): String {
        if (iso2.isNullOrBlank()) return ""
        return "${flag(iso2)} ${iso2.uppercase()}"
    }
}
