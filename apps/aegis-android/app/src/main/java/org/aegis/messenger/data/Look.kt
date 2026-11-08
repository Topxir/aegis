package org.aegis.messenger.data

/**
 * Per-account appearance. Stored in the vault under its own "look" key; unknown or broken
 * values fall back to the defaults so older and newer vaults both load.
 */
data class Look(
    /** A preset id from [PRESETS] or "custom". */
    val theme: String = "mono",
    /** Custom gradient stops as 0xRRGGBB, two or three of them. */
    val custom: List<Int> = emptyList(),
    val animated: Boolean = false,
    val motion: String = "subtle",
    val depth: Boolean = false,
    /** "left", "right" or "top"; left and right only differ on wide screens. */
    val list: String = "left",
    val density: String = "comfortable",
    val bubble: String = "rounded",
    val radius: Int = RADIUS_DEFAULT,
    val font: Int = FONT_DEFAULT,
    val wall: String = "none",
    val avatar: String = "circle",
) {
    /** Gradient stops for accents, buttons and outgoing bubbles. */
    fun stops(): List<Int> =
        if (theme == "custom" && custom.size in 2..3) custom
        else (PRESETS[theme] ?: PRESETS.getValue("mono"))

    /** Outgoing bubble gradient: muted variants for the light presets, the accent otherwise. */
    fun bubbleStops(): List<Int> = if (theme == "custom" && custom.size in 2..3) custom else BUBBLE_PRESETS[theme] ?: stops()

    val motionOff: Boolean get() = motion == "off"
    val compact: Boolean get() = density == "compact"

    /**
     * How an open chat sits next to the chat list: "left" or "right" (two panes, wide screens
     * only), "strip" (recent chats above the chat) or "single" (one screen at a time).
     */
    fun placement(wide: Boolean, chatOpen: Boolean): String = when {
        !chatOpen -> "single"
        list == "top" -> "strip"
        !wide -> "single"
        list == "right" -> "right"
        else -> "left"
    }

    fun sanitize(): Look = Look(
        theme = if (theme == "custom" && custom.size in 2..3 || theme in PRESETS) theme else "mono",
        custom = custom.take(3).map { it and 0xFFFFFF }.let { if (it.size >= 2) it else emptyList() },
        animated = animated,
        motion = pick(motion, MOTIONS, "subtle"),
        depth = depth,
        list = pick(list, LISTS),
        density = pick(density, DENSITIES),
        bubble = pick(bubble, BUBBLES),
        radius = radius.coerceIn(0, RADIUS_MAX),
        font = font.coerceIn(FONT_MIN, FONT_MAX),
        wall = pick(wall, WALLS),
        avatar = pick(avatar, AVATARS),
    )

    fun toJson(): Map<String, Any?> = linkedMapOf(
        "theme" to theme,
        "custom" to custom.map { hex(it) },
        "animated" to animated,
        "motion" to motion,
        "depth" to depth,
        "list" to list,
        "density" to density,
        "bubble" to bubble,
        "radius" to radius.toLong(),
        "font" to font.toLong(),
        "wall" to wall,
        "avatar" to avatar,
    )

    companion object {
        const val RADIUS_MAX = 22
        const val RADIUS_DEFAULT = 16
        const val FONT_MIN = 13
        const val FONT_MAX = 20
        const val FONT_DEFAULT = 16

        val MOTIONS = listOf("off", "subtle", "full")
        val LISTS = listOf("left", "right", "top")
        val DENSITIES = listOf("comfortable", "compact")
        val BUBBLES = listOf("rounded", "sharp", "minimal")
        val WALLS = listOf("none", "solid", "gradient")
        val AVATARS = listOf("circle", "rounded", "square")

        val PRESETS: Map<String, List<Int>> = linkedMapOf(
            "mono" to listOf(0xF4F4F6, 0xCFD0D6),
            "ocean" to listOf(0x2563EB, 0x0EA5B7),
            "dusk" to listOf(0x6D4AFF, 0xD9467E),
            "aurora" to listOf(0x0F9F7A, 0x2B6FE0, 0x7C4DFF),
            "ember" to listOf(0xF0662E, 0xD42F4F),
            "slate" to listOf(0x8FA3C2, 0x5D6F8C),
        )

        private val BUBBLE_PRESETS: Map<String, List<Int>> = mapOf(
            "mono" to listOf(0x2C2D32, 0x222327),
            "slate" to listOf(0x4B5A73, 0x2D3646),
        )

        private fun pick(v: String, all: List<String>, def: String = all.first()) = if (v in all) v else def

        fun hex(rgb: Int): String = "#" + (rgb and 0xFFFFFF).toString(16).padStart(6, '0')

        /** Parses "#rrggbb"; anything else is null. */
        fun parseHex(s: String): Int? {
            if (s.length != 7 || s[0] != '#') return null
            if (!s.substring(1).all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
            return s.substring(1).toInt(16)
        }

        /** Relative luminance 0..1 of an 0xRRGGBB colour. */
        fun luma(rgb: Int): Double {
            fun ch(v: Int): Double { val c = v / 255.0; return if (c <= 0.03928) c / 12.92 else Math.pow((c + 0.055) / 1.055, 2.4) }
            return 0.2126 * ch(rgb shr 16 and 0xFF) + 0.7152 * ch(rgb shr 8 and 0xFF) + 0.0722 * ch(rgb and 0xFF)
        }

        /** True when text on this gradient should be dark. */
        fun darkInk(stops: List<Int>): Boolean = stops.map { luma(it) }.average() > 0.4

        fun fromJson(m: Map<String, Any?>?): Look {
            if (m == null) return Look()
            val d = Look()
            fun s(k: String, def: String) = m[k] as? String ?: def
            fun b(k: String, def: Boolean) = m[k] as? Boolean ?: def
            fun n(k: String, def: Int) = (m[k] as? Number)?.toLong()?.coerceIn(-1000, 1000)?.toInt() ?: def
            val custom = (m["custom"] as? List<*>)?.mapNotNull { (it as? String)?.let(::parseHex) } ?: emptyList()
            return Look(
                theme = s("theme", d.theme),
                custom = custom,
                animated = b("animated", d.animated),
                motion = s("motion", d.motion),
                depth = b("depth", d.depth),
                list = s("list", d.list),
                density = s("density", d.density),
                bubble = s("bubble", d.bubble),
                radius = n("radius", d.radius),
                font = n("font", d.font),
                wall = s("wall", d.wall),
                avatar = s("avatar", d.avatar),
            ).sanitize()
        }
    }
}
