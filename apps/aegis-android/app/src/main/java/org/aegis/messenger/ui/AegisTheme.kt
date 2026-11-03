package org.aegis.messenger.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.aegis.messenger.R

/**
 * Single source of truth for Aegis visual tokens: neutral palette, Onest
 * typography, 8-12 dp shapes and the 4/8/12/16/24 spacing grid.
 */
data class AegisPalette(
    val bg: Color,
    val surface: Color,
    val surface2: Color,
    val surface3: Color,
    val border: Color,
    val text: Color,
    val muted: Color,
    val accent: Color,
    val onAccent: Color,
    val danger: Color,
    val warning: Color,
    val outgoing: Color,
    val incoming: Color
)

object AegisPalettes {
    val Dark = AegisPalette(
        bg = Color(0xFF0F0F10),
        surface = Color(0xFF17171A),
        surface2 = Color(0xFF1C1C20),
        surface3 = Color(0xFF222226),
        border = Color(0xFF26262B),
        text = Color(0xFFE8E8EA),
        muted = Color(0xFF8A8A90),
        accent = Color(0xFF7F8FCB),
        onAccent = Color(0xFF101014),
        danger = Color(0xFFC97A7A),
        warning = Color(0xFFB99A62),
        outgoing = Color(0xFF232838),
        incoming = Color(0xFF1C1C20)
    )

    val Light = AegisPalette(
        bg = Color(0xFFFFFFFF),
        surface = Color(0xFFF5F5F4),
        surface2 = Color(0xFFEFEFED),
        surface3 = Color(0xFFE9E9E7),
        border = Color(0xFFE4E4E2),
        text = Color(0xFF1A1A1C),
        muted = Color(0xFF6B6B70),
        accent = Color(0xFF4F63A8),
        onAccent = Color(0xFFFFFFFF),
        danger = Color(0xFFA94F4F),
        warning = Color(0xFF8A6A2F),
        outgoing = Color(0xFFE9EDF7),
        incoming = Color(0xFFF2F2F0)
    )
}

/**
 * Compose-facing bridge. Existing composables read `AegisColors.*`; the
 * values are state-backed so a system light/dark change recomposes them.
 */
object AegisColors {
    var bg by mutableStateOf(AegisPalettes.Dark.bg)
    var panel by mutableStateOf(AegisPalettes.Dark.surface)
    var panel2 by mutableStateOf(AegisPalettes.Dark.surface2)
    var panel3 by mutableStateOf(AegisPalettes.Dark.surface3)
    var line by mutableStateOf(AegisPalettes.Dark.border)
    var text by mutableStateOf(AegisPalettes.Dark.text)
    var muted by mutableStateOf(AegisPalettes.Dark.muted)
    var accent by mutableStateOf(AegisPalettes.Dark.accent)
    var onAccent by mutableStateOf(AegisPalettes.Dark.onAccent)
    var info by mutableStateOf(AegisPalettes.Dark.accent)
    var danger by mutableStateOf(AegisPalettes.Dark.danger)
    var warning by mutableStateOf(AegisPalettes.Dark.warning)
    var outgoing by mutableStateOf(AegisPalettes.Dark.outgoing)
    var incoming by mutableStateOf(AegisPalettes.Dark.incoming)

    internal fun apply(palette: AegisPalette) {
        bg = palette.bg
        panel = palette.surface
        panel2 = palette.surface2
        panel3 = palette.surface3
        line = palette.border
        text = palette.text
        muted = palette.muted
        accent = palette.accent
        onAccent = palette.onAccent
        info = palette.accent
        danger = palette.danger
        warning = palette.warning
        outgoing = palette.outgoing
        incoming = palette.incoming
    }
}

val AegisFontFamily = FontFamily(
    Font(R.font.onest_regular, FontWeight.Normal),
    Font(R.font.onest_medium, FontWeight.Medium)
)

val AegisTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 28.sp,
        lineHeight = 34.sp
    ),
    headlineSmall = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 20.sp,
        lineHeight = 26.sp
    ),
    titleLarge = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 17.sp,
        lineHeight = 24.sp
    ),
    titleMedium = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 15.sp,
        lineHeight = 21.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 21.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 19.sp
    ),
    bodySmall = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        lineHeight = 15.sp
    ),
    labelLarge = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp
    ),
    labelMedium = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 15.sp
    ),
    labelSmall = TextStyle(
        fontFamily = AegisFontFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        lineHeight = 15.sp
    )
)

val AegisShapes = Shapes(
    extraSmall = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
    small = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
    medium = androidx.compose.foundation.shape.RoundedCornerShape(10.dp),
    large = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
    extraLarge = androidx.compose.foundation.shape.RoundedCornerShape(12.dp)
)

object AegisSpacing {
    val xs = 4.dp
    val s = 8.dp
    val m = 12.dp
    val l = 16.dp
    val xl = 24.dp
}

object AegisSizes {
    val rowHeight = 64.dp
    val avatar = 40.dp
    val icon = 20.dp
    val iconSmall = 16.dp
    val control = 40.dp
}

/**
 * Resolves `system` / `dark` / `light` (legacy theme ids fall back to system)
 * and provides MaterialTheme with the Aegis tokens.
 */
@Composable
fun AegisTheme(mode: String, content: @Composable () -> Unit) {
    val systemDark = isSystemInDarkTheme()
    val dark = when (mode) {
        "light" -> false
        "dark" -> true
        else -> systemDark
    }
    val palette = if (dark) AegisPalettes.Dark else AegisPalettes.Light
    SideEffect { AegisColors.apply(palette) }

    MaterialTheme(
        colorScheme = if (dark) {
            darkColorScheme(
                primary = palette.accent,
                onPrimary = palette.onAccent,
                secondary = palette.accent,
                onSecondary = palette.onAccent,
                background = palette.bg,
                onBackground = palette.text,
                surface = palette.surface,
                onSurface = palette.text,
                surfaceVariant = palette.surface2,
                onSurfaceVariant = palette.muted,
                outline = palette.border,
                error = palette.danger
            )
        } else {
            lightColorScheme(
                primary = palette.accent,
                onPrimary = palette.onAccent,
                secondary = palette.accent,
                onSecondary = palette.onAccent,
                background = palette.bg,
                onBackground = palette.text,
                surface = palette.surface,
                onSurface = palette.text,
                surfaceVariant = palette.surface2,
                onSurfaceVariant = palette.muted,
                outline = palette.border,
                error = palette.danger
            )
        },
        typography = AegisTypography,
        shapes = AegisShapes,
        content = content
    )
}
