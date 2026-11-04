package org.aegis.messenger.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import android.provider.Settings
import androidx.compose.runtime.remember
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.aegis.messenger.R

/** Dark only: near-black ground, soft grey-black gradients, light primary. */
object Ui {
    val bg = Color(0xFF08080A)
    val surface = Color(0xFF111113)
    val surface2 = Color(0xFF17171A)
    val border = Color(0xFF25262B)
    val bubbleBorder = Color(0xFF222327)
    val text = Color(0xFFEDEDEF)
    val muted = Color(0xFF9A9BA1)
    val accent = Color(0xFFE9E9EC)
    val onAccent = Color(0xFF0E0E10)
    val danger = Color(0xFFD27B74)
    val warning = Color(0xFFC9A66B)
    const val ANIM_MS = 180
    const val ENTER_MS = 300

    val lightGradient = Brush.verticalGradient(listOf(Color(0xFFF6F6F7), Color(0xFFD9D9DE)))
    val outBubble = Brush.linearGradient(listOf(Color(0xFFECECEF), Color(0xFFD9D9DE)))
    val avatarGradient = Brush.linearGradient(listOf(Color(0xFF3A3B40), Color(0xFF1B1C1F)))

    /** Soft radial glow anchored top-left; [shift] moves the centre a little (0..1). */
    fun ground(shift: Float = 0f): Brush = Brush.radialGradient(
        colors = listOf(Color(0xFF1E1F23), Color(0xFF0D0D0F), Color(0xFF0A0A0B)),
        center = Offset(120f + 160f * shift, 60f + 90f * shift),
        radius = 1500f,
    )
}

/** False when the system "remove animations" setting is on. */
@Composable
fun animationsOn(): Boolean {
    val ctx = LocalContext.current
    return remember {
        try {
            Settings.Global.getFloat(ctx.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) != 0f
        } catch (_: Exception) { true }
    }
}

val Geist = FontFamily(
    Font(R.font.geist_light, FontWeight.Light),
    Font(R.font.geist_regular, FontWeight.Normal),
    Font(R.font.geist_medium, FontWeight.Medium),
    Font(R.font.geist_semibold, FontWeight.SemiBold),
)

val GeistMono = FontFamily(
    Font(R.font.geist_mono_regular, FontWeight.Normal),
    Font(R.font.geist_mono_medium, FontWeight.Medium),
)

private fun style(size: Int, line: Int, weight: FontWeight = FontWeight.Normal) =
    TextStyle(fontFamily = Geist, fontWeight = weight, fontSize = size.sp, lineHeight = line.sp)

private val Type = Typography(
    headlineSmall = style(22, 28, FontWeight.Medium),
    displaySmall = TextStyle(fontFamily = Geist, fontWeight = FontWeight.Light, fontSize = 34.sp, lineHeight = 40.sp),
    headlineMedium = TextStyle(fontFamily = Geist, fontWeight = FontWeight.Light, fontSize = 30.sp, lineHeight = 36.sp),
    titleLarge = style(19, 24, FontWeight.Medium),
    titleMedium = style(16, 22, FontWeight.Medium),
    bodyLarge = style(16, 22),
    bodyMedium = style(14, 20),
    bodySmall = style(12, 16),
    labelLarge = style(14, 20, FontWeight.Medium),
    labelMedium = style(12, 16, FontWeight.Medium),
)

@Composable
fun AegisTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Ui.accent,
            onPrimary = Ui.onAccent,
            background = Ui.bg,
            onBackground = Ui.text,
            surface = Ui.surface,
            onSurface = Ui.text,
            surfaceVariant = Ui.surface2,
            onSurfaceVariant = Ui.muted,
            outline = Ui.border,
            error = Ui.danger,
        ),
        typography = Type,
        shapes = Shapes(
            small = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
            medium = androidx.compose.foundation.shape.RoundedCornerShape(10.dp),
            large = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
        ),
        content = content,
    )
}
