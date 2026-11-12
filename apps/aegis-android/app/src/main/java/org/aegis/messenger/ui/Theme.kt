package org.aegis.messenger.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import android.provider.Settings
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.aegis.messenger.R
import org.aegis.messenger.data.Look

/** Dark only: black ground, flat surfaces; the accent gradient comes from the account's [Look]. */
object Ui {
    val bg = Color(0xFF000000)
    val surface = Color(0xFF0C0C0E)
    val surface2 = Color(0xFF151518)
    val border = Color(0xFF222226)
    val bubbleBorder = Color(0xFF1E1E22)
    val text = Color(0xFFEDEDEF)
    val muted = Color(0xFF8E8F96)
    val danger = Color(0xFFD27B74)
    val warning = Color(0xFFC9A66B)
    const val ANIM_MS = 180
    const val ENTER_MS = 300

    var look by mutableStateOf(Look())
        private set
    var accent by mutableStateOf(Color(0xFFF4F4F6))
        private set
    var onAccent by mutableStateOf(Color(0xFF0E0E10))
        private set
    /** Accent gradient for primary buttons and highlights. */
    var lightGradient: Brush by mutableStateOf(Brush.linearGradient(listOf(Color(0xFFF4F4F6), Color(0xFFCFD0D6))))
        private set
    /** Fill and ink of outgoing bubbles. */
    var outBubble: Brush by mutableStateOf(Brush.linearGradient(listOf(Color(0xFF2C2D32), Color(0xFF222327))))
        private set
    var onOutBubble by mutableStateOf(Color(0xFFEDEDEF))
        private set
    var accentStops by mutableStateOf(listOf(Color(0xFFF4F4F6), Color(0xFFCFD0D6)))
        private set
    val avatarGradient = Brush.linearGradient(listOf(Color(0xFF34353A), Color(0xFF18191C)))

    fun rgb(v: Int) = Color(0xFF000000.toInt() or (v and 0xFFFFFF))

    fun apply(l: Look) {
        if (l == look) return
        look = l
        val a = l.stops()
        accentStops = a.map(::rgb)
        accent = rgb(a.first())
        onAccent = if (Look.darkInk(a)) Color(0xFF0E0E10) else Color.White
        lightGradient = Brush.linearGradient(accentStops)
        val b = l.bubbleStops()
        outBubble = Brush.linearGradient(b.map(::rgb))
        onOutBubble = if (Look.darkInk(b)) Color(0xFF0E0E10) else Color(0xFFF6F6F8)
    }
}

/** False when the system "remove animations" setting is on or the account turned motion off. */
@Composable
fun animationsOn(): Boolean = systemAnimations() && !Ui.look.motionOff

/** The system animator scale; zero means the user asked for reduced motion. */
@Composable
fun systemAnimations(): Boolean {
    val ctx = LocalContext.current
    return remember {
        try {
            Settings.Global.getFloat(ctx.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) != 0f
        } catch (_: Exception) { true }
    }
}

@Composable
fun fullMotion(): Boolean = animationsOn() && Ui.look.motion == "full"

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

private fun style(size: Int, line: Int, weight: FontWeight = FontWeight.Normal, k: Float = 1f) =
    TextStyle(fontFamily = Geist, fontWeight = weight, fontSize = (size * k).sp, lineHeight = (line * k).sp)

private fun type(k: Float) = Typography(
    headlineSmall = style(22, 28, FontWeight.Medium),
    displaySmall = TextStyle(fontFamily = Geist, fontWeight = FontWeight.Light, fontSize = 34.sp, lineHeight = 40.sp),
    headlineMedium = TextStyle(fontFamily = Geist, fontWeight = FontWeight.Light, fontSize = 30.sp, lineHeight = 36.sp),
    titleLarge = style(19, 24, FontWeight.Medium),
    titleMedium = style(16, 22, FontWeight.Medium, k),
    bodyLarge = style(16, 22, k = k),
    bodyMedium = style(14, 20, k = k),
    bodySmall = style(12, 16, k = k),
    labelLarge = style(14, 20, FontWeight.Medium),
    labelMedium = style(12, 16, FontWeight.Medium),
)

@Composable
fun AegisTheme(content: @Composable () -> Unit) {
    val k = Ui.look.font / Look.FONT_DEFAULT.toFloat()
    val typography = remember(k) { type(k) }
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
        typography = typography,
        shapes = Shapes(
            small = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
            medium = androidx.compose.foundation.shape.RoundedCornerShape(10.dp),
            large = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
        ),
        content = content,
    )
}
