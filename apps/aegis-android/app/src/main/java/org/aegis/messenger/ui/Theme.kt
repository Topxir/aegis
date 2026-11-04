package org.aegis.messenger.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.aegis.messenger.R

/** Black background, neutral greys, one muted accent. */
object Ui {
    val bg = Color(0xFF000000)
    val surface = Color(0xFF0E0E10)
    val surface2 = Color(0xFF17171A)
    val border = Color(0xFF26262A)
    val text = Color(0xFFEDEDEE)
    val muted = Color(0xFF8D8D93)
    val accent = Color(0xFF8FA6C2)
    val onAccent = Color(0xFF05070A)
    val danger = Color(0xFFD27B74)
    val warning = Color(0xFFC9A66B)
    const val ANIM_MS = 180
}

private val Onest = FontFamily(
    Font(R.font.onest_regular, FontWeight.Normal),
    Font(R.font.onest_medium, FontWeight.Medium),
)

private fun style(size: Int, line: Int, weight: FontWeight = FontWeight.Normal) =
    TextStyle(fontFamily = Onest, fontWeight = weight, fontSize = size.sp, lineHeight = line.sp)

private val Type = Typography(
    headlineSmall = style(22, 28, FontWeight.Medium),
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
