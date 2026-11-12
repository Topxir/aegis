package org.aegis.messenger.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathBuilder
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/**
 * One thin-line icon set for the whole app: 24x24 viewport, 1.5 stroke,
 * round caps/joins. Icons are tinted by [androidx.compose.material3.Icon].
 */
object AegisIcons {
    val ArrowLeft: ImageVector = lineIcon("ArrowLeft") {
        line {
            moveTo(19f, 12f)
            horizontalLineTo(5f)
            moveTo(10f, 7f)
            lineTo(5f, 12f)
            lineTo(10f, 17f)
        }
    }

    val ArrowUp: ImageVector = lineIcon("ArrowUp") {
        line {
            moveTo(12f, 19f)
            verticalLineTo(5f)
            moveTo(6f, 11f)
            lineTo(12f, 5f)
            lineTo(18f, 11f)
        }
    }

    val Clock: ImageVector = lineIcon("Clock") {
        line {
            circle(12f, 12f, 8f)
            moveTo(12f, 8f)
            verticalLineTo(12.5f)
            lineTo(15f, 14.5f)
        }
    }

    val Lock: ImageVector = lineIcon("Lock") {
        line {
            roundedRect(5f, 10.5f, 14f, 9.5f, 2f)
            moveTo(8f, 10.5f)
            verticalLineTo(8f)
            curveTo(8f, 5.8f, 9.8f, 4f, 12f, 4f)
            curveTo(14.2f, 4f, 16f, 5.8f, 16f, 8f)
            verticalLineTo(10.5f)
        }
    }

    val Plus: ImageVector = lineIcon("Plus") {
        line {
            moveTo(12f, 5f)
            verticalLineTo(19f)
            moveTo(5f, 12f)
            horizontalLineTo(19f)
        }
    }

    val Send: ImageVector = lineIcon("Send") {
        line {
            moveTo(4f, 11.5f)
            lineTo(20f, 4f)
            lineTo(13.5f, 20f)
            lineTo(11.1f, 13.9f)
            close()
            moveTo(11.1f, 13.9f)
            lineTo(20f, 4f)
        }
    }

    val Settings: ImageVector = lineIcon("Settings") {
        line {
            moveTo(4f, 7f)
            horizontalLineTo(14f)
            moveTo(18f, 7f)
            horizontalLineTo(20f)
            moveTo(4f, 17f)
            horizontalLineTo(6f)
            moveTo(10f, 17f)
            horizontalLineTo(20f)
            circle(16f, 7f, 2f)
            circle(8f, 17f, 2f)
        }
    }

    val Shield: ImageVector = lineIcon("Shield") {
        line {
            moveTo(12f, 3.5f)
            lineTo(19f, 6.3f)
            verticalLineTo(11.5f)
            curveTo(19f, 15.9f, 16f, 18.9f, 12f, 20.5f)
            curveTo(8f, 18.9f, 5f, 15.9f, 5f, 11.5f)
            verticalLineTo(6.3f)
            close()
            moveTo(9f, 12f)
            lineTo(11f, 14f)
            lineTo(15f, 10f)
        }
    }

    val Users: ImageVector = lineIcon("Users") {
        line {
            circle(9f, 8f, 3f)
            moveTo(3.5f, 19f)
            curveTo(3.5f, 16f, 6f, 14f, 9f, 14f)
            curveTo(12f, 14f, 14.5f, 16f, 14.5f, 19f)
            moveTo(15.5f, 5.6f)
            curveTo(17.2f, 6.1f, 18.2f, 7.4f, 18.2f, 8.7f)
            curveTo(18.2f, 10f, 17.2f, 11.3f, 15.5f, 11.8f)
            moveTo(17f, 14.2f)
            curveTo(19.1f, 14.6f, 20.5f, 16.3f, 20.5f, 19f)
        }
    }

    val Menu: ImageVector = lineIcon("Menu") {
        line { moveTo(4f, 7f); horizontalLineTo(20f); moveTo(4f, 12f); horizontalLineTo(20f); moveTo(4f, 17f); horizontalLineTo(20f) }
    }

    val Search: ImageVector = lineIcon("Search") {
        line { circle(11f, 11f, 6f); moveTo(16f, 16f); lineTo(20f, 20f) }
    }

    val Pencil: ImageVector = lineIcon("Pencil") {
        line { moveTo(4f, 20f); lineTo(5f, 15f); lineTo(16f, 4f); lineTo(20f, 8f); lineTo(9f, 19f); close() }
    }

    val Clip: ImageVector = lineIcon("Clip") {
        line {
            moveTo(19f, 11f); lineTo(11f, 19f); curveTo(8.5f, 21.5f, 5f, 18f, 7.5f, 15.5f)
            lineTo(15.5f, 7.5f); curveTo(17f, 6f, 19.5f, 8.5f, 18f, 10f); lineTo(10f, 18f)
        }
    }

    val Play: ImageVector = lineIcon("Play") {
        line { moveTo(8f, 5f); lineTo(19f, 12f); lineTo(8f, 19f); close() }
    }

    val Check: ImageVector = lineIcon("Check") {
        line { moveTo(5f, 12.5f); lineTo(10f, 17f); lineTo(19f, 7f) }
    }

    val Close: ImageVector = lineIcon("Close") {
        line { moveTo(6f, 6f); lineTo(18f, 18f); moveTo(18f, 6f); lineTo(6f, 18f) }
    }

    val Pin: ImageVector = lineIcon("Pin") {
        line { moveTo(9f, 4f); horizontalLineTo(15f); lineTo(14f, 10f); lineTo(17f, 13f); horizontalLineTo(7f); lineTo(10f, 10f); close(); moveTo(12f, 13f); verticalLineTo(20f) }
    }

    val Mute: ImageVector = lineIcon("Mute") {
        line {
            moveTo(6f, 16f); verticalLineTo(11f); curveTo(6f, 7f, 18f, 7f, 18f, 11f); verticalLineTo(16f); lineTo(20f, 18f); horizontalLineTo(4f); close()
            moveTo(4f, 4f); lineTo(20f, 20f)
        }
    }

    val Trash: ImageVector = lineIcon("Trash") {
        line { moveTo(5f, 7f); horizontalLineTo(19f); moveTo(9f, 7f); verticalLineTo(4f); horizontalLineTo(15f); verticalLineTo(7f); moveTo(7f, 7f); lineTo(8f, 20f); horizontalLineTo(16f); lineTo(17f, 7f) }
    }

    val Megaphone: ImageVector = lineIcon("Megaphone") {
        line { moveTo(4f, 10f); verticalLineTo(14f); horizontalLineTo(8f); lineTo(18f, 19f); verticalLineTo(5f); lineTo(8f, 10f); close() }
    }

    val User: ImageVector = lineIcon("User") {
        line { circle(12f, 8f, 4f); moveTo(4f, 20f); curveTo(4f, 14f, 20f, 14f, 20f, 20f) }
    }

    val Backspace: ImageVector = lineIcon("Backspace") {
        line { moveTo(9f, 6f); horizontalLineTo(20f); verticalLineTo(18f); horizontalLineTo(9f); lineTo(3f, 12f); close(); moveTo(12f, 9f); lineTo(17f, 15f); moveTo(17f, 9f); lineTo(12f, 15f) }
    }

    val More: ImageVector = lineIcon("More") {
        line { circle(12f, 5f, 0.6f); circle(12f, 12f, 0.6f); circle(12f, 19f, 0.6f) }
    }
}

private fun lineIcon(name: String, build: ImageVector.Builder.() -> Unit): ImageVector =
    ImageVector.Builder(
        name = name,
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f
    ).apply(build).build()

private fun ImageVector.Builder.line(build: PathBuilder.() -> Unit) {
    path(
        fill = null,
        stroke = SolidColor(Color.Black),
        strokeLineWidth = 1.5f,
        strokeLineCap = StrokeCap.Round,
        strokeLineJoin = StrokeJoin.Round,
        pathBuilder = build
    )
}

private fun PathBuilder.circle(cx: Float, cy: Float, r: Float) {
    val k = r * 0.5523f
    moveTo(cx, cy - r)
    curveTo(cx + k, cy - r, cx + r, cy - k, cx + r, cy)
    curveTo(cx + r, cy + k, cx + k, cy + r, cx, cy + r)
    curveTo(cx - k, cy + r, cx - r, cy + k, cx - r, cy)
    curveTo(cx - r, cy - k, cx - k, cy - r, cx, cy - r)
    close()
}

private fun PathBuilder.roundedRect(x: Float, y: Float, w: Float, h: Float, r: Float) {
    val k = r * 0.5523f
    moveTo(x + r, y)
    horizontalLineTo(x + w - r)
    curveTo(x + w - r + k, y, x + w, y + r - k, x + w, y + r)
    verticalLineTo(y + h - r)
    curveTo(x + w, y + h - r + k, x + w - r + k, y + h, x + w - r, y + h)
    horizontalLineTo(x + r)
    curveTo(x + r - k, y + h, x, y + h - r + k, x, y + h - r)
    verticalLineTo(y + r)
    curveTo(x, y + r - k, x + r - k, y, x + r, y)
    close()
}
