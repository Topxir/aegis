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
    val Chat: ImageVector = lineIcon("Chat") {
        line {
            moveTo(4f, 5.5f)
            horizontalLineTo(20f)
            verticalLineTo(16.5f)
            horizontalLineTo(9f)
            lineTo(4f, 20f)
            close()
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

    val Channel: ImageVector = lineIcon("Channel") {
        line {
            moveTo(4f, 10f)
            verticalLineTo(14f)
            horizontalLineTo(7f)
            lineTo(14f, 18f)
            verticalLineTo(6f)
            lineTo(7f, 10f)
            close()
            moveTo(17f, 9.5f)
            curveTo(18f, 10.2f, 18.5f, 11f, 18.5f, 12f)
            curveTo(18.5f, 13f, 18f, 13.8f, 17f, 14.5f)
            moveTo(19.5f, 7f)
            curveTo(21f, 8.2f, 21.8f, 10f, 21.8f, 12f)
            curveTo(21.8f, 14f, 21f, 15.8f, 19.5f, 17f)
        }
    }

    val User: ImageVector = lineIcon("User") {
        line {
            circle(12f, 8f, 3.5f)
            moveTo(5f, 20f)
            curveTo(5f, 16.4f, 8.1f, 14f, 12f, 14f)
            curveTo(15.9f, 14f, 19f, 16.4f, 19f, 20f)
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

    val Star: ImageVector = lineIcon("Star") {
        line {
            moveTo(12f, 4f)
            lineTo(14.4f, 9f)
            lineTo(20f, 9.8f)
            lineTo(16f, 13.7f)
            lineTo(16.9f, 19.2f)
            lineTo(12f, 16.6f)
            lineTo(7.1f, 19.2f)
            lineTo(8f, 13.7f)
            lineTo(4f, 9.8f)
            lineTo(9.6f, 9f)
            close()
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

    val Globe: ImageVector = lineIcon("Globe") {
        line {
            circle(12f, 12f, 8f)
            moveTo(4f, 12f)
            horizontalLineTo(20f)
            moveTo(12f, 4f)
            curveTo(14.5f, 6.4f, 15.7f, 9f, 15.7f, 12f)
            curveTo(15.7f, 15f, 14.5f, 17.6f, 12f, 20f)
            curveTo(9.5f, 17.6f, 8.3f, 15f, 8.3f, 12f)
            curveTo(8.3f, 9f, 9.5f, 6.4f, 12f, 4f)
            close()
        }
    }

    val Refresh: ImageVector = lineIcon("Refresh") {
        line {
            moveTo(19f, 8f)
            curveTo(17.6f, 5.4f, 14.9f, 4f, 12f, 4f)
            curveTo(8.7f, 4f, 6f, 6.7f, 6f, 10f)
            lineTo(4f, 8f)
            moveTo(4f, 4f)
            verticalLineTo(9f)
            horizontalLineTo(9f)
            moveTo(5f, 16f)
            curveTo(6.4f, 18.6f, 9.1f, 20f, 12f, 20f)
            curveTo(15.3f, 20f, 18f, 17.3f, 18f, 14f)
            lineTo(20f, 16f)
            moveTo(20f, 20f)
            verticalLineTo(15f)
            horizontalLineTo(15f)
        }
    }

    val Search: ImageVector = lineIcon("Search") {
        line {
            circle(10.5f, 10.5f, 5.5f)
            moveTo(15f, 15f)
            lineTo(19.5f, 19.5f)
        }
    }

    val Bell: ImageVector = lineIcon("Bell") {
        line {
            moveTo(6f, 16f)
            verticalLineTo(11f)
            curveTo(6f, 7.7f, 8.7f, 5f, 12f, 5f)
            curveTo(15.3f, 5f, 18f, 7.7f, 18f, 11f)
            verticalLineTo(16f)
            lineTo(19.5f, 18f)
            horizontalLineTo(4.5f)
            close()
            moveTo(10f, 20f)
            horizontalLineTo(14f)
        }
    }

    val Volume: ImageVector = lineIcon("Volume") {
        line {
            moveTo(4f, 10f)
            verticalLineTo(14f)
            horizontalLineTo(7f)
            lineTo(11f, 17f)
            verticalLineTo(7f)
            lineTo(7f, 10f)
            close()
            moveTo(15f, 9.5f)
            curveTo(16f, 10.2f, 16.5f, 11f, 16.5f, 12f)
            curveTo(16.5f, 13f, 16f, 13.8f, 15f, 14.5f)
            moveTo(17.5f, 7f)
            curveTo(19f, 8.2f, 19.8f, 10f, 19.8f, 12f)
            curveTo(19.8f, 14f, 19f, 15.8f, 17.5f, 17f)
        }
    }

    val Download: ImageVector = lineIcon("Download") {
        line {
            moveTo(12f, 4f)
            verticalLineTo(14f)
            moveTo(8f, 10.5f)
            lineTo(12f, 14.5f)
            lineTo(16f, 10.5f)
            moveTo(5f, 19f)
            horizontalLineTo(19f)
        }
    }

    val Check: ImageVector = lineIcon("Check") {
        line {
            moveTo(5f, 12.5f)
            lineTo(9.2f, 16.7f)
            lineTo(19f, 7f)
        }
    }

    val ArrowLeft: ImageVector = lineIcon("ArrowLeft") {
        line {
            moveTo(19f, 12f)
            horizontalLineTo(5f)
            moveTo(10f, 7f)
            lineTo(5f, 12f)
            lineTo(10f, 17f)
        }
    }

    val ArrowRight: ImageVector = lineIcon("ArrowRight") {
        line {
            moveTo(5f, 12f)
            horizontalLineTo(19f)
            moveTo(14f, 7f)
            lineTo(19f, 12f)
            lineTo(14f, 17f)
        }
    }

    val Trash: ImageVector = lineIcon("Trash") {
        line {
            moveTo(5f, 7f)
            horizontalLineTo(19f)
            moveTo(9f, 7f)
            verticalLineTo(5f)
            horizontalLineTo(15f)
            verticalLineTo(7f)
            moveTo(7f, 7f)
            lineTo(8f, 20f)
            horizontalLineTo(16f)
            lineTo(17f, 7f)
            moveTo(10f, 11f)
            verticalLineTo(16f)
            moveTo(14f, 11f)
            verticalLineTo(16f)
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

    val X: ImageVector = lineIcon("X") {
        line {
            moveTo(6f, 6f)
            lineTo(18f, 18f)
            moveTo(18f, 6f)
            lineTo(6f, 18f)
        }
    }

    val Image: ImageVector = lineIcon("Image") {
        line {
            roundedRect(4f, 5f, 16f, 14f, 2f)
            circle(9f, 10f, 1.5f)
            moveTo(4f, 16f)
            lineTo(9f, 12f)
            lineTo(13f, 15f)
            lineTo(16f, 13f)
            lineTo(20f, 16f)
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

    val More: ImageVector = lineIcon("More") {
        line {
            circle(6f, 12f, 1f)
            circle(12f, 12f, 1f)
            circle(18f, 12f, 1f)
        }
    }

    val Key: ImageVector = lineIcon("Key") {
        line {
            circle(8f, 12f, 4f)
            moveTo(12f, 12f)
            horizontalLineTo(20f)
            moveTo(17f, 12f)
            verticalLineTo(15f)
            moveTo(20f, 12f)
            verticalLineTo(14f)
        }
    }

    val Warning: ImageVector = lineIcon("Warning") {
        line {
            moveTo(12f, 4f)
            lineTo(21f, 20f)
            horizontalLineTo(3f)
            close()
            moveTo(12f, 10f)
            verticalLineTo(14f)
            moveTo(12f, 17f)
            horizontalLineTo(12.01f)
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

    val Logout: ImageVector = lineIcon("Logout") {
        line {
            moveTo(10f, 5f)
            horizontalLineTo(6f)
            curveTo(4.9f, 5f, 4f, 5.9f, 4f, 7f)
            verticalLineTo(17f)
            curveTo(4f, 18.1f, 4.9f, 19f, 6f, 19f)
            horizontalLineTo(10f)
            moveTo(14f, 8f)
            lineTo(18f, 12f)
            lineTo(14f, 16f)
            moveTo(9f, 12f)
            horizontalLineTo(18f)
        }
    }

    val Edit: ImageVector = lineIcon("Edit") {
        line {
            moveTo(5f, 19f)
            horizontalLineTo(9f)
            lineTo(19f, 9f)
            lineTo(15f, 5f)
            lineTo(5f, 15f)
            close()
            moveTo(13.5f, 6.5f)
            lineTo(17.5f, 10.5f)
        }
    }

    val Server: ImageVector = lineIcon("Server") {
        line {
            roundedRect(4f, 5f, 16f, 6f, 2f)
            roundedRect(4f, 13f, 16f, 6f, 2f)
            moveTo(8f, 8f)
            horizontalLineTo(8.01f)
            moveTo(8f, 16f)
            horizontalLineTo(8.01f)
        }
    }

    val Moon: ImageVector = lineIcon("Moon") {
        line {
            moveTo(19f, 14.5f)
            curveTo(17.9f, 15.2f, 16.6f, 15.6f, 15.2f, 15.6f)
            curveTo(11.2f, 15.6f, 8f, 12.4f, 8f, 8.4f)
            curveTo(8f, 7.5f, 8.2f, 6.6f, 8.5f, 5.8f)
            curveTo(5.9f, 6.9f, 4f, 9.5f, 4f, 12.5f)
            curveTo(4f, 16.6f, 7.4f, 20f, 11.5f, 20f)
            curveTo(14.5f, 20f, 17.1f, 18.1f, 18.2f, 15.5f)
            close()
        }
    }

    val Sun: ImageVector = lineIcon("Sun") {
        line {
            circle(12f, 12f, 3.5f)
            moveTo(12f, 3f)
            verticalLineTo(5f)
            moveTo(12f, 19f)
            verticalLineTo(21f)
            moveTo(3f, 12f)
            horizontalLineTo(5f)
            moveTo(19f, 12f)
            horizontalLineTo(21f)
            moveTo(5.6f, 5.6f)
            lineTo(7f, 7f)
            moveTo(17f, 17f)
            lineTo(18.4f, 18.4f)
            moveTo(18.4f, 5.6f)
            lineTo(17f, 7f)
            moveTo(7f, 17f)
            lineTo(5.6f, 18.4f)
        }
    }

    val Monitor: ImageVector = lineIcon("Monitor") {
        line {
            roundedRect(3f, 5f, 18f, 12f, 2f)
            moveTo(9f, 21f)
            horizontalLineTo(15f)
            moveTo(12f, 17f)
            verticalLineTo(21f)
        }
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
