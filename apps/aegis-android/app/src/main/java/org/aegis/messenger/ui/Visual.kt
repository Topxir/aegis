package org.aegis.messenger.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import org.aegis.messenger.core.Avatar
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Particles
import org.aegis.messenger.core.Text as CoreText
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.floor
import kotlin.math.sin

private fun grey(v: Int) = Color(v, v, v)

/** Default avatar: a 5x5 mirrored grid derived from [seed] (spec section 17). */
@Composable
fun AvatarView(seed: ByteArray, size: Int = 52, modifier: Modifier = Modifier) {
    val a = remember(seed.toList()) { Avatar.fromEdPk(seed) }
    Canvas(modifier.size(size.dp).clip(CircleShape)) {
        drawRect(grey(a.bg))
        val pad = this.size.width * 0.2f
        val cell = (this.size.width - 2 * pad) / 5f
        for (r in 0 until 5) for (c in 0 until 5) if (a.cells[r][c]) {
            drawRect(grey(a.fg), Offset(pad + c * cell, pad + r * cell), androidx.compose.ui.geometry.Size(cell, cell))
        }
    }
}

/** Seed for chats that have no identity key: a hash of a stable label. */
fun seedOf(label: String): ByteArray = Crypto.sha256(CoreText.utf8(label))

private fun frac(x: Float) = x - floor(x)
private fun rnd(i: Int, k: Int): Float = frac(sin((i * 12.9898f + k * 78.233f)) * 43758.547f)

/**
 * Slow particle effect on a Canvas. Static when the system animator scale is zero.
 */
@Composable
fun ParticlesLayer(kind: Particles, modifier: Modifier = Modifier) {
    if (kind == Particles.None) return
    val on = animationsOn()
    var t by remember { mutableFloatStateOf(0f) }
    if (on) LaunchedEffect(kind) {
        val start = androidx.compose.runtime.withFrameNanos { it }
        while (true) androidx.compose.runtime.withFrameNanos { t = (it - start) / 1e9f }
    }
    val dp = LocalDensity.current.density
    Canvas(modifier) {
        val w = size.width
        val h = size.height
        val n = if (kind == Particles.Rain) 36 else 44
        for (i in 0 until n) {
            val r1 = rnd(i, 1); val r2 = rnd(i, 2); val r3 = rnd(i, 3)
            when (kind) {
                Particles.Dust -> {
                    val x = frac(r1 + 0.012f * t * (r2 - 0.5f) * 4f)
                    val y = frac(r3 + 0.008f * t)
                    drawCircle(grey(200).copy(alpha = 0.10f + 0.2f * r2), (0.8f + 1.4f * r2) * dp, Offset(x * w, y * h))
                }
                Particles.Snow -> {
                    val y = frac(r3 + t * (0.04f + 0.05f * r2))
                    val x = frac(r1 + 0.02f * sin(t * 0.6f + i))
                    drawCircle(Color.White.copy(alpha = 0.25f + 0.35f * r2), (1f + 1.6f * r2) * dp, Offset(x * w, y * h))
                }
                Particles.Embers -> {
                    val p = frac(r3 + t * (0.05f + 0.05f * r2))
                    val x = frac(r1 + 0.03f * sin(t * 0.8f + i))
                    drawCircle(Color(0xFFD9A066).copy(alpha = (1f - p) * 0.6f), (0.8f + 1.4f * r2) * dp, Offset(x * w, (1f - p) * h))
                }
                Particles.Orbit -> {
                    val a = t * (0.15f + 0.35f * r2) + r1 * 2f * PI.toFloat()
                    val rad = (0.12f + 0.4f * r3) * h
                    drawCircle(grey(210).copy(alpha = 0.15f + 0.3f * r2), (0.9f + 1.2f * r2) * dp, Offset(w / 2f + cos(a) * rad * 1.6f, h / 2f + sin(a) * rad))
                }
                Particles.Rain -> {
                    val y = frac(r3 + t * (0.5f + 0.4f * r2))
                    val x = r1 * w
                    val len = (8f + 10f * r2) * dp
                    drawLine(grey(190).copy(alpha = 0.18f + 0.2f * r2), Offset(x, y * h), Offset(x - len * 0.15f, y * h + len), 1f * dp)
                }
                Particles.None -> {}
            }
        }
    }
}

/**
 * Numeric PIN pad. Holds no state: the caller keeps [value] and receives changes.
 * Wired to the vault in a later phase.
 */
@Composable
fun PinPad(value: String, maxLen: Int, onChange: (String) -> Unit, onSubmit: () -> Unit) {
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Row(horizontalArrangement = Arrangement.spacedBy(14.dp), modifier = Modifier.height(28.dp), verticalAlignment = Alignment.CenterVertically) {
            for (i in 0 until maxLen) {
                Box(Modifier.size(11.dp).clip(CircleShape).background(if (i < value.length) Ui.accent else Ui.border))
            }
        }
        Spacer(Modifier.height(20.dp))
        val rows = listOf(listOf("1", "2", "3"), listOf("4", "5", "6"), listOf("7", "8", "9"), listOf("<", "0", ">"))
        rows.forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(18.dp), modifier = Modifier.padding(vertical = 7.dp)) {
                row.forEach { k ->
                    Box(
                        Modifier.size(68.dp).clip(CircleShape).background(if (k == "<" || k == ">") Color.Transparent else Ui.surface2)
                            .clickable(role = Role.Button) {
                                when (k) {
                                    "<" -> if (value.isNotEmpty()) onChange(value.dropLast(1))
                                    ">" -> onSubmit()
                                    else -> if (value.length < maxLen) onChange(value + k)
                                }
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        when (k) {
                            "<" -> Icon(AegisIcons.Backspace, null, tint = Ui.muted)
                            ">" -> Icon(AegisIcons.Check, null, tint = Ui.muted)
                            else -> Text(k, style = MaterialTheme.typography.headlineMedium.copy(fontFamily = GeistMono), color = Ui.text)
                        }
                    }
                }
            }
        }
    }
}
