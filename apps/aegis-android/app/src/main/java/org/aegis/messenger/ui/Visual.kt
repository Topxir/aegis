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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import org.aegis.messenger.core.Avatar
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Text as CoreText

private fun grey(v: Int) = Color(v, v, v)

/** Default avatar: a 5x5 mirrored grid derived from [seed] (spec section 17). */
@Composable
fun AvatarView(seed: ByteArray, size: Int = 52, modifier: Modifier = Modifier) {
    val a = remember(seed.toList()) { Avatar.fromEdPk(seed) }
    Canvas(modifier.size(size.dp).clip(avatarShape())) {
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
