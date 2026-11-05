package org.aegis.messenger.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.heightIn
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import org.aegis.messenger.R

@Composable
fun TopBar(title: String, subtitle: String? = null, onBack: (() -> Unit)? = null, actions: @Composable () -> Unit = {}) {
    Row(
        Modifier.fillMaxWidth().statusBarsPadding().heightIn(min = 56.dp).padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (onBack != null) {
            IconButton(onClick = onBack, modifier = Modifier.size(48.dp)) { Icon(AegisIcons.ArrowLeft, stringResource(R.string.back), tint = Ui.text) }
        } else {
            Spacer(Modifier.width(12.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleLarge, color = Ui.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodySmall, color = Ui.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        actions()
    }
}

@Composable
fun BarIcon(icon: ImageVector, desc: String, onClick: () -> Unit) {
    IconButton(onClick = onClick, modifier = Modifier.size(48.dp)) { Icon(icon, desc, tint = Ui.text) }
}

@Composable
fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
        Text(title.uppercase(), style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 1.5.sp), color = Ui.muted)
        Spacer(Modifier.height(8.dp))
        content()
    }
}

@Composable
fun Note(text: String, color: Color = Ui.muted) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = color, modifier = Modifier.padding(top = 4.dp, bottom = 4.dp))
}

@Composable
fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    password: Boolean = false,
    singleLine: Boolean = true,
    keyboard: KeyboardType = KeyboardType.Text,
    enabled: Boolean = true,
    mono: Boolean = false,
) {
    val shape = RoundedCornerShape(12.dp)
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = Ui.muted, modifier = Modifier.padding(bottom = 4.dp))
        Box(Modifier.fillMaxWidth().clip(shape).background(Ui.surface).border(1.dp, Ui.border, shape).padding(horizontal = 14.dp)) {
            ImeText(
                value, onChange, label, Modifier.fillMaxWidth(), maxLines = if (singleLine) 1 else 5, enabled = enabled,
                password = password, single = singleLine, mono = mono,
                uri = keyboard == KeyboardType.Uri, ascii = keyboard == KeyboardType.Ascii,
            )
        }
    }
}

@Composable
fun Primary(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    val shape = RoundedCornerShape(14.dp)
    val src = remember { androidx.compose.foundation.interaction.MutableInteractionSource() }
    val pressed by src.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed && enabled) 0.985f else 1f, tween(120), label = "press")
    Box(
        Modifier.fillMaxWidth().padding(vertical = 4.dp).height(52.dp).graphicsLayer { scaleX = scale; scaleY = scale }.clip(shape)
            .background(if (enabled) Ui.lightGradient else SolidColor(Ui.surface2))
            .clickable(interactionSource = src, indication = null, enabled = enabled, role = Role.Button, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = MaterialTheme.typography.labelLarge, color = if (enabled) Ui.onAccent else Ui.muted)
    }
}

@Composable
fun Secondary(text: String, enabled: Boolean = true, danger: Boolean = false, modifier: Modifier = Modifier.fillMaxWidth(), onClick: () -> Unit) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        border = BorderStroke(1.dp, Ui.border),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = if (danger) Ui.danger else Ui.text),
        shape = RoundedCornerShape(14.dp),
        modifier = modifier.padding(vertical = 4.dp).heightIn(min = 48.dp),
    ) { Text(text) }
}

@Composable
fun Link(text: String, onClick: () -> Unit) {
    TextButton(onClick = onClick, modifier = Modifier.heightIn(min = 48.dp)) { Text(text, color = Ui.accent) }
}

/** A single-select row of text options. */
@Composable
fun <T> Choices(options: List<Pair<T, String>>, selected: T, onSelect: (T) -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).border(1.dp, Ui.border, RoundedCornerShape(10.dp)),
    ) {
        options.forEach { (value, label) ->
            val on = value == selected
            Box(
                Modifier.weight(1f).height(48.dp)
                    .background(if (on) Ui.surface2 else Color.Transparent)
                    .clickable(role = Role.Tab) { onSelect(value) },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    style = MaterialTheme.typography.labelMedium,
                    color = if (on) Ui.accent else Ui.muted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
            }
        }
    }
}

@Composable
fun Avatar(name: String, size: Int = 48) {
    val initials = name.trimStart('@').filter { it.isLetterOrDigit() }.take(2).uppercase().ifEmpty { "?" }
    Box(Modifier.size(size.dp).clip(CircleShape).background(Ui.avatarGradient).border(1.dp, Ui.border, CircleShape), contentAlignment = Alignment.Center) {
        Text(initials, style = MaterialTheme.typography.titleMedium.copy(fontFamily = GeistMono), color = Ui.text)
    }
}

/** Plain text tabs with an underline under the selected one. */
@Composable
fun <T> UnderlineTabs(options: List<Pair<T, String>>, selected: T, onSelect: (T) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(20.dp)) {
        options.forEach { (value, label) ->
            val on = value == selected
            Column(
                Modifier.heightIn(min = 48.dp).clickable(role = Role.Tab) { onSelect(value) },
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(label, style = MaterialTheme.typography.labelLarge, color = if (on) Ui.text else Ui.muted, maxLines = 1)
                Spacer(Modifier.height(6.dp))
                Box(Modifier.height(1.5.dp).width(24.dp).background(if (on) Ui.text else Color.Transparent))
            }
        }
    }
}

@Composable
fun Divider() {
    Box(Modifier.fillMaxWidth().height(1.dp).background(Ui.border))
}

@Composable
fun Banner(text: String, color: Color = Ui.warning, content: @Composable ColumnScope.() -> Unit = {}) {
    Column(
        Modifier.fillMaxWidth().padding(12.dp).clip(RoundedCornerShape(10.dp)).border(1.dp, color, RoundedCornerShape(10.dp)).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = Ui.text)
        content()
    }
}
