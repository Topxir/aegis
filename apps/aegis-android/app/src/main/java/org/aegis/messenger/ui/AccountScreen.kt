package org.aegis.messenger.ui

import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aegis.messenger.MainActivity
import org.aegis.messenger.R
import org.aegis.messenger.app.Boot
import org.aegis.messenger.app.Session
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Particles
import org.aegis.messenger.core.Profile
import org.aegis.messenger.data.VaultData

private fun Context.activity(): MainActivity? {
    var c = this
    while (c is ContextWrapper) {
        if (c is MainActivity) return c
        c = c.baseContext
    }
    return null
}

@Composable
private fun particleLabel(p: Particles): String = stringResource(
    when (p) {
        Particles.None -> R.string.particles_none
        Particles.Dust -> R.string.particles_dust
        Particles.Snow -> R.string.particles_snow
        Particles.Embers -> R.string.particles_embers
        Particles.Orbit -> R.string.particles_orbit
        Particles.Rain -> R.string.particles_rain
    },
)

@Composable
private fun TextBox(label: String, content: @Composable () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = Ui.muted)
        Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(Ui.surface).border(1.dp, Ui.border, RoundedCornerShape(12.dp)).padding(horizontal = 14.dp)) { content() }
    }
}

@Composable
fun AccountScreen(session: Session, d: VaultData, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val s = d.settings
    var name by remember { mutableStateOf(d.profile.name.ifBlank { s.displayName }) }
    var about by remember { mutableStateOf(d.profile.about) }
    var particles by remember { mutableStateOf(d.profile.particles) }
    var error by remember { mutableStateOf<Int?>(null) }
    var saved by remember { mutableStateOf(false) }
    var secure by remember { mutableStateOf(Boot.secureScreen(ctx)) }
    val ed = remember(d.edSk.toList()) { Crypto.ed25519Public(d.edSk) }
    val maxAbout = 140

    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.account), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Box(Modifier.fillMaxWidth().height(180.dp).background(Ui.surface2)) {
                ParticlesLayer(particles, Modifier.fillMaxSize())
                Column(Modifier.align(Alignment.BottomStart).padding(16.dp)) {
                    AvatarView(ed, 76)
                    Text("@" + d.username, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = GeistMono), color = Ui.muted, modifier = Modifier.padding(top = 8.dp))
                }
            }
            Section(stringResource(R.string.account_profile)) {
                TextBox(stringResource(R.string.field_display_name)) {
                    ImeText(name, { name = it; saved = false }, stringResource(R.string.field_display_name), Modifier.fillMaxWidth(), maxLines = 1, maxChars = Profile.MAX_NAME)
                }
                TextBox(stringResource(R.string.field_about) + "  " + about.length + "/" + maxAbout) {
                    ImeText(about, { about = it.replace('\n', ' '); saved = false }, stringResource(R.string.field_about), Modifier.fillMaxWidth(), maxLines = 3, maxChars = maxAbout)
                }
                Text(stringResource(R.string.particles_title), style = MaterialTheme.typography.labelMedium, color = Ui.muted, modifier = Modifier.padding(top = 10.dp, bottom = 6.dp))
                Particles.values().toList().chunked(3).forEach { row ->
                    Choices(row.map { it to particleLabel(it) }, particles) { particles = it; saved = false }
                    Box(Modifier.height(6.dp))
                }
                Note(stringResource(R.string.profile_note))
                error?.let { Note(stringResource(it), Ui.danger) }
                if (saved) Note(stringResource(R.string.saved), Ui.accent)
                Primary(stringResource(R.string.save)) {
                    session.saveProfile(name, about, particles) { e -> error = e; saved = e == null }
                }
            }
            Divider()
            Section(stringResource(R.string.privacy_security)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.secure_screen), color = Ui.text, modifier = Modifier.weight(1f))
                    Switch(
                        secure, { secure = it; Boot.setSecureScreen(ctx, it); ctx.activity()?.applySecure() },
                        colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
                    )
                }
                Note(stringResource(R.string.secure_note))
                Text(stringResource(R.string.lock_idle), color = Ui.text, modifier = Modifier.padding(top = 12.dp, bottom = 6.dp))
                Choices(listOf(1, 5, 15, 60).map { it to lockText(it) }, s.idleLockMin) { session.saveSettings(s.copy(idleLockMin = it)) { } }
                PinSection(session)
            }
        }
    }
}

@Composable
private fun lockText(min: Int): String = when (min) {
    60 -> stringResource(R.string.lock_hour)
    else -> stringResource(R.string.lock_minutes, min)
}
