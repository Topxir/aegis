package org.aegis.messenger.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aegis.messenger.BuildConfig
import org.aegis.messenger.R
import org.aegis.messenger.app.Boot
import org.aegis.messenger.app.Session
import org.aegis.messenger.app.Tor
import org.aegis.messenger.app.TorStatus
import org.aegis.messenger.data.Settings
import org.aegis.messenger.data.VaultData

@Composable
private fun lockLabel(min: Int): String = when (min) {
    0 -> stringResource(R.string.lock_immediately)
    -1 -> stringResource(R.string.lock_never)
    60 -> stringResource(R.string.lock_hour)
    else -> stringResource(R.string.lock_minutes, min)
}

@Composable
fun SettingsScreen(session: Session, d: VaultData, onBack: () -> Unit, onAbout: () -> Unit, onLanguage: () -> Unit, part: String = "") {
    val ctx = LocalContext.current
    // One page of the settings hub, or every section when [part] is empty.
    val all = part.isEmpty()
    val acct = all || part == "account"
    val net = all || part == "network"
    val lock = all || part == "privacy"
    val notify = all || part == "notifications"
    val s = d.settings
    var name by remember { mutableStateOf(s.displayName) }
    var endpoint by remember { mutableStateOf(s.endpoint) }
    var proxy by remember { mutableStateOf(s.proxy) }
    var tor by remember { mutableStateOf(Boot.tor(ctx)) }
    var error by remember { mutableStateOf<Int?>(null) }
    var saved by remember { mutableStateOf(false) }
    var test by remember { mutableStateOf<Boolean?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    var confirmWipe by remember { mutableStateOf(false) }
    var confirmTorOff by remember { mutableStateOf(false) }
    var info by remember { mutableStateOf<Int?>(null) }

    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) session.exportVault(d.username, uri) { e -> info = if (e == null) R.string.info_exported else e }
    }

    fun save(next: Settings) {
        session.saveSettings(next) { e -> error = e; saved = e == null }
    }
    fun current() = s.copy(endpoint = endpoint, proxy = proxy, displayName = name)

    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(SETTINGS_SECTIONS.firstOrNull { it.id == part }?.title ?: R.string.settings), onBack = onBack)
        HeadLine()
        Column(Modifier.verticalScroll(rememberScrollState())) {
            if (acct) Section(stringResource(R.string.account)) {
                Text("@" + d.username, style = MaterialTheme.typography.titleMedium, color = Ui.text)
                if (!d.registered) Note(stringResource(R.string.not_registered), Ui.warning)
                Field(name, { name = it; saved = false }, stringResource(R.string.field_display_name))
            }
            if (acct) Divider()
            if (net) Section(stringResource(R.string.tor)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.tor_connect), color = Ui.text, modifier = Modifier.weight(1f))
                    Switch(
                        tor, { if (it) { tor = true; test = null; session.setTor(true) } else confirmTorOff = true },
                        colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
                    )
                }
                if (tor) {
                    when (Tor.status) {
                        TorStatus.Connected -> Note(stringResource(R.string.tor_connected), Ui.accent)
                        TorStatus.Failed -> Note(stringResource(R.string.tor_failed), Ui.danger)
                        else -> Note(stringResource(R.string.tor_starting))
                    }
                    BridgeSettings()
                }
                Note(stringResource(if (tor) R.string.tor_note_on else R.string.tor_note_off))
            }
            if (net) Divider()
            if (net) Section(stringResource(R.string.server)) {
                Field(endpoint, { endpoint = it; saved = false; test = null }, stringResource(R.string.field_server), keyboard = androidx.compose.ui.text.input.KeyboardType.Uri)
                if (!tor) Note(stringResource(R.string.server_cloudflare_note))
                if (!tor) {
                    Field(proxy, { proxy = it; saved = false; test = null }, stringResource(R.string.field_proxy), keyboard = androidx.compose.ui.text.input.KeyboardType.Uri)
                    Note(stringResource(R.string.proxy_note))
                }
                Secondary(stringResource(R.string.test_connection), enabled = !session.busy) {
                    // The test uses the saved settings, so save first.
                    session.saveSettings(current()) { e ->
                        error = e
                        if (e == null) session.testConnection { test = it }
                    }
                }
                test?.let { Note(stringResource(if (it) R.string.test_ok else R.string.test_fail), if (it) Ui.accent else Ui.danger) }
            }
            if (net) Divider()
            if (net) { UpdateSettings(); Divider() }
            if (net) Section(stringResource(R.string.cover_traffic)) {
                val coverCtx = LocalContext.current
                var cover by remember { mutableStateOf(Boot.coverMode(coverCtx)) }
                Choices(
                    listOf(0 to stringResource(R.string.cover_off), 1 to stringResource(R.string.cover_standard), 2 to stringResource(R.string.cover_high)),
                    cover,
                ) { cover = it; Boot.setCoverMode(coverCtx, it); session.coverChanged() }
                Note(stringResource(R.string.cover_note))
            }
            if (net) Divider()
            if (part == "privacy") { PrivacySection(session); Divider() }
            if (lock) Section(stringResource(R.string.locking)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.app_lock), color = Ui.text, modifier = Modifier.weight(1f))
                    Switch(
                        s.appLock, { save(current().copy(appLock = it)); ctx.activity()?.applySecure() },
                        colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
                    )
                }
                if (s.appLock) {
                    Text(stringResource(R.string.lock_idle), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                    Choices(listOf(1, 5, 15, 60).map { it to lockLabel(it) }, s.idleLockMin) { save(current().copy(idleLockMin = it)) }
                    Text(stringResource(R.string.lock_background), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                    Choices(listOf(0, 1, 5, 15, 60, -1).map { it to lockLabel(it) }, s.backgroundLockMin) { save(current().copy(backgroundLockMin = it)) }
                }
                Note(stringResource(if (s.appLock) R.string.lock_note else R.string.app_lock_off_note))
                Secondary(stringResource(R.string.lock_now)) { session.lock() }
            }
            if (lock) Divider()
            if (notify) Section(stringResource(R.string.notifications)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.notifications_enable), color = Ui.text, modifier = Modifier.weight(1f))
                    Switch(
                        s.notifications, { save(current().copy(notifications = it)) },
                        colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
                    )
                }
                Note(stringResource(R.string.notifications_note))
                Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.notifications_content), color = Ui.text, modifier = Modifier.weight(1f))
                    Switch(
                        s.showContent, { save(current().copy(showContent = it)) },
                        colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
                    )
                }
                Note(stringResource(R.string.notifications_content_note))
                var bg by remember { mutableStateOf(Boot.backgroundPoll(ctx)) }
                Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.background_check), color = Ui.text, modifier = Modifier.weight(1f))
                    Switch(
                        bg, { bg = it; session.setBackgroundPoll(it) },
                        colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
                    )
                }
                Note(stringResource(R.string.background_check_note))
            }
            if (notify) Divider()
            if (all) Section(stringResource(R.string.language)) {
                val cur = Boot.language(ctx)
                Choices(
                    listOf("" to stringResource(R.string.lang_system), "en" to "English", "ru" to "Русский"),
                    cur,
                ) { Boot.setLanguage(ctx, it); onLanguage() }
            }
            if (all) Divider()
            if (acct) Section(stringResource(R.string.data)) {
                Secondary(stringResource(R.string.start_export)) { exporter.launch("aegis-" + d.username + ".vault") }
                Note(stringResource(R.string.export_note))
                Secondary(stringResource(R.string.wipe_chats), danger = true) { confirmWipe = true }
                Secondary(stringResource(R.string.delete_account), danger = true) { confirmDelete = true }
                info?.let { Note(stringResource(it), Ui.accent) }
            }
            if (acct) Divider()
            error?.let { Note(stringResource(it), Ui.danger) }
            if (saved) Note(stringResource(R.string.saved), Ui.accent)
            Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                if (acct || net) Primary(stringResource(R.string.save)) { save(current()) }
                if (all) Secondary(stringResource(R.string.about)) { onAbout() }
                if (all) Note(stringResource(R.string.version_line, BuildConfig.VERSION_NAME))
            }
        }
    }
    if (confirmTorOff) Confirm(
        stringResource(R.string.tor_off_title), stringResource(R.string.tor_off_body), stringResource(R.string.tor_off_action),
        { confirmTorOff = false; tor = false; test = null; session.setTor(false) }, { confirmTorOff = false },
    )
    if (confirmWipe) Confirm(
        stringResource(R.string.wipe_chats), stringResource(R.string.delete_chats_body), stringResource(R.string.delete),
        { confirmWipe = false; session.wipeAllChats() }, { confirmWipe = false },
    )
    if (confirmDelete) Confirm(
        stringResource(R.string.delete_account), stringResource(R.string.delete_account_body), stringResource(R.string.delete),
        { confirmDelete = false; session.deleteAccount() }, { confirmDelete = false },
    )
}

@Composable
fun AboutScreen(onBack: () -> Unit, onGuide: (() -> Unit)? = null) {
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.about), onBack = onBack)
        Divider()
        Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.app_name) + " " + BuildConfig.VERSION_NAME, style = MaterialTheme.typography.titleLarge, color = Ui.text)
            Text(stringResource(R.string.about_intro), style = MaterialTheme.typography.bodyMedium, color = Ui.text)
            Text(stringResource(R.string.about_limits_title), style = MaterialTheme.typography.labelMedium, color = Ui.muted)
            listOf(
                R.string.about_l1, R.string.about_l2, R.string.about_l3, R.string.about_l4, R.string.about_l5, R.string.about_l6,
            ).forEach { Text("• " + stringResource(it), style = MaterialTheme.typography.bodyMedium, color = Ui.text) }
            Text(stringResource(R.string.about_privacy), style = MaterialTheme.typography.bodyMedium, color = Ui.muted)
            Text(stringResource(R.string.about_font_license), style = MaterialTheme.typography.bodySmall, color = Ui.muted)
            if (onGuide != null) Secondary(stringResource(R.string.guide_show), onClick = onGuide)
        }
    }
}
