package org.aegis.messenger.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.data.dmKey
import org.aegis.messenger.data.groupKey

@Composable
fun Confirm(title: String, body: String, action: String, onYes: () -> Unit, onNo: () -> Unit) {
    AlertDialog(
        onDismissRequest = onNo,
        containerColor = Ui.surface,
        title = { Text(title, color = Ui.text) },
        text = { Text(body, color = Ui.muted) },
        confirmButton = { TextButton(onClick = onYes) { Text(action, color = Ui.danger) } },
        dismissButton = { TextButton(onClick = onNo) { Text(stringResource(R.string.cancel), color = Ui.text) } },
        properties = DialogProperties(securePolicy = securePolicy()),
    )
}

@Composable
fun ttlLabel(s: Long): String = when (s) {
    0L -> stringResource(R.string.ttl_off)
    30L -> stringResource(R.string.ttl_30s)
    300L -> stringResource(R.string.ttl_5m)
    3600L -> stringResource(R.string.ttl_1h)
    86400L -> stringResource(R.string.ttl_1d)
    else -> stringResource(R.string.ttl_7d)
}

@Composable
private fun TtlPicker(current: Long, onPick: (Long) -> Unit) {
    Section(stringResource(R.string.ttl_title)) {
        Choices(Session.ttlChoices().map { it to ttlLabel(it) }, current, onPick)
        Note(stringResource(R.string.ttl_note))
    }
}

@Composable
fun NewChatScreen(session: Session, onBack: () -> Unit, onOpen: (String) -> Unit, onGroup: () -> Unit) {
    var user by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<Int?>(null) }
    Column(Modifier.fillMaxSize().imePadding().navigationBarsPadding()) {
        TopBar(stringResource(R.string.new_chat), onBack = onBack)
        Divider()
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Column(Modifier.padding(16.dp)) {
                Field(user, { user = it; error = null }, stringResource(R.string.field_contact_username), keyboard = androidx.compose.ui.text.input.KeyboardType.Ascii)
                Note(stringResource(R.string.new_chat_note))
                error?.let { Note(stringResource(it), Ui.danger) }
                if (session.busy) Note(stringResource(R.string.working))
                Primary(stringResource(R.string.find_and_add), enabled = user.isNotBlank() && !session.busy) {
                    session.addContact(user) { u, e -> error = e; if (u != null) onOpen(dmKey(u)) }
                }
                Secondary(stringResource(R.string.new_group)) { onGroup() }
            }
            Divider()
            InviteSections(session, onOpen)
        }
    }
}

@Composable
fun NewGroupScreen(session: Session, d: VaultData, onBack: () -> Unit, onOpen: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    val picked = remember { mutableStateListOf<String>() }
    var error by remember { mutableStateOf<Int?>(null) }
    val eligible = d.contacts.filter { !it.keyChanged }
    Column(Modifier.fillMaxSize().imePadding().navigationBarsPadding()) {
        TopBar(stringResource(R.string.new_group), onBack = onBack)
        Divider()
        Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp)) {
            Field(name, { name = it; error = null }, stringResource(R.string.field_group_name))
            Text(stringResource(R.string.group_pick, picked.size), style = MaterialTheme.typography.labelMedium, color = Ui.muted, modifier = Modifier.padding(top = 12.dp))
            if (eligible.isEmpty()) Note(stringResource(R.string.group_no_contacts))
            eligible.forEach { c ->
                val on = c.username in picked
                Row(
                    Modifier.fillMaxWidth().clickable { if (on) picked.remove(c.username) else picked.add(c.username) }.padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(on, null, colors = CheckboxDefaults.colors(checkedColor = Ui.accent, uncheckedColor = Ui.muted, checkmarkColor = Ui.onAccent))
                    Text("@" + c.username + if (c.title.isNotBlank()) "  " + c.title else "", color = Ui.text, fontFamily = GeistMono, modifier = Modifier.padding(start = 12.dp))
                }
            }
            Note(stringResource(R.string.group_note))
            error?.let { Note(stringResource(it), Ui.danger) }
            Primary(stringResource(R.string.group_create), enabled = name.isNotBlank() && picked.isNotEmpty() && !session.busy) {
                session.createGroup(name, picked.toList()) { id, e -> error = e; if (id != null) onOpen(groupKey(id)) }
            }
        }
    }
}

@Composable
fun ContactScreen(session: Session, d: VaultData, user: String, onBack: () -> Unit) {
    val c = d.contact(user)
    if (c == null) { androidx.compose.runtime.LaunchedEffect(Unit) { onBack() }; return }
    val safety = remember(c.ed.toList(), c.x.toList()) { session.safetyNumber(c) }
    var confirmClear by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<Int?>(null) }
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.profile_title), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            ProfileHeader(c.ed, c.cardName.ifBlank { c.title.ifBlank { "@" + c.username } }, "@" + c.username, c.about, c.particles)
            SharedMedia(session, d.chat(dmKey(c.username)).messages)
            Divider()
            if (c.keyChanged) {
                Banner(stringResource(R.string.key_changed_detail, c.username), Ui.warning) {
                    Row {
                        Link(stringResource(R.string.key_keep_old)) { session.keepOldKey(c.username) }
                        Link(stringResource(R.string.key_accept_new)) { session.acceptNewKey(c.username) { error = it } }
                    }
                }
                error?.let { Note(stringResource(it), Ui.danger) }
            }
            Section(stringResource(R.string.safety_title)) {
                Text(safety ?: "", style = MaterialTheme.typography.bodyLarge.copy(fontFamily = GeistMono, letterSpacing = 1.sp), color = Ui.text)
                Note(stringResource(R.string.safety_note))
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.safety_verified), color = Ui.text)
                    Switch(
                        c.verified, { session.setVerified(c.username, it) }, enabled = !c.keyChanged,
                        colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
                    )
                }
            }
            Divider()
            TtlPicker(c.ttlS) { session.setChatTtl(dmKey(c.username), it) }
            Divider()
            Section(stringResource(R.string.history)) {
                Secondary(stringResource(R.string.clear_history), danger = true) { confirmClear = true }
            }
        }
    }
    if (confirmClear) Confirm(
        stringResource(R.string.clear_history), stringResource(R.string.clear_history_body), stringResource(R.string.delete),
        { session.deleteChatHistory(dmKey(c.username)); confirmClear = false }, { confirmClear = false },
    )
}

@Composable
fun GroupInfoScreen(session: Session, d: VaultData, id: String, onBack: () -> Unit, onLeft: () -> Unit) {
    val g = d.group(id)
    if (g == null) { androidx.compose.runtime.LaunchedEffect(Unit) { onBack() }; return }
    var confirmLeave by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf<String?>(null) }
    val mine = g.creator == d.username
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.profile_title), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            ProfileHeader(seedOf("g:" + g.id), g.name, stringResource(R.string.members_count, g.members.size), "", org.aegis.messenger.core.Particles.None)
            SharedMedia(session, d.chat(groupKey(g.id)).messages)
            Divider()
            Section(stringResource(R.string.members)) {
                g.members.forEach { m ->
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(if (m == d.username) "@$m  (" + stringResource(R.string.you) + ")" else "@$m", color = Ui.text, fontFamily = GeistMono, modifier = Modifier.weight(1f).padding(vertical = 4.dp))
                        if (mine && m != d.username && g.members.size > 2) TextButton({ removing = m }) { Text(stringResource(R.string.remove_member), color = Ui.danger) }
                    }
                }
                Note(stringResource(R.string.group_trust_note))
            }
            Divider()
            TtlPicker(g.ttlS) { session.setChatTtl(groupKey(g.id), it) }
            Divider()
            Section(stringResource(R.string.group_actions)) {
                if (mine || g.creator.isEmpty()) Secondary(stringResource(R.string.resend_invites)) { session.resendInvites(g.id) }
                Secondary(stringResource(R.string.clear_history), danger = true) { confirmClear = true }
                Secondary(stringResource(R.string.leave_group), danger = true) { confirmLeave = true }
                Note(stringResource(R.string.leave_note))
            }
        }
    }
    if (confirmClear) Confirm(
        stringResource(R.string.clear_history), stringResource(R.string.clear_history_body), stringResource(R.string.delete),
        { session.deleteChatHistory(groupKey(g.id)); confirmClear = false }, { confirmClear = false },
    )
    removing?.let { u ->
        Confirm(
            stringResource(R.string.remove_member_title, u), stringResource(R.string.remove_member_body), stringResource(R.string.remove),
            { removing = null; session.removeMember(g.id, u) }, { removing = null },
        )
    }
    if (confirmLeave) Confirm(
        stringResource(R.string.leave_group), stringResource(R.string.leave_body), stringResource(R.string.leave),
        { confirmLeave = false; session.leaveGroup(g.id); onLeft() }, { confirmLeave = false },
    )
}

@Composable
fun ProfileHeader(seed: ByteArray, name: String, handle: String, about: String, particles: org.aegis.messenger.core.Particles) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        AvatarView(seed, 88)
        androidx.compose.foundation.layout.Spacer(Modifier.height(12.dp))
        Text(name, style = MaterialTheme.typography.titleLarge, color = Ui.text)
        Text(handle, style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono), color = Ui.muted)
    }
    if (about.isNotBlank()) Section(stringResource(R.string.field_about)) { Text(about, style = MaterialTheme.typography.bodyLarge, color = Ui.text) }
}

@Composable
fun SharedMedia(session: Session, messages: List<org.aegis.messenger.data.Message>) {
    val items = messages.filter { it.media != null }.takeLast(30).reversed()
    if (items.isEmpty()) return
    var open by remember { mutableStateOf<org.aegis.messenger.data.Media?>(null) }
    Section(stringResource(R.string.shared_media)) {
        items.chunked(3).forEach { row ->
            Row(Modifier.fillMaxWidth().padding(bottom = 2.dp), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                row.forEach { m -> MediaThumb(session, m.media!!, Modifier.weight(1f), square = true) { open = m.media } }
                repeat(3 - row.size) { androidx.compose.foundation.layout.Spacer(Modifier.weight(1f)) }
            }
        }
    }
    open?.let { MediaViewer(session, it) { open = null } }
}

@Composable
fun ContactsScreen(d: VaultData, onBack: () -> Unit, onOpen: (String) -> Unit) {
    val sorted = d.contacts.sortedBy { it.username }
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.contacts), onBack = onBack)
        Divider()
        androidx.compose.foundation.lazy.LazyColumn {
            items(sorted, key = { it.username }) { c ->
                Row(Modifier.fillMaxWidth().clickable { onOpen(dmKey(c.username)) }.padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    AvatarView(c.ed, 44)
                    Column(Modifier.padding(start = 12.dp)) {
                        Text(c.title.ifBlank { "@" + c.username }, style = MaterialTheme.typography.titleMedium, color = Ui.text)
                        Text("@" + c.username, style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono), color = Ui.muted)
                    }
                }
            }
        }
    }
}

@Composable
fun NewChannelScreen(session: Session, d: VaultData, onBack: () -> Unit, onOpen: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    val picked = remember { mutableStateListOf<String>() }
    var error by remember { mutableStateOf<Int?>(null) }
    val eligible = d.contacts.filter { !it.keyChanged }
    Column(Modifier.fillMaxSize().imePadding().navigationBarsPadding()) {
        TopBar(stringResource(R.string.new_channel), onBack = onBack)
        Divider()
        Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp)) {
            Field(name, { name = it; error = null }, stringResource(R.string.field_channel_name))
            Text(stringResource(R.string.channel_pick, picked.size), style = MaterialTheme.typography.labelMedium, color = Ui.muted, modifier = Modifier.padding(top = 12.dp))
            eligible.forEach { c ->
                val on = c.username in picked
                Row(
                    Modifier.fillMaxWidth().clickable { if (on) picked.remove(c.username) else picked.add(c.username) }.padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(on, null, colors = CheckboxDefaults.colors(checkedColor = Ui.accent, uncheckedColor = Ui.muted, checkmarkColor = Ui.onAccent))
                    Text("@" + c.username + if (c.title.isNotBlank()) "  " + c.title else "", color = Ui.text, fontFamily = GeistMono, modifier = Modifier.padding(start = 12.dp))
                }
            }
            Note(stringResource(R.string.channel_note))
            error?.let { Note(stringResource(it), Ui.danger) }
            Primary(stringResource(R.string.channel_create), enabled = name.isNotBlank() && !session.busy) {
                session.createChannel(name, picked.toList()) { id, e -> error = e; if (id != null) onOpen(org.aegis.messenger.data.channelKey(id)) }
            }
        }
    }
}

@Composable
fun ChannelInfoScreen(session: Session, d: VaultData, id: String, onBack: () -> Unit, onLeft: () -> Unit) {
    val ch = d.channel(id)
    if (ch == null) { androidx.compose.runtime.LaunchedEffect(Unit) { onBack() }; return }
    val key = org.aegis.messenger.data.channelKey(ch.id)
    var confirmLeave by remember { mutableStateOf(false) }
    var confirmClear by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.profile_title), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState())) {
            ProfileHeader(
                if (ch.official) ch.ownerEd else seedOf("c:" + ch.id), ch.name,
                stringResource(if (ch.official) R.string.official_status else R.string.channel_status), "", org.aegis.messenger.core.Particles.None,
            )
            SharedMedia(session, d.chat(key).messages)
            Divider()
            Section(stringResource(R.string.group_actions)) {
                Secondary(stringResource(R.string.clear_history), danger = true) { confirmClear = true }
                if (!ch.official) Secondary(stringResource(R.string.delete), danger = true) { confirmLeave = true }
            }
        }
    }
    if (confirmClear) Confirm(
        stringResource(R.string.clear_history), stringResource(R.string.clear_history_body), stringResource(R.string.delete),
        { session.deleteChatHistory(key); confirmClear = false }, { confirmClear = false },
    )
    if (confirmLeave) Confirm(
        stringResource(R.string.delete_chats_title), stringResource(R.string.delete_chats_body), stringResource(R.string.delete),
        { confirmLeave = false; session.deleteChannel(ch.id); onLeft() }, { confirmLeave = false },
    )
}
