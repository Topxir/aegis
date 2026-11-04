package org.aegis.messenger.ui

import androidx.compose.foundation.clickable
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
    )
}

@Composable
private fun ttlLabel(s: Long): String = when (s) {
    0L -> stringResource(R.string.ttl_off)
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
        Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp)) {
            Field(user, { user = it; error = null }, stringResource(R.string.field_contact_username), keyboard = androidx.compose.ui.text.input.KeyboardType.Ascii)
            Note(stringResource(R.string.new_chat_note))
            error?.let { Note(stringResource(it), Ui.danger) }
            if (session.busy) Note(stringResource(R.string.working))
            Primary(stringResource(R.string.find_and_add), enabled = user.isNotBlank() && !session.busy) {
                session.addContact(user) { u, e -> error = e; if (u != null) onOpen(dmKey(u)) }
            }
            Secondary(stringResource(R.string.new_group)) { onGroup() }
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
                    Text("@" + c.username + if (c.title.isNotBlank()) "  " + c.title else "", color = Ui.text, modifier = Modifier.padding(start = 12.dp))
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
        TopBar("@" + c.username, c.title.ifBlank { null }, onBack = onBack)
        Divider()
        Column(Modifier.verticalScroll(rememberScrollState())) {
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
                Text(safety ?: "", style = MaterialTheme.typography.bodyLarge, color = Ui.text)
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
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(g.name, stringResource(R.string.members_count, g.members.size), onBack = onBack)
        Divider()
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Section(stringResource(R.string.members)) {
                g.members.forEach { m ->
                    Text(if (m == d.username) "@$m  (" + stringResource(R.string.you) + ")" else "@$m", color = Ui.text, modifier = Modifier.padding(vertical = 4.dp))
                }
                Note(stringResource(R.string.group_trust_note))
            }
            Divider()
            TtlPicker(g.ttlS) { session.setChatTtl(groupKey(g.id), it) }
            Divider()
            Section(stringResource(R.string.group_actions)) {
                Secondary(stringResource(R.string.resend_invites)) { session.resendInvites(g.id) }
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
    if (confirmLeave) Confirm(
        stringResource(R.string.leave_group), stringResource(R.string.leave_body), stringResource(R.string.leave),
        { confirmLeave = false; session.leaveGroup(g.id); onLeft() }, { confirmLeave = false },
    )
}
