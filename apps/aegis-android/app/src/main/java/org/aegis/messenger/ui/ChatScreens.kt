package org.aegis.messenger.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.data.Message
import org.aegis.messenger.data.Status
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.data.dmKey
import org.aegis.messenger.data.groupKey
import java.text.DateFormat
import java.util.Date

private class Row_(val key: String, val title: String, val last: Message?, val unread: Int, val isGroup: Boolean)

private fun rows(d: VaultData): List<Row_> {
    val dms = d.contacts.map {
        val c = d.chat(dmKey(it.username))
        Row_(dmKey(it.username), it.title.ifBlank { "@" + it.username }, c.messages.lastOrNull(), c.unread, false)
    }
    val groups = d.groups.map {
        val c = d.chat(groupKey(it.id))
        Row_(groupKey(it.id), it.name, c.messages.lastOrNull(), c.unread, true)
    }
    return (dms + groups).sortedByDescending { it.last?.tsMs ?: 0L }
}

fun formatTime(ms: Long): String {
    val now = System.currentTimeMillis()
    val d = Date(ms)
    return if (now - ms < 20 * 3600_000L) DateFormat.getTimeInstance(DateFormat.SHORT).format(d)
    else DateFormat.getDateInstance(DateFormat.SHORT).format(d)
}

@Composable
fun ChatListScreen(session: Session, d: VaultData, onOpen: (String) -> Unit, onNew: () -> Unit, onSettings: () -> Unit) {
    val list = rows(d)
    Box(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            TopBar(stringResource(R.string.app_name), actions = {
                BarIcon(AegisIcons.Lock, stringResource(R.string.lock_now)) { session.lock() }
                BarIcon(AegisIcons.Settings, stringResource(R.string.settings)) { onSettings() }
            })
            Divider()
            if (list.isEmpty()) {
                Column(Modifier.fillMaxSize().padding(32.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(stringResource(R.string.list_empty), style = MaterialTheme.typography.bodyMedium, color = Ui.muted)
                }
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(list, key = { it.key }) { r -> ChatRow(r) { onOpen(r.key) } }
                }
            }
        }
        FloatingActionButton(
            onClick = onNew,
            containerColor = Ui.accent,
            contentColor = Ui.onAccent,
            elevation = FloatingActionButtonDefaults.elevation(0.dp, 0.dp, 0.dp, 0.dp),
            modifier = Modifier.align(Alignment.BottomEnd).navigationBarsPadding().padding(20.dp),
        ) { Icon(AegisIcons.Plus, stringResource(R.string.new_chat)) }
    }
}

@Composable
private fun ChatRow(r: Row_, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Avatar(r.title)
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (r.isGroup) {
                    Icon(AegisIcons.Users, null, tint = Ui.muted, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.size(6.dp))
                }
                Text(r.title, style = MaterialTheme.typography.titleMedium, color = Ui.text, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
            }
            Text(
                r.last?.body?.lineSequence()?.firstOrNull() ?: "",
                style = MaterialTheme.typography.bodyMedium, color = Ui.muted, maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            r.last?.let { Text(formatTime(it.tsMs), style = MaterialTheme.typography.bodySmall, color = Ui.muted) }
            if (r.unread > 0) {
                Spacer(Modifier.size(4.dp))
                Box(Modifier.clip(CircleShape).background(Ui.accent).padding(horizontal = 7.dp, vertical = 1.dp)) {
                    Text(r.unread.toString(), style = MaterialTheme.typography.labelMedium, color = Ui.onAccent)
                }
            }
        }
    }
}

@Composable
fun ChatScreen(session: Session, d: VaultData, key: String, onBack: () -> Unit, onInfo: () -> Unit) {
    val isGroup = key.startsWith("g:")
    val contact = if (isGroup) null else d.contact(key.removePrefix("dm:"))
    val group = if (isGroup) d.group(key.removePrefix("g:")) else null
    if (contact == null && group == null) { LaunchedEffect(Unit) { onBack() }; return }
    val title = group?.name ?: contact!!.title.ifBlank { "@" + contact.username }
    val sub = group?.let { stringResource(R.string.members_count, it.members.size) } ?: ("@" + contact!!.username)
    val chat = d.chat(key)
    val blocked = contact?.keyChanged == true
    var text by remember { mutableStateOf("") }
    val state = rememberLazyListState()

    LaunchedEffect(key) { session.openChat = key }
    LaunchedEffect(key, chat.messages.size) {
        session.markRead(key)
        if (chat.messages.isNotEmpty()) state.scrollToItem(chat.messages.size - 1)
    }
    LaunchedEffect(Unit) { while (true) { delay(30_000); session.purgeNow() } }
    androidx.compose.runtime.DisposableEffect(key) { onDispose { if (session.openChat == key) session.openChat = null } }

    Column(Modifier.fillMaxSize().imePadding().navigationBarsPadding()) {
        TopBar(title, sub, onBack = onBack) {
            BarIcon(if (isGroup) AegisIcons.Users else AegisIcons.Shield, stringResource(R.string.info), onInfo)
        }
        Divider()
        if (blocked) {
            Banner(stringResource(R.string.key_changed_banner, contact!!.username), Ui.warning) {
                Link(stringResource(R.string.key_changed_review), onInfo)
            }
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth(), state = state, contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(chat.messages, key = { it.id }) { m ->
                Bubble(m, showSender = isGroup && !m.outgoing) { if (m.status == Status.FAILED) session.retry(key, m.id) }
            }
        }
        if (chat.messages.isEmpty()) {
            Note(stringResource(R.string.chat_empty), Ui.muted)
        }
        Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.Bottom) {
            OutlinedTextField(
                value = text,
                onValueChange = { if (it.length <= Session.MAX_TEXT_CHARS) text = it },
                placeholder = { Text(stringResource(R.string.message_hint)) },
                enabled = !blocked,
                maxLines = 5,
                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Ui.accent, unfocusedBorderColor = Ui.border, cursorColor = Ui.accent),
                shape = RoundedCornerShape(22.dp),
                modifier = Modifier.weight(1f),
            )
            IconButton(
                enabled = !blocked && text.isNotBlank(),
                onClick = {
                    if (group != null) session.sendGroup(group.id, text) else session.sendDm(contact!!.username, text)
                    text = ""
                },
            ) { Icon(AegisIcons.Send, stringResource(R.string.send), tint = if (!blocked && text.isNotBlank()) Ui.accent else Ui.muted) }
        }
    }
}

@Composable
private fun Bubble(m: Message, showSender: Boolean, onFailedClick: () -> Unit) {
    val out = m.outgoing
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (out) Arrangement.End else Arrangement.Start) {
        Column(
            Modifier.widthIn(max = 300.dp).clip(RoundedCornerShape(14.dp))
                .background(if (out) Ui.surface2 else Ui.surface)
                .clickable(enabled = m.status == Status.FAILED, onClick = onFailedClick)
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            if (showSender) Text(m.senderName.ifBlank { "@" + m.sender }, style = MaterialTheme.typography.labelMedium, color = Ui.accent)
            Text(m.body, style = MaterialTheme.typography.bodyLarge, color = Ui.text)
            Row(Modifier.align(Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                if (m.ttlS > 0) {
                    Icon(AegisIcons.Clock, null, tint = Ui.muted, modifier = Modifier.size(12.dp))
                    Spacer(Modifier.size(3.dp))
                }
                val status = when (m.status) {
                    Status.SENDING -> stringResource(R.string.status_sending) + "  "
                    Status.FAILED -> stringResource(R.string.status_failed) + "  "
                    else -> ""
                }
                Text(status + formatTime(m.tsMs), style = MaterialTheme.typography.bodySmall, color = if (m.status == Status.FAILED) Ui.danger else Ui.muted)
            }
        }
    }
}
