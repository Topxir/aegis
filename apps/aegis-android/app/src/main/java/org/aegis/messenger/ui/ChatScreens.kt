package org.aegis.messenger.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.sp
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
            Row(
                Modifier.fillMaxWidth().statusBarsPadding().padding(start = 20.dp, end = 4.dp, top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.app_name).uppercase(),
                        style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 4.sp), color = Ui.muted,
                    )
                    Text(stringResource(R.string.chats_title), style = MaterialTheme.typography.displaySmall, color = Ui.text)
                }
                BarIcon(AegisIcons.Lock, stringResource(R.string.lock_now)) { session.lock() }
                BarIcon(AegisIcons.Settings, stringResource(R.string.settings)) { onSettings() }
            }
            Spacer(Modifier.height(8.dp))
            if (list.isEmpty()) {
                Column(Modifier.fillMaxSize().padding(32.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(stringResource(R.string.list_empty), style = MaterialTheme.typography.bodyMedium, color = Ui.muted)
                    Text(stringResource(R.string.keys_hint), style = MaterialTheme.typography.bodySmall, color = Ui.muted, modifier = Modifier.padding(top = 12.dp))
                }
            } else {
                LazyColumn(Modifier.weight(1f).fillMaxWidth(), contentPadding = PaddingValues(bottom = 96.dp)) {
                    items(list, key = { it.key }) { r -> ChatRow(r) { onOpen(r.key) } }
                    item {
                        Text(
                            stringResource(R.string.keys_hint), style = MaterialTheme.typography.bodySmall, color = Ui.muted,
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 20.dp),
                        )
                    }
                }
            }
        }
        Box(
            Modifier.align(Alignment.BottomEnd).navigationBarsPadding().padding(20.dp).size(56.dp)
                .clip(RoundedCornerShape(18.dp)).background(Ui.lightGradient)
                .clickable(role = Role.Button, onClick = onNew),
            contentAlignment = Alignment.Center,
        ) { Icon(AegisIcons.Plus, stringResource(R.string.new_chat), tint = Ui.onAccent) }
    }
}

@Composable
private fun ChatRow(r: Row_, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 64.dp).clickable(onClick = onClick).padding(horizontal = 20.dp, vertical = 10.dp),
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
                Text(r.title, style = MaterialTheme.typography.titleMedium.copy(fontFamily = if (r.isGroup || r.title.startsWith("@")) GeistMono else Geist), color = Ui.text, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
            }
            Text(
                r.last?.body?.lineSequence()?.firstOrNull() ?: "",
                style = MaterialTheme.typography.bodyMedium, color = Ui.muted, maxLines = 1, overflow = TextOverflow.Ellipsis,
            )
        }
        Column(horizontalAlignment = Alignment.End) {
            r.last?.let { Text(formatTime(it.tsMs), style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono), color = Ui.muted) }
            if (r.unread > 0) {
                Spacer(Modifier.size(4.dp))
                Box(Modifier.clip(CircleShape).background(Ui.accent).defaultMinSize(minWidth = 20.dp).padding(horizontal = 7.dp, vertical = 1.dp), contentAlignment = Alignment.Center) {
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
    val seen = remember(key) { chat.messages.map { it.id }.toHashSet() }
    val anim = animationsOn()

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
        if (blocked) {
            Banner(stringResource(R.string.key_changed_banner, contact!!.username), Ui.warning) {
                Link(stringResource(R.string.key_changed_review), onInfo)
            }
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth(), state = state, contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(chat.messages, key = { it.id }) { m ->
                Bubble(m, showSender = isGroup && !m.outgoing, animate = anim, seen = seen) { if (m.status == Status.FAILED) session.retry(key, m.id) }
            }
        }
        if (chat.messages.isEmpty()) {
            Note(stringResource(R.string.chat_empty), Ui.muted)
        }
        val canSend = !blocked && text.isNotBlank()
        Row(
            Modifier.fillMaxWidth().padding(10.dp).clip(RoundedCornerShape(22.dp)).background(Ui.surface)
                .border(1.dp, Ui.border, RoundedCornerShape(22.dp)).padding(start = 16.dp, top = 6.dp, end = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.Bottom,
        ) {
            BasicTextField(
                value = text,
                onValueChange = { if (it.length <= Session.MAX_TEXT_CHARS) text = it },
                enabled = !blocked,
                maxLines = 5,
                textStyle = MaterialTheme.typography.bodyLarge.copy(color = Ui.text),
                cursorBrush = SolidColor(Ui.accent),
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                decorationBox = { inner ->
                    Box(Modifier.heightIn(min = 48.dp), contentAlignment = Alignment.CenterStart) {
                        if (text.isEmpty()) Text(stringResource(R.string.message_hint), style = MaterialTheme.typography.bodyLarge, color = Ui.muted)
                        inner()
                    }
                },
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.size(6.dp))
            Box(
                Modifier.size(48.dp).clip(RoundedCornerShape(14.dp))
                    .background(if (canSend) Ui.lightGradient else SolidColor(Ui.surface2))
                    .clickable(enabled = canSend, role = Role.Button, onClickLabel = stringResource(R.string.send)) {
                        if (group != null) session.sendGroup(group.id, text) else session.sendDm(contact!!.username, text)
                        text = ""
                    },
                contentAlignment = Alignment.Center,
            ) { Icon(AegisIcons.ArrowUp, stringResource(R.string.send), tint = if (canSend) Ui.onAccent else Ui.muted) }
        }
    }
}

@Composable
private fun Bubble(m: Message, showSender: Boolean, animate: Boolean, seen: MutableSet<String>, onFailedClick: () -> Unit) {
    val out = m.outgoing
    val fresh = animate && m.id !in seen
    val progress = remember(m.id) { Animatable(if (fresh) 0f else 1f) }
    val slidePx = with(LocalDensity.current) { 6.dp.toPx() }
    LaunchedEffect(m.id) {
        if (fresh) progress.animateTo(1f, tween(Ui.ENTER_MS))
        seen.add(m.id)
    }
    // 16/16/16/5, the small corner mirrored for outgoing
    val shape = RoundedCornerShape(16.dp, 16.dp, if (out) 5.dp else 16.dp, if (out) 16.dp else 5.dp)
    val fg = if (out) Ui.onAccent else Ui.text
    val sub = if (out) Color(0xFF55565C) else Ui.muted
    Row(
        Modifier.fillMaxWidth().graphicsLayer { alpha = progress.value; translationY = (1f - progress.value) * slidePx },
        horizontalArrangement = if (out) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            Modifier.widthIn(max = 300.dp).clip(shape)
                .then(if (out) Modifier.background(Ui.outBubble) else Modifier.background(Ui.surface2).border(1.dp, Ui.bubbleBorder, shape))
                .clickable(enabled = m.status == Status.FAILED, onClick = onFailedClick)
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            if (showSender) Text(m.senderName.ifBlank { "@" + m.sender }, style = MaterialTheme.typography.labelMedium.copy(fontFamily = GeistMono), color = Ui.muted)
            Text(m.body, style = MaterialTheme.typography.bodyLarge, color = fg)
            Row(Modifier.align(Alignment.End), verticalAlignment = Alignment.CenterVertically) {
                if (m.ttlS > 0) {
                    Icon(AegisIcons.Clock, null, tint = sub, modifier = Modifier.size(12.dp))
                    Spacer(Modifier.size(3.dp))
                }
                val status = when (m.status) {
                    Status.SENDING -> stringResource(R.string.status_sending) + "  "
                    Status.FAILED -> stringResource(R.string.status_failed) + "  "
                    else -> ""
                }
                Text(status + formatTime(m.tsMs), style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono), color = if (m.status == Status.FAILED) (if (out) Color(0xFF9A2F27) else Ui.danger) else sub)
            }
        }
    }
}
