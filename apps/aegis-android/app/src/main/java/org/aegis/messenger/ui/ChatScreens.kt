package org.aegis.messenger.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetDefaults
import androidx.compose.ui.window.PopupProperties
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Names
import org.aegis.messenger.data.Media
import org.aegis.messenger.data.Message
import org.aegis.messenger.data.Status
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.data.channelKey
import org.aegis.messenger.data.dmKey
import org.aegis.messenger.data.groupKey
import java.text.DateFormat
import java.util.Calendar
import java.util.Date

internal enum class Kind { Dm, Group, Channel }
private enum class Tab { All, Groups, Channels }

internal class Row_(
    val key: String,
    val title: String,
    val seed: ByteArray,
    val kind: Kind,
    val last: Message?,
    val unread: Int,
    val pinned: Boolean,
    val muted: Boolean,
    val official: Boolean,
)

internal fun rows(d: VaultData): List<Row_> {
    val dms = d.contacts.map {
        val k = dmKey(it.username)
        val c = d.chat(k)
        Row_(k, it.title.ifBlank { "@" + it.username }, it.ed, Kind.Dm, c.messages.lastOrNull(), c.unread, d.pref(k).pinned, d.pref(k).muted, false)
    }
    val groups = d.groups.map {
        val k = groupKey(it.id)
        val c = d.chat(k)
        Row_(k, it.name, seedOf("g:" + it.id), Kind.Group, c.messages.lastOrNull(), c.unread, d.pref(k).pinned, d.pref(k).muted, false)
    }
    val channels = d.channels.map {
        val k = channelKey(it.id)
        val c = d.chat(k)
        Row_(k, it.name, if (it.official) it.ownerEd else seedOf("c:" + it.id), Kind.Channel, c.messages.lastOrNull(), c.unread, d.pref(k).pinned || it.official, d.pref(k).muted, it.official)
    }
    return (dms + groups + channels).sortedWith(
        compareByDescending<Row_> { it.official }.thenByDescending { it.pinned }.thenByDescending { it.last?.tsMs ?: 0L },
    )
}

fun formatTime(ms: Long): String {
    val now = System.currentTimeMillis()
    val d = Date(ms)
    return if (now - ms < 20 * 3600_000L) DateFormat.getTimeInstance(DateFormat.SHORT).format(d)
    else DateFormat.getDateInstance(DateFormat.SHORT).format(d)
}

private fun dayOf(ms: Long): Int {
    val c = Calendar.getInstance().apply { timeInMillis = ms }
    return c.get(Calendar.YEAR) * 400 + c.get(Calendar.DAY_OF_YEAR)
}

@Composable
private fun previewOf(m: Message?): String {
    if (m == null) return ""
    m.timer?.let { return timerText(it, if (m.outgoing) stringResource(R.string.ttl_you) else m.senderName.ifBlank { "@" + m.sender }) }
    val prefix = if (m.outgoing) stringResource(R.string.you_prefix) else ""
    val media = m.media
    val body = m.body.lineSequence().firstOrNull() ?: ""
    val label = when {
        media == null -> body
        media.kind == org.aegis.messenger.core.MediaKind.Video -> stringResource(R.string.media_video) + if (body.isNotEmpty()) ", $body" else ""
        else -> stringResource(R.string.media_photo) + if (body.isNotEmpty()) ", $body" else ""
    }
    return prefix + label
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatListScreen(
    session: Session,
    d: VaultData,
    onOpen: (String) -> Unit,
    onRoute: (String) -> Unit,
) {
    val all = rows(d)
    var tab by remember { mutableStateOf(Tab.All) }
    var searching by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var sheet by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    val selected = remember { mutableStateListOf<String>() }
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val anim = animationsOn()

    fun inTab(r: Row_) = when (tab) {
        Tab.All -> true
        Tab.Groups -> r.kind == Kind.Group
        Tab.Channels -> r.kind == Kind.Channel
    }
    val q = query.trim().lowercase()
    val shown = all.filter { inTab(it) && (q.isEmpty() || it.title.lowercase().contains(q)) }
    fun unreadOf(t: Tab) = all.filter { r -> !r.muted && when (t) { Tab.All -> true; Tab.Groups -> r.kind == Kind.Group; Tab.Channels -> r.kind == Kind.Channel } }.sumOf { it.unread }

    androidx.activity.compose.BackHandler(selected.isNotEmpty() || searching || drawer.isOpen) {
        when {
            drawer.isOpen -> scope.launch { drawer.close() }
            selected.isNotEmpty() -> selected.clear()
            else -> { searching = false; query = "" }
        }
    }

    ModalNavigationDrawer(
        drawerState = drawer,
        gesturesEnabled = selected.isEmpty(),
        drawerContent = {
            ModalDrawerSheet(drawerContainerColor = Ui.surface, drawerContentColor = Ui.text, modifier = Modifier.widthIn(max = 320.dp)) {
                DrawerHeader(d)
                val go: (String) -> Unit = { r -> scope.launch { drawer.close() }; onRoute(r) }
                DrawerItem(AegisIcons.User, stringResource(R.string.account)) { go("account") }
                DrawerItem(AegisIcons.Users, stringResource(R.string.new_group)) { go("newgroup") }
                DrawerItem(AegisIcons.Megaphone, stringResource(R.string.new_channel)) { go("newchannel") }
                DrawerItem(AegisIcons.Send, stringResource(R.string.contacts)) { go("contacts") }
                val pending = remember(session.requestTick) { session.requests().size }
                if (pending > 0) DrawerItem(AegisIcons.User, stringResource(R.string.requests_count, pending)) { go("requests") }
                DrawerItem(AegisIcons.Settings, stringResource(R.string.settings)) { go("settings") }
                Spacer(Modifier.weight(1f))
                DrawerItem(AegisIcons.Lock, stringResource(R.string.lock_now)) { scope.launch { drawer.close() }; session.lock() }
                Spacer(Modifier.height(12.dp))
            }
        },
    ) {
        Box(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize()) {
                if (selected.isNotEmpty()) {
                    Row(Modifier.fillMaxWidth().statusBarsPadding().heightIn(min = 56.dp).padding(horizontal = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        BarIcon(AegisIcons.Close, stringResource(R.string.cancel)) { selected.clear() }
                        Text(stringResource(R.string.selected_count, selected.size), style = MaterialTheme.typography.titleLarge, color = Ui.text, modifier = Modifier.weight(1f))
                        val allPinned = selected.all { k -> d.pref(k).pinned }
                        BarIcon(AegisIcons.Pin, stringResource(if (allPinned) R.string.unpin else R.string.pin)) {
                            session.setPinned(selected.toList(), !allPinned); selected.clear()
                        }
                        val allMuted = selected.all { k -> d.pref(k).muted }
                        BarIcon(AegisIcons.Mute, stringResource(if (allMuted) R.string.unmute else R.string.mute)) {
                            session.setMuted(selected.toList(), !allMuted); selected.clear()
                        }
                        BarIcon(AegisIcons.Trash, stringResource(R.string.delete)) { confirmDelete = true }
                    }
                } else {
                    Row(Modifier.fillMaxWidth().statusBarsPadding().heightIn(min = 56.dp).padding(horizontal = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.guideTarget("menu")) { BarIcon(AegisIcons.Menu, stringResource(R.string.menu)) { scope.launch { drawer.open() } } }
                        if (searching) {
                            ImeText(
                                query, { query = it }, stringResource(R.string.search_hint),
                                Modifier.weight(1f), search = true, autoFocus = true,
                                onSubmit = {
                                    val u = query.trim().removePrefix("@")
                                    if (u.isNotEmpty() && runCatching { Names.normalizeUsername(u) }.isSuccess) {
                                        session.addContact(u) { name, _ -> if (name != null) onOpen(dmKey(name)) }
                                    }
                                },
                            )
                            BarIcon(AegisIcons.Close, stringResource(R.string.cancel)) { searching = false; query = "" }
                        } else {
                            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge, color = Ui.text, modifier = Modifier.weight(1f).padding(start = 8.dp))
                            Box(Modifier.guideTarget("search")) { BarIcon(AegisIcons.Search, stringResource(R.string.search)) { searching = true } }
                        }
                    }
                }
                val ctx = androidx.compose.ui.platform.LocalContext.current
                StatusStrip(session, d, remember { org.aegis.messenger.app.Boot.tor(ctx) }, onRoute)
                FolderTabs(tab, { tab = it }, anim, unreadOf(Tab.All), unreadOf(Tab.Groups), unreadOf(Tab.Channels))
                if (session.busy) LinearProgressIndicator(Modifier.fillMaxWidth().height(2.dp), color = Ui.accent, trackColor = Ui.border)
                val listState = rememberLazyListState()
                val tilt = depthOn()
                LazyColumn(Modifier.weight(1f).fillMaxWidth(), state = listState, contentPadding = PaddingValues(bottom = 96.dp)) {
                    items(shown, key = { it.key }) { r ->
                        ChatRow(r, r.key in selected, selected.isNotEmpty(), if (tilt) Modifier.depth(listState, r.key) else Modifier,
                            onClick = { if (selected.isNotEmpty()) { if (r.key in selected) selected.remove(r.key) else selected.add(r.key) } else onOpen(r.key) },
                            onLong = { if (!r.official || selected.isNotEmpty()) { if (r.key in selected) selected.remove(r.key) else selected.add(r.key) } else selected.add(r.key) })
                    }
                    if (searching && q.isNotEmpty()) {
                        item {
                            Text(
                                stringResource(R.string.search_lookup, query.trim().removePrefix("@")),
                                style = MaterialTheme.typography.bodyMedium, color = Ui.muted,
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
                            )
                        }
                    }
                    if (shown.isEmpty() && q.isEmpty()) {
                        item {
                            Text(
                                stringResource(R.string.list_empty), style = MaterialTheme.typography.bodyMedium, color = Ui.muted,
                                modifier = Modifier.fillMaxWidth().padding(32.dp),
                            )
                        }
                    }
                }
            }
            if (selected.isEmpty()) {
                Box(
                    Modifier.align(Alignment.BottomEnd).navigationBarsPadding().padding(20.dp).size(56.dp)
                        .clip(CircleShape).background(Ui.lightGradient)
                        .clickable(role = Role.Button, onClickLabel = stringResource(R.string.new_chat)) { sheet = true },
                    contentAlignment = Alignment.Center,
                ) { Icon(AegisIcons.Pencil, stringResource(R.string.new_chat), tint = Ui.onAccent) }
            }
        }
    }

    if (sheet) ModalBottomSheet(
        onDismissRequest = { sheet = false }, containerColor = Ui.surface, contentColor = Ui.text,
        properties = ModalBottomSheetDefaults.properties(securePolicy = securePolicy()),
    ) {
        Column(Modifier.navigationBarsPadding().padding(bottom = 12.dp)) {
            SheetItem(AegisIcons.Send, stringResource(R.string.new_chat)) { sheet = false; onRoute("new") }
            SheetItem(AegisIcons.Users, stringResource(R.string.new_group)) { sheet = false; onRoute("newgroup") }
            SheetItem(AegisIcons.Megaphone, stringResource(R.string.new_channel)) { sheet = false; onRoute("newchannel") }
        }
    }
    if (confirmDelete) Confirm(
        stringResource(R.string.delete_chats_title), stringResource(R.string.delete_chats_body), stringResource(R.string.delete),
        { session.deleteChats(selected.toList()); selected.clear(); confirmDelete = false }, { confirmDelete = false },
    )
}

@Composable
private fun DrawerHeader(d: VaultData) {
    val ed = remember(d.edSk.toList()) { Crypto.ed25519Public(d.edSk) }
    Column(Modifier.fillMaxWidth().statusBarsPadding().padding(20.dp)) {
        AvatarView(ed, 64)
        Spacer(Modifier.height(10.dp))
        Text(d.profile.name.ifBlank { d.settings.displayName }.ifBlank { "@" + d.username }, style = MaterialTheme.typography.titleMedium, color = Ui.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text("@" + d.username, style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono), color = Ui.muted)
    }
    HeadLine()
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun DrawerItem(icon: ImageVector, label: String, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 52.dp).clickable(role = Role.Button, onClick = onClick).padding(horizontal = 22.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, null, tint = Ui.muted, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(20.dp))
        Text(label, style = MaterialTheme.typography.bodyLarge, color = Ui.text)
    }
}

@Composable
private fun SheetItem(icon: ImageVector, label: String, onClick: () -> Unit) = DrawerItem(icon, label, onClick)

@Composable
private fun FolderTabs(tab: Tab, onTab: (Tab) -> Unit, anim: Boolean, a: Int, g: Int, c: Int) {
    val labels = listOf(Tab.All to stringResource(R.string.tab_all), Tab.Groups to stringResource(R.string.tab_groups), Tab.Channels to stringResource(R.string.tab_channels))
    val counts = mapOf(Tab.All to a, Tab.Groups to g, Tab.Channels to c)
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val w = maxWidth / 3
        val pos by animateFloatAsState(tab.ordinal.toFloat(), tween(if (anim) 200 else 0), label = "tab")
        Column {
            Row {
                labels.forEach { (t, label) ->
                    Row(
                        Modifier.weight(1f).height(44.dp).clickable(role = Role.Tab) { onTab(t) },
                        horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(label, style = MaterialTheme.typography.labelLarge, color = if (t == tab) Ui.text else Ui.muted, maxLines = 1)
                        val n = counts[t] ?: 0
                        if (n > 0) {
                            Spacer(Modifier.width(6.dp))
                            Box(Modifier.clip(CircleShape).background(if (t == tab) Ui.accent else Ui.border).defaultMinSize(minWidth = 18.dp).padding(horizontal = 5.dp)) {
                                Text(n.toString(), style = MaterialTheme.typography.labelMedium.copy(fontSize = 11.sp), color = if (t == tab) Ui.onAccent else Ui.text, modifier = Modifier.align(Alignment.Center))
                            }
                        }
                    }
                }
            }
            Box(Modifier.fillMaxWidth().height(2.dp)) {
                Box(Modifier.offset(x = w * pos).width(w).height(2.dp).padding(horizontal = 24.dp).background(Ui.lightGradient))
            }
            Divider()
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ChatRow(r: Row_, selected: Boolean, selecting: Boolean, modifier: Modifier, onClick: () -> Unit, onLong: () -> Unit) {
    val compact = Ui.look.compact
    Row(
        modifier.fillMaxWidth().height(if (compact) 60.dp else 72.dp).background(if (selected) Ui.surface2 else Color.Transparent)
            .combinedClickable(onClick = onClick, onLongClick = onLong).padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box {
            AvatarView(r.seed, if (compact) 44 else 52)
            if (selected) Box(Modifier.align(Alignment.BottomEnd).size(20.dp).clip(CircleShape).background(Ui.accent), contentAlignment = Alignment.Center) {
                Icon(AegisIcons.Check, null, tint = Ui.onAccent, modifier = Modifier.size(14.dp))
            }
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (r.kind == Kind.Group) { Icon(AegisIcons.Users, null, tint = Ui.muted, modifier = Modifier.size(15.dp)); Spacer(Modifier.width(5.dp)) }
                if (r.kind == Kind.Channel) { Icon(AegisIcons.Megaphone, null, tint = Ui.muted, modifier = Modifier.size(15.dp)); Spacer(Modifier.width(5.dp)) }
                Text(r.title, style = MaterialTheme.typography.titleMedium, color = Ui.text, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                if (r.muted) { Spacer(Modifier.width(6.dp)); Icon(AegisIcons.Mute, null, tint = Ui.muted, modifier = Modifier.size(14.dp)) }
                Spacer(Modifier.weight(1f))
                r.last?.let { Text(formatTime(it.tsMs), style = MaterialTheme.typography.bodySmall, color = Ui.muted) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(previewOf(r.last), style = MaterialTheme.typography.bodyMedium, color = Ui.muted, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                if (r.pinned && r.unread == 0) Icon(AegisIcons.Pin, null, tint = Ui.muted, modifier = Modifier.size(14.dp))
                if (r.unread > 0) {
                    Spacer(Modifier.width(8.dp))
                    Box(Modifier.clip(CircleShape).background(if (r.muted) Ui.border else Ui.accent).defaultMinSize(minWidth = 20.dp).padding(horizontal = 6.dp, vertical = 1.dp), contentAlignment = Alignment.Center) {
                        Text(r.unread.toString(), style = MaterialTheme.typography.labelMedium, color = if (r.muted) Ui.muted else Ui.onAccent)
                    }
                }
            }
        }
    }
}

// ---- chat screen ----------------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(
    session: Session, d: VaultData, key: String, onBack: () -> Unit,
    strip: (@Composable () -> Unit)? = null, onInfo: () -> Unit,
) {
    val kind = when { key.startsWith("g:") -> Kind.Group; key.startsWith("c:") -> Kind.Channel; else -> Kind.Dm }
    val contact = if (kind == Kind.Dm) d.contact(key.removePrefix("dm:")) else null
    val group = if (kind == Kind.Group) d.group(key.removePrefix("g:")) else null
    val channel = if (kind == Kind.Channel) d.channel(key.removePrefix("c:")) else null
    if (contact == null && group == null && channel == null) { LaunchedEffect(Unit) { onBack() }; return }
    val title = group?.name ?: channel?.name ?: contact!!.title.ifBlank { "@" + contact.username }
    val seed = contact?.ed ?: if (channel?.official == true) channel.ownerEd else seedOf(key)
    val sub = when {
        group != null -> stringResource(R.string.members_count, group.members.size)
        channel != null -> stringResource(if (channel.official) R.string.official_status else R.string.channel_status)
        else -> "@" + contact!!.username
    }
    val chat = d.chat(key)
    val blocked = contact?.keyChanged == true
    val canPost = kind != Kind.Channel || channel!!.mine(d.username)
    var text by remember { mutableStateOf("") }
    var viewer by remember { mutableStateOf<Media?>(null) }
    var menu by remember { mutableStateOf(false) }
    val state = rememberLazyListState()
    val seen = remember(key) { chat.messages.map { it.id }.toHashSet() }
    val anim = animationsOn()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) { session.sendMedia(key, uri, text); text = "" }
    }
    val muted = d.pref(key).muted

    LaunchedEffect(key) { session.openChat = key }
    LaunchedEffect(key, chat.messages.size) {
        session.markRead(key)
        if (chat.messages.isNotEmpty()) state.scrollToItem(chat.messages.size - 1)
    }
    LaunchedEffect(Unit) { while (true) { delay(30_000); session.purgeNow() } }
    DisposableEffect(key) { onDispose { if (session.openChat == key) session.openChat = null } }

    Column(Modifier.fillMaxSize().imePadding().navigationBarsPadding()) {
        Row(Modifier.fillMaxWidth().statusBarsPadding().heightIn(min = 56.dp).padding(end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            BarIcon(AegisIcons.ArrowLeft, stringResource(R.string.back), onBack)
            Row(Modifier.weight(1f).clickable(onClick = onInfo).padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                AvatarView(seed, 38)
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(title, style = MaterialTheme.typography.titleMedium, color = Ui.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(sub, style = MaterialTheme.typography.bodySmall, color = Ui.muted, maxLines = 1)
                }
            }
            Box {
                BarIcon(AegisIcons.More, stringResource(R.string.menu)) { menu = true }
                DropdownMenu(menu, { menu = false }, modifier = Modifier.background(Ui.surface2), properties = PopupProperties(focusable = true, securePolicy = securePolicy())) {
                    DropdownMenuItem({ Text(stringResource(R.string.profile_title), color = Ui.text) }, { menu = false; onInfo() })
                    DropdownMenuItem({ Text(stringResource(if (muted) R.string.unmute else R.string.mute), color = Ui.text) }, { menu = false; session.setMuted(listOf(key), !muted) })
                }
            }
        }
        HeadLine()
        strip?.invoke()
        if (blocked) {
            Banner(stringResource(R.string.key_changed_banner, contact!!.username), Ui.warning) {
                Link(stringResource(R.string.key_changed_review), onInfo)
            }
        }
        if (session.busy) LinearProgressIndicator(Modifier.fillMaxWidth().height(2.dp), color = Ui.accent, trackColor = Ui.border)
        val tilt = depthOn()
        LazyColumn(Modifier.weight(1f).fillMaxWidth().wallpaper(), state = state, contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp)) {
            items(chat.messages.size, key = { chat.messages[it].id }) { i ->
                val m = chat.messages[i]
                val prev = chat.messages.getOrNull(i - 1)
                val next = chat.messages.getOrNull(i + 1)
                val newDay = prev == null || dayOf(prev.tsMs) != dayOf(m.tsMs)
                val first = newDay || prev == null || prev.sender != m.sender || prev.outgoing != m.outgoing
                val last = next == null || next.sender != m.sender || next.outgoing != m.outgoing || dayOf(next.tsMs) != dayOf(m.tsMs)
                if (newDay) DatePill(m.tsMs)
                Spacer(Modifier.height(if (first) 8.dp else 2.dp))
                val timer = m.timer
                if (timer != null) {
                    val who = if (m.outgoing) stringResource(R.string.ttl_you) else d.contact(m.sender)?.title?.ifBlank { null } ?: m.senderName.ifBlank { "@" + m.sender }
                    TimerLine(timerText(timer, who), m.status == Status.FAILED) { session.retry(key, m.id) }
                } else if (kind == Kind.Channel) Box(if (tilt) Modifier.depth(state, m.id) else Modifier) {
                    PostCard(session, m, anim, seen, { viewer = it })
                } else Box(if (tilt) Modifier.depth(state, m.id) else Modifier) {
                    val senderSeed = d.contact(m.sender)?.ed ?: seedOf("u:" + m.sender)
                    Bubble(session, m, first, last, kind == Kind.Group, senderSeed, anim, seen, { viewer = it }) { if (m.status == Status.FAILED) session.retry(key, m.id) }
                }
            }
        }
        if (chat.messages.isEmpty()) Note(stringResource(R.string.chat_empty), Ui.muted)
        if (!canPost) {
            Box(
                Modifier.fillMaxWidth().height(52.dp).background(Ui.surface).clickable(role = Role.Button) { session.setMuted(listOf(key), !muted) },
                contentAlignment = Alignment.Center,
            ) { Text(stringResource(if (muted) R.string.unmute else R.string.mute), style = MaterialTheme.typography.labelLarge, color = Ui.text) }
        } else {
            val hasText = text.isNotBlank()
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 6.dp, vertical = 6.dp).clip(RoundedCornerShape(24.dp)).background(Ui.surface)
                    .border(1.dp, Ui.border, RoundedCornerShape(24.dp)).padding(start = 2.dp, end = 4.dp),
                verticalAlignment = Alignment.Bottom,
            ) {
                Box(Modifier.size(44.dp).clickable(enabled = !blocked && !session.busy, role = Role.Button, onClickLabel = stringResource(R.string.attach)) {
                    picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo))
                }, contentAlignment = Alignment.Center) { Icon(AegisIcons.Clip, stringResource(R.string.attach), tint = Ui.muted) }
                ImeText(text, { text = it }, stringResource(R.string.message_hint), Modifier.weight(1f).padding(vertical = 2.dp), enabled = !blocked, maxChars = Session.MAX_TEXT_CHARS)
                AnimatedVisibility(hasText && !blocked, enter = fadeIn(tween(150)) + scaleIn(tween(150)), exit = fadeOut(tween(120)) + scaleOut(tween(120))) {
                    Box(
                        Modifier.padding(start = 4.dp, bottom = 4.dp).size(40.dp).clip(CircleShape).background(Ui.lightGradient)
                            .clickable(role = Role.Button, onClickLabel = stringResource(R.string.send)) { session.sendText(key, text); text = "" },
                        contentAlignment = Alignment.Center,
                    ) { Icon(AegisIcons.ArrowUp, stringResource(R.string.send), tint = Ui.onAccent) }
                }
            }
        }
    }
    viewer?.let { MediaViewer(session, it) { viewer = null } }
}

@Composable
private fun timerText(ttlS: Long, who: String): String =
    if (ttlS == 0L) stringResource(R.string.ttl_line_off, who) else stringResource(R.string.ttl_line_set, who, ttlLabel(ttlS))

/** The local line left by a timer change; a failed one is sent again on tap. */
@Composable
private fun TimerLine(text: String, failed: Boolean, onRetry: () -> Unit) {
    Box(Modifier.fillMaxWidth().padding(vertical = 4.dp), contentAlignment = Alignment.Center) {
        Row(
            Modifier.clip(CircleShape).background(Ui.surface2).clickable(enabled = failed, role = Role.Button, onClick = onRetry)
                .padding(horizontal = 12.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(AegisIcons.Clock, null, tint = Ui.muted, modifier = Modifier.size(12.dp))
            Spacer(Modifier.width(6.dp))
            Text(text, style = MaterialTheme.typography.labelMedium, color = Ui.muted)
            if (failed) { Spacer(Modifier.width(6.dp)); Text("!", style = MaterialTheme.typography.labelMedium, color = Ui.danger) }
        }
    }
}

@Composable
private fun DatePill(ms: Long) {
    Box(Modifier.fillMaxWidth().padding(top = 10.dp, bottom = 2.dp), contentAlignment = Alignment.Center) {
        Text(
            DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(ms)),
            style = MaterialTheme.typography.labelMedium, color = Ui.muted,
            modifier = Modifier.clip(CircleShape).background(Ui.surface2).padding(horizontal = 12.dp, vertical = 4.dp),
        )
    }
}

@Composable
private fun enterAnim(m: Message, animate: Boolean, seen: MutableSet<String>): Modifier {
    val fresh = animate && m.id !in seen
    val progress = remember(m.id) { androidx.compose.animation.core.Animatable(if (fresh) 0f else 1f) }
    val slidePx = with(LocalDensity.current) { 6.dp.toPx() }
    LaunchedEffect(m.id) {
        if (fresh) progress.animateTo(1f, tween(Ui.ANIM_MS))
        seen.add(m.id)
    }
    return Modifier.graphicsLayer { alpha = progress.value; translationY = (1f - progress.value) * slidePx }
}

@Composable
private fun TimeAndStatus(m: Message, color: Color, modifier: Modifier = Modifier) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        if (m.ttlS > 0) { Icon(AegisIcons.Clock, null, tint = color, modifier = Modifier.size(11.dp)); Spacer(Modifier.width(3.dp)) }
        Text(formatTime(m.tsMs), style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp), color = color)
        if (m.outgoing) {
            Spacer(Modifier.width(3.dp))
            when (m.status) {
                Status.SENDING -> Icon(AegisIcons.Clock, null, tint = color, modifier = Modifier.size(12.dp))
                Status.FAILED -> Text("!", style = MaterialTheme.typography.labelMedium, color = Ui.danger)
                else -> Icon(AegisIcons.Check, null, tint = color, modifier = Modifier.size(13.dp))
            }
        }
    }
}

@Composable
private fun MediaBody(session: Session, m: Message, media: Media, onMedia: (Media) -> Unit, hasCaption: Boolean) {
    Box {
        MediaThumb(session, media, Modifier.fillMaxWidth(), onClick = { onMedia(media) })
        if (media.kind == org.aegis.messenger.core.MediaKind.Video && media.durationMs > 0) {
            Text(durationLabel(media.durationMs), style = MaterialTheme.typography.labelMedium, color = Color.White,
                modifier = Modifier.align(Alignment.TopStart).padding(6.dp).clip(CircleShape).background(Color(0x99000000)).padding(horizontal = 8.dp, vertical = 2.dp))
        }
        if (!hasCaption) TimeAndStatus(m, Color.White, Modifier.align(Alignment.BottomEnd).padding(6.dp).clip(CircleShape).background(Color(0x99000000)).padding(horizontal = 8.dp, vertical = 2.dp))
    }
}

@Composable
private fun Bubble(
    session: Session, m: Message, first: Boolean, last: Boolean, group: Boolean, senderSeed: ByteArray,
    animate: Boolean, seen: MutableSet<String>, onMedia: (Media) -> Unit, onFailedClick: () -> Unit,
) {
    val out = m.outgoing
    val shape = bubbleShape(out, last)
    val ink = bubbleInk(out)
    val sub = bubbleSub(out)
    val showAvatar = group && !out
    Row(
        Modifier.fillMaxWidth().then(enterAnim(m, animate, seen)),
        horizontalArrangement = if (out) Arrangement.End else Arrangement.Start,
        verticalAlignment = Alignment.Bottom,
    ) {
        if (showAvatar) {
            if (last) AvatarView(senderSeed, 30) else Spacer(Modifier.size(30.dp))
            Spacer(Modifier.width(6.dp))
        }
        val media = m.media
        Column(
            Modifier.widthIn(max = 300.dp).clip(shape).background(bubbleFill(out)).bubbleEdge(out, shape)
                .clickable(enabled = m.status == Status.FAILED, onClick = onFailedClick),
        ) {
            if (group && !out && first) {
                Text(m.senderName.ifBlank { "@" + m.sender }, style = MaterialTheme.typography.labelMedium, color = Ui.muted, modifier = Modifier.padding(start = 12.dp, end = 12.dp, top = 7.dp), maxLines = 1)
            }
            if (media != null) {
                MediaBody(session, m, media, onMedia, m.body.isNotEmpty())
                if (m.body.isNotEmpty()) {
                    Text(m.body, style = MaterialTheme.typography.bodyLarge, color = ink, modifier = Modifier.padding(start = 12.dp, end = 12.dp, top = 6.dp))
                    TimeAndStatus(m, sub, Modifier.align(Alignment.End).padding(end = 10.dp, bottom = 5.dp))
                }
            } else {
                Column(Modifier.padding(start = 12.dp, end = 10.dp, top = 6.dp, bottom = 5.dp)) {
                    Text(m.body, style = MaterialTheme.typography.bodyLarge, color = ink)
                    TimeAndStatus(m, sub, Modifier.align(Alignment.End))
                }
            }
        }
    }
}

@Composable
private fun PostCard(session: Session, m: Message, animate: Boolean, seen: MutableSet<String>, onMedia: (Media) -> Unit) {
    val media = m.media
    Column(Modifier.fillMaxWidth().then(enterAnim(m, animate, seen)).clip(RoundedCornerShape(cardRadius())).background(InBubbleColor)) {
        if (media != null) MediaBody(session, m, media, onMedia, m.body.isNotEmpty())
        if (media == null || m.body.isNotEmpty()) {
            Column(Modifier.padding(start = 14.dp, end = 12.dp, top = 10.dp, bottom = 7.dp)) {
                if (m.body.isNotEmpty()) Text(m.body, style = MaterialTheme.typography.bodyLarge, color = Ui.text)
                TimeAndStatus(m, Ui.muted, Modifier.align(Alignment.End).padding(top = 4.dp))
            }
        }
    }
}
