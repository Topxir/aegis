package org.aegis.messenger.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.remember
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.data.Look

/**
 * Routes are strings: "list", "chat:<key>", "new", "newgroup", "contact:<u>", "ginfo:<id>",
 * "settings", "settings:<section>", "about".
 */
@Composable
fun Root(session: Session, onLanguage: () -> Unit) {
    val d = session.data
    // Only a saved change re-applies the look, so an unsaved preview in Appearance stays.
    remember(d?.look) { Ui.apply(d?.look ?: Look()) }
    Box(Modifier.fillMaxSize().background(Ui.bg)) {
        LookGround()
        if (session.keyChangedOrigin != null) KeyChangedStop(session)
        else if (d == null) StartScreen(session) else Navigator(session, onLanguage)
        session.notice?.let { n ->
            Box(Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(12.dp).clip(RoundedCornerShape(14.dp)).background(Ui.surface2).border(1.dp, Ui.border, RoundedCornerShape(14.dp)).fillMaxWidth()) {
                Text(stringResource(n), color = Ui.text, modifier = Modifier.padding(12.dp).align(Alignment.CenterStart))
                TextButton({ session.notice = null }, Modifier.align(Alignment.CenterEnd)) { Text(stringResource(R.string.ok), color = Ui.accent) }
            }
        }
    }
}

@Composable
private fun Navigator(session: Session, onLanguage: () -> Unit) {
    val anim = animationsOn()
    val full = fullMotion()
    val ctx = LocalContext.current
    var stack by rememberSaveable { mutableStateOf("list") }
    val routes = stack.split('|')
    val route = routes.last()
    fun push(r: String) { stack = "$stack|$r" }
    fun pop() { if (routes.size > 1) stack = routes.dropLast(1).joinToString("|") }
    fun reset(r: String) { stack = r }
    // Settings pages opened from the list keep the hub below them, so Back lands there.
    fun open(r: String) { if (r.startsWith("settings:")) push("settings"); push(r) }
    fun guide() { reset("list"); Guide.start() }

    BackHandler(routes.size > 1) { pop() }
    LaunchedEffect(session.linkIn) { if (session.linkIn != null && route != "new") push("new") }
    LaunchedEffect(Unit) { while (true) { delay(5_000); session.purgeNow() } }
    LaunchedEffect(Unit) { if (!Guide.done(ctx)) Guide.start() }

    val wide = LocalConfiguration.current.screenWidthDp >= 600
    val chatKey = if (route.startsWith("chat:")) route.substringAfter(':') else null
    val pane = Ui.look.placement(wide, chatKey != null)
    val openChat: (String) -> Unit = { k -> stack = "list|chat:$k" }

    @Composable
    fun ListPane(modifier: Modifier) {
        val d = session.data ?: return
        Box(modifier) { ChatListScreen(session, d, openChat) { r -> open(r) } }
    }

    @Composable
    fun Screens(modifier: Modifier) = AnimatedContent(
        targetState = route,
        modifier = modifier,
        transitionSpec = {
            val ms = if (anim) Ui.ANIM_MS else 0
            if (full) (slideInHorizontally(tween(Ui.ENTER_MS)) { it / 8 } + fadeIn(tween(ms))) togetherWith (slideOutHorizontally(tween(Ui.ENTER_MS)) { -it / 8 } + fadeOut(tween(ms)))
            else fadeIn(tween(ms)) togetherWith fadeOut(tween(ms))
        },
        label = "route",
    ) { r ->
        val d = session.data ?: return@AnimatedContent
        val arg = r.substringAfter(':', "")
        when (r.substringBefore(':')) {
            "chat" -> ChatScreen(session, d, arg, ::pop, strip = if (pane == "strip") ({ RecentStrip(d, arg, openChat) }) else null) {
                when {
                    arg.startsWith("g:") -> push("ginfo:" + arg.removePrefix("g:"))
                    arg.startsWith("c:") -> push("chinfo:" + arg.removePrefix("c:"))
                    else -> push("contact:" + arg.removePrefix("dm:"))
                }
            }
            "account" -> AccountScreen(session, d, ::pop)
            "contacts" -> ContactsScreen(d, ::pop) { k -> push("chat:$k") }
            "newchannel" -> NewChannelScreen(session, d, ::pop) { k -> stack = "list|chat:$k" }
            "chinfo" -> ChannelInfoScreen(session, d, arg, ::pop) { reset("list") }
            "new" -> NewChatScreen(session, ::pop, { k -> stack = "list|chat:$k" }) { push("newgroup") }
            "newgroup" -> NewGroupScreen(session, d, ::pop) { k -> stack = "list|chat:$k" }
            "contact" -> ContactScreen(session, d, arg, ::pop)
            "ginfo" -> GroupInfoScreen(session, d, arg, ::pop) { reset("list") }
            "settings" -> if (arg.isEmpty()) SettingsHub(d, ::pop) { id -> push(if (id == "profile") "account" else "settings:$id") }
                else SettingsPage(arg, SettingsHost(session, d, ::pop, onLanguage, ::guide))
            "about" -> AboutScreen(::pop, ::guide)
            "requests" -> RequestsScreen(session, ::pop)
            else -> ChatListScreen(session, d, { k -> push("chat:$k") }) { r -> open(r) }
        }
    }

    when (pane) {
        "left", "right" -> Row(Modifier.fillMaxSize()) {
            if (pane == "left") ListPane(Modifier.width(ListWidth).fillMaxHeight())
            if (pane == "left") Box(Modifier.width(1.dp).fillMaxHeight().background(Ui.border))
            Screens(Modifier.weight(1f).fillMaxHeight())
            if (pane == "right") Box(Modifier.width(1.dp).fillMaxHeight().background(Ui.border))
            if (pane == "right") ListPane(Modifier.width(ListWidth).fillMaxHeight())
        }
        else -> Screens(Modifier.fillMaxSize())
    }
    if (route == "list") GuideOverlay()
}

/** Hard stop when the pinned server key changed (spec section 23). */
@Composable
private fun KeyChangedStop(session: Session) {
    var confirm by rememberSaveable { mutableStateOf(false) }
    androidx.compose.foundation.layout.Column(
        Modifier.fillMaxSize().navigationBarsPadding().padding(24.dp),
        verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center,
    ) {
        Text(stringResource(R.string.key_changed_title), color = Ui.danger, style = androidx.compose.material3.MaterialTheme.typography.titleLarge)
        androidx.compose.foundation.layout.Spacer(Modifier.padding(8.dp))
        Text(stringResource(R.string.key_changed_body), color = Ui.text)
        androidx.compose.foundation.layout.Spacer(Modifier.padding(12.dp))
        Primary(stringResource(R.string.key_changed_lock)) { session.lock(); session.dismissKeyChanged() }
        androidx.compose.foundation.layout.Spacer(Modifier.padding(4.dp))
        if (!confirm) {
            Secondary(stringResource(R.string.key_changed_trust), danger = true) { confirm = true }
        } else {
            Text(stringResource(R.string.key_changed_warn), color = Ui.danger)
            androidx.compose.foundation.layout.Spacer(Modifier.padding(4.dp))
            Secondary(stringResource(R.string.key_changed_trust_yes), danger = true) { session.trustNewServerKey() }
            Secondary(stringResource(R.string.cancel)) { confirm = false }
        }
    }
}
