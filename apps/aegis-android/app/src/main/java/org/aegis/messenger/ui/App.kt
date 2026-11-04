package org.aegis.messenger.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.remember
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.Box
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.aegis.messenger.R
import org.aegis.messenger.app.Session

/** Routes are strings: "list", "chat:<key>", "new", "newgroup", "contact:<u>", "ginfo:<id>", "settings", "about". */
@Composable
fun Root(session: Session, onLanguage: () -> Unit) {
    val d = session.data
    val anim = animationsOn()
    val shift by if (anim) rememberInfiniteTransition(label = "drift").animateFloat(
        0f, 1f, infiniteRepeatable(tween(20_000, easing = LinearEasing), RepeatMode.Reverse), label = "shift",
    ) else remember { mutableStateOf(0f) }
    Box(Modifier.fillMaxSize().background(Ui.bg).background(Ui.ground(if (d == null) shift else 0f))) {
        if (d == null) StartScreen(session) else Navigator(session, onLanguage)
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
    var stack by rememberSaveable { mutableStateOf("list") }
    val routes = stack.split('|')
    val route = routes.last()
    fun push(r: String) { stack = "$stack|$r" }
    fun pop() { if (routes.size > 1) stack = routes.dropLast(1).joinToString("|") }
    fun reset(r: String) { stack = r }

    BackHandler(routes.size > 1) { pop() }
    LaunchedEffect(Unit) { while (true) { delay(30_000); session.purgeNow() } }

    AnimatedContent(
        targetState = route,
        transitionSpec = { val ms = if (anim) Ui.ANIM_MS else 0; fadeIn(tween(ms)) togetherWith fadeOut(tween(ms)) },
        label = "route",
    ) { r ->
        val d = session.data ?: return@AnimatedContent
        val arg = r.substringAfter(':', "")
        when (r.substringBefore(':')) {
            "chat" -> ChatScreen(session, d, arg, ::pop) {
                if (arg.startsWith("g:")) push("ginfo:" + arg.removePrefix("g:")) else push("contact:" + arg.removePrefix("dm:"))
            }
            "new" -> NewChatScreen(session, ::pop, { k -> stack = "list|chat:$k" }) { push("newgroup") }
            "newgroup" -> NewGroupScreen(session, d, ::pop) { k -> stack = "list|chat:$k" }
            "contact" -> ContactScreen(session, d, arg, ::pop)
            "ginfo" -> GroupInfoScreen(session, d, arg, ::pop) { reset("list") }
            "settings" -> SettingsScreen(session, d, ::pop, { push("about") }, onLanguage)
            "about" -> AboutScreen(::pop)
            else -> ChatListScreen(session, d, { k -> push("chat:$k") }, { push("new") }, { push("settings") })
        }
    }
}
