package org.aegis.messenger.ui

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.app.Tor
import org.aegis.messenger.app.TorStatus
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.net.Route
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.sin

/** Avatar outline chosen in Appearance. */
fun avatarShape(): Shape = when (Ui.look.avatar) {
    "rounded" -> RoundedCornerShape(30)
    "square" -> RoundedCornerShape(12)
    else -> CircleShape
}

/** Corner shape of a message bubble; the last bubble of a run gets a small corner on its own side. */
fun bubbleShape(out: Boolean, last: Boolean): Shape {
    val l = Ui.look
    val big = (if (l.bubble == "sharp") l.radius / 3 else l.radius).dp
    val small = minOf(l.radius, 4).dp
    return RoundedCornerShape(big, big, if (out && last) small else big, if (!out && last) small else big)
}

/** Corner radius for cards that follow the bubble setting, such as channel posts. */
fun cardRadius(): Dp = (if (Ui.look.bubble == "sharp") Ui.look.radius / 3 else Ui.look.radius).dp

fun bubbleFill(out: Boolean): Brush = when {
    Ui.look.bubble == "minimal" -> SolidColor(if (out) Ui.surface2 else Color.Transparent)
    out -> Ui.outBubble
    else -> SolidColor(InBubbleColor)
}

fun bubbleInk(out: Boolean): Color = if (out && Ui.look.bubble != "minimal") Ui.onOutBubble else Ui.text

fun bubbleSub(out: Boolean): Color = if (out && Ui.look.bubble != "minimal") Ui.onOutBubble.copy(alpha = 0.66f) else Ui.muted

/** Hairline border for the minimal bubble style; other styles have none. */
fun Modifier.bubbleEdge(out: Boolean, shape: Shape): Modifier =
    if (Ui.look.bubble == "minimal") border(1.dp, if (out) Ui.accent.copy(alpha = 0.45f) else Ui.border, shape) else this

val InBubbleColor = Color(0xFF161619)

/** Chat background from the wallpaper setting. */
fun Modifier.wallpaper(): Modifier = drawBehind {
    when (Ui.look.wall) {
        "solid" -> drawRect(Ui.surface)
        "gradient" -> drawRect(Brush.linearGradient(Ui.accentStops.map { it.copy(alpha = 0.10f) }, Offset.Zero, Offset(size.width, size.height)))
    }
}

/** Thin accent line under a header. */
@Composable
fun HeadLine() {
    Box(Modifier.fillMaxWidth().height(1.dp).background(Brush.horizontalGradient(Ui.accentStops.map { it.copy(alpha = 0.55f) })))
}

/** Slowly moving accent gradient behind every screen; nothing when it is off or motion is off. */
@Composable
fun LookGround() {
    if (!Ui.look.animated || !animationsOn()) return
    val t by rememberInfiniteTransition(label = "ground").animateFloat(
        0f, 6.2832f, infiniteRepeatable(tween(48_000, easing = LinearEasing), RepeatMode.Restart), label = "angle",
    )
    val stops = Ui.accentStops.map { it.copy(alpha = 0.13f) } + Color.Transparent
    Canvas(Modifier.fillMaxSize()) {
        val r = maxOf(size.width, size.height)
        val c = Offset(size.width / 2f + cos(t) * size.width * 0.35f, size.height * 0.3f + sin(t) * size.height * 0.2f)
        drawRect(Brush.radialGradient(stops, c, r))
    }
}

/** Scroll depth: rows near the edges of the list tilt back and fade slightly. */
fun Modifier.depth(state: LazyListState, key: Any): Modifier = graphicsLayer {
    val info = state.layoutInfo
    val item = info.visibleItemsInfo.firstOrNull { it.key == key } ?: return@graphicsLayer
    val h = (info.viewportEndOffset - info.viewportStartOffset).toFloat()
    if (h <= 0f) return@graphicsLayer
    val d = (((item.offset + item.size / 2f - info.viewportStartOffset) / h - 0.5f) * 2f).coerceIn(-1f, 1f)
    val e = abs(d) * abs(d)
    rotationX = -d * 9f
    scaleX = 1f - 0.035f * e
    scaleY = 1f - 0.035f * e
    alpha = 1f - 0.25f * e
    cameraDistance = 14f * density
}

@Composable
fun depthOn(): Boolean = Ui.look.depth && animationsOn()

/** Calm status line: Tor and route, end-to-end encryption, app lock. */
@Composable
fun StatusStrip(session: Session, d: VaultData, tor: Boolean, onRoute: (String) -> Unit) {
    val onion = tor && runCatching { Route.plan(true, d.settings.endpoint, d.settings.proxy).endpoint.contains(".onion") }.getOrDefault(false)
    val (torText, torOn) = when {
        !tor -> stringResource(R.string.stat_tor_off) to false
        Tor.status == TorStatus.Connected -> stringResource(if (onion) R.string.stat_onion else R.string.stat_tor) to true
        Tor.status == TorStatus.Failed -> stringResource(R.string.stat_tor_failed) to false
        else -> stringResource(R.string.stat_tor_starting) to false
    }
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Pill(torText, torOn, Modifier.guideTarget("tor")) { onRoute("settings:network") }
        Pill(stringResource(R.string.stat_e2ee), true, Modifier) { onRoute("settings:privacy") }
        Pill(stringResource(if (session.pinSet) R.string.stat_pin else R.string.stat_nopin), session.pinSet, Modifier.guideTarget("lock")) {
            onRoute("settings:privacy")
        }
    }
}

@Composable
private fun Pill(text: String, ok: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Row(
        modifier.clip(RoundedCornerShape(50)).border(1.dp, Ui.border, RoundedCornerShape(50))
            .clickable(role = Role.Button, onClick = onClick).padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(Modifier.size(6.dp).clip(CircleShape).background(if (ok) Ui.accent else Ui.muted.copy(alpha = 0.5f)))
        Text(text, style = MaterialTheme.typography.labelMedium, color = if (ok) Ui.text else Ui.muted, maxLines = 1)
    }
}

/** Recent chats above an open chat when the list is placed on top on a phone. */
@Composable
fun RecentStrip(d: VaultData, current: String, onOpen: (String) -> Unit) {
    val rs = rows(d).take(24)
    if (rs.isEmpty()) return
    Column {
        LazyRow(Modifier.fillMaxWidth().height(84.dp), contentPadding = PaddingValues(horizontal = 8.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            items(rs, key = { it.key }) { r ->
                val on = r.key == current
                Column(
                    Modifier.width(64.dp).clip(RoundedCornerShape(10.dp)).background(if (on) Ui.surface2 else Color.Transparent)
                        .clickable(role = Role.Button) { if (!on) onOpen(r.key) }.padding(vertical = 6.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    AvatarView(r.seed, 40)
                    Text(
                        r.title, style = MaterialTheme.typography.labelMedium, color = if (on) Ui.text else Ui.muted,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.padding(top = 4.dp, start = 2.dp, end = 2.dp),
                    )
                }
            }
        }
        HeadLine()
    }
}

/** Width of the chat list beside an open chat on wide screens. */
val ListWidth: Dp = 340.dp
