package org.aegis.messenger.ui

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.BlendMode
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.CompositingStrategy
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aegis.messenger.R

/** One step of the first-run guide; [target] names an element tagged with [guideTarget]. */
class GuideStep(val title: Int, val body: Int, val target: String?)

val GUIDE_STEPS = listOf(
    GuideStep(R.string.guide_welcome, R.string.guide_welcome_text, null),
    GuideStep(R.string.guide_settings, R.string.guide_settings_text, "menu"),
    GuideStep(R.string.guide_security, R.string.guide_security_text, "lock"),
    GuideStep(R.string.guide_tor, R.string.guide_tor_text, "tor"),
    GuideStep(R.string.guide_contacts, R.string.guide_contacts_text, "search"),
    GuideStep(R.string.guide_appearance, R.string.guide_appearance_text, "menu"),
)

/** Guide state. The "seen" flag is per device, kept outside the vault. */
object Guide {
    private const val PREFS = "aegis_ui"
    private const val DONE = "guide_done"

    var step by mutableStateOf<Int?>(null)
        private set
    val targets = mutableStateMapOf<String, Rect>()

    fun done(ctx: Context): Boolean = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(DONE, false)

    fun start() { step = 0 }

    fun next(ctx: Context) {
        val s = step ?: return
        val n = after(s, GUIDE_STEPS.size)
        if (n == null) finish(ctx) else step = n
    }

    fun back() { step = step?.let(::before) }

    /** The step after [s] out of [count], or null when the guide is over. */
    fun after(s: Int, count: Int): Int? = if (s + 1 >= count) null else s + 1

    fun before(s: Int): Int = maxOf(0, s - 1)

    fun finish(ctx: Context) {
        step = null
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(DONE, true).apply()
    }
}

/** Marks an element the guide can point at. */
fun Modifier.guideTarget(id: String): Modifier = onGloballyPositioned { Guide.targets[id] = it.boundsInRoot() }

/** Dims the screen, rings the current target and shows the step card. Drawn above the chat list only. */
@Composable
fun GuideOverlay() {
    val i = Guide.step ?: return
    val ctx = LocalContext.current
    val step = GUIDE_STEPS[i]
    val target = step.target?.let { Guide.targets[it] }
    val pad = with(LocalDensity.current) { 6.dp.toPx() }
    val ring = Ui.accent
    BackHandler { Guide.finish(ctx) }
    BoxWithConstraints(Modifier.fillMaxSize().pointerInput(Unit) { detectTapGestures { } }) {
        Canvas(Modifier.fillMaxSize().graphicsLayer { compositingStrategy = CompositingStrategy.Offscreen }) {
            drawRect(Color.Black.copy(alpha = 0.72f))
            if (target != null) {
                val tl = Offset(target.left - pad, target.top - pad)
                val sz = Size(target.width + 2 * pad, target.height + 2 * pad)
                val cr = CornerRadius(minOf(sz.height / 2f, 18.dp.toPx()))
                drawRoundRect(Color.Transparent, tl, sz, cr, blendMode = BlendMode.Clear)
                drawRoundRect(ring, tl, sz, cr, style = Stroke(1.5.dp.toPx()))
            }
        }
        val below = target == null || target.center.y < constraints.maxHeight / 2f
        Column(
            Modifier.align(if (below) Alignment.BottomCenter else Alignment.TopCenter)
                .then(if (below) Modifier.navigationBarsPadding() else Modifier.statusBarsPadding())
                .padding(16.dp).widthIn(max = 480.dp).fillMaxWidth()
                .clip(RoundedCornerShape(16.dp)).background(Ui.surface).border(1.dp, Ui.border, RoundedCornerShape(16.dp))
                .padding(start = 18.dp, end = 10.dp, top = 16.dp, bottom = 8.dp),
        ) {
            Text(stringResource(step.title), style = MaterialTheme.typography.titleMedium, color = Ui.text)
            Spacer(Modifier.size(6.dp))
            Text(stringResource(step.body), style = MaterialTheme.typography.bodyMedium, color = Ui.muted, modifier = Modifier.padding(end = 8.dp))
            Spacer(Modifier.size(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Row(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                    GUIDE_STEPS.indices.forEach { k ->
                        Box(Modifier.size(if (k == i) 7.dp else 5.dp).clip(CircleShape).background(if (k == i) Ui.accent else Ui.border))
                    }
                }
                TextButton({ Guide.finish(ctx) }) { Text(stringResource(R.string.guide_skip), color = Ui.muted) }
                if (i > 0) TextButton({ Guide.back() }) { Text(stringResource(R.string.guide_back), color = Ui.text) }
                TextButton({ Guide.next(ctx) }) {
                    Text(stringResource(if (i + 1 == GUIDE_STEPS.size) R.string.guide_done else R.string.guide_next), color = Ui.accent)
                }
            }
        }
    }
}
