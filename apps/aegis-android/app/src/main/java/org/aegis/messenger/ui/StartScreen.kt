package org.aegis.messenger.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.net.Endpoint

/** Shown whenever no account is unlocked. Asks for username and password every time. */
@OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)
@Composable
fun StartScreen(session: Session) {
    var tab by rememberSaveable { mutableStateOf(0) } // 0 unlock, 1 create, 2 import
    val create = tab == 1
    var user by rememberSaveable { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var server by rememberSaveable { mutableStateOf(Endpoint.DEFAULT) }
    var error by remember { mutableStateOf<Int?>(null) }
    var info by remember { mutableStateOf<Int?>(null) }

    val importer = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) session.importVault(user, pass, uri) { e -> error = e; info = if (e == null) R.string.info_imported else null }
    }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) session.exportVault(user, uri) { e -> error = e; info = if (e == null) R.string.info_exported else null }
    }

    fun submit() {
        error = null
        info = null
        if (create) {
            if (pass != pass2) { error = R.string.err_password_mismatch; return }
            session.create(user, pass, name, server) { e ->
                error = e
                if (e == null) { pass = ""; pass2 = "" }
            }
        } else {
            session.unlock(user, pass) { e ->
                error = e
                if (e == null) pass = ""
            }
        }
    }

    val anim = animationsOn()
    val drift: State<Float> = if (anim) {
        rememberInfiniteTransition(label = "drift").animateFloat(
            0f, 1f, infiniteRepeatable(tween(26000, easing = LinearEasing), RepeatMode.Reverse), label = "drift",
        )
    } else remember { mutableFloatStateOf(0f) }
    val sheen: State<Float> = if (anim) {
        rememberInfiniteTransition(label = "sheen").animateFloat(
            0f, 1f, infiniteRepeatable(tween(9000, easing = LinearEasing), RepeatMode.Reverse), label = "sheen",
        )
    } else remember { mutableFloatStateOf(0.5f) }

    Box(
        Modifier.fillMaxSize().background(StartBg).drawBehind {
            val t = drift.value
            drawRect(
                Brush.radialGradient(
                    listOf(Color(0xFF26272C), Color.Transparent),
                    center = Offset(size.width * (0.05f + 0.22f * t), size.height * (0.02f + 0.12f * t)),
                    radius = size.width * 1.1f,
                ),
            )
        },
    ) {
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()
                .verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 32.dp),
        ) {
            Reveal(0, anim) {
                Column {
                    Text(
                        stringResource(R.string.start_eyebrow),
                        style = MaterialTheme.typography.labelMedium.copy(fontFamily = GeistMono, letterSpacing = 2.sp), color = Ui.muted,
                    )
                    Spacer(Modifier.height(16.dp))
                    val x = -400f + 800f * sheen.value
                    val silver = Brush.linearGradient(
                        listOf(Color.White, Color(0xFFD4D5DA), Color(0xFF8E9097), Color(0xFFD4D5DA), Color.White),
                        start = Offset(x, 0f), end = Offset(x + 1100f, 350f),
                    )
                    Text(
                        stringResource(R.string.start_headline),
                        style = TextStyle(
                            fontFamily = Geist, fontWeight = FontWeight.Light, fontSize = 40.sp, lineHeight = 44.sp,
                            letterSpacing = (-1.2).sp, brush = silver,
                        ),
                    )
                    Spacer(Modifier.height(14.dp))
                    Text(stringResource(R.string.start_subline), style = MaterialTheme.typography.bodyLarge, color = Ui.muted)
                    Spacer(Modifier.height(16.dp))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf(R.string.start_chip_1, R.string.start_chip_2, R.string.start_chip_3).forEach { Chip(stringResource(it)) }
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
            Reveal(1, anim) {
                Column(
                    Modifier.fillMaxWidth()
                        .clip(RoundedCornerShape(22.dp))
                        .background(Brush.verticalGradient(listOf(Color(0xFF1A1A1E).copy(alpha = 0.78f), Color(0xFF0E0E10).copy(alpha = 0.86f))))
                        .border(1.dp, Color(0xFF25262B), RoundedCornerShape(22.dp))
                        .padding(16.dp),
                ) {
                    SegmentedTabs(
                        listOf(0 to stringResource(R.string.start_unlock), 1 to stringResource(R.string.start_create), 2 to stringResource(R.string.start_import_tab)),
                        tab,
                    ) { tab = it; error = null; info = null }
                    Spacer(Modifier.height(8.dp))
                    Field(user, { user = it }, stringResource(R.string.field_username), keyboard = androidx.compose.ui.text.input.KeyboardType.Ascii, mono = true)
                    Field(pass, { pass = it }, stringResource(R.string.field_password), password = true)
                    if (create) {
                        Field(pass2, { pass2 = it }, stringResource(R.string.field_password_repeat), password = true)
                        Field(name, { name = it }, stringResource(R.string.field_display_name))
                        Field(server, { server = it }, stringResource(R.string.field_server), keyboard = androidx.compose.ui.text.input.KeyboardType.Uri)
                        Note(stringResource(R.string.start_create_note))
                    }
                    if (tab == 2) Note(stringResource(R.string.start_import_note))
                    error?.let { Note(stringResource(it), Ui.danger) }
                    info?.let { Note(stringResource(it), Ui.accent) }
                    Spacer(Modifier.height(8.dp))
                    if (session.busy) {
                        Row(Modifier.fillMaxWidth().padding(8.dp), horizontalArrangement = Arrangement.Center) {
                            CircularProgressIndicator(color = Ui.accent, strokeWidth = 2.dp)
                        }
                    } else if (tab == 2) {
                        Primary(stringResource(R.string.start_import), enabled = user.isNotBlank() && pass.isNotEmpty()) { importer.launch(arrayOf("*/*")) }
                        Secondary(stringResource(R.string.start_export), enabled = user.isNotBlank()) { exporter.launch("aegis-account.vault") }
                    } else {
                        Primary(stringResource(if (create) R.string.start_create_btn else R.string.start_unlock_btn), enabled = user.isNotBlank() && pass.isNotEmpty()) { submit() }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            Reveal(2, anim) { Note(stringResource(R.string.start_password_note)) }
            Spacer(Modifier.height(12.dp))
            Reveal(3, anim) {
                Text(
                    stringResource(R.string.start_footer),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono), color = Ui.muted,
                )
            }
        }
    }
}

private val StartBg = Color(0xFF08080A)
private val RevealEase = CubicBezierEasing(0.16f, 0.8f, 0.24f, 1f)

/** Fade and rise-in; steps are 0/150/300/450 ms. No animation when [anim] is false. */
@Composable
private fun Reveal(step: Int, anim: Boolean, content: @Composable () -> Unit) {
    val p = remember { Animatable(if (anim) 0f else 1f) }
    LaunchedEffect(anim) {
        if (anim) p.animateTo(1f, tween(700, delayMillis = step * 150, easing = RevealEase)) else p.snapTo(1f)
    }
    Box(Modifier.graphicsLayer { alpha = p.value; translationY = (1f - p.value) * 14.dp.toPx() }) { content() }
}

@Composable
private fun Chip(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono),
        color = Ui.muted,
        modifier = Modifier.clip(RoundedCornerShape(50)).border(1.dp, Ui.border, RoundedCornerShape(50))
            .background(Color(0x0DFFFFFF)).padding(horizontal = 10.dp, vertical = 5.dp),
    )
}

@Composable
private fun <T> SegmentedTabs(options: List<Pair<T, String>>, selected: T, onSelect: (T) -> Unit) {
    val shape = RoundedCornerShape(12.dp)
    Row(
        Modifier.fillMaxWidth().clip(shape).background(Color(0x66000000)).border(1.dp, Ui.border, shape).padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        options.forEach { (value, label) ->
            val on = value == selected
            Box(
                Modifier.weight(1f).height(40.dp).clip(RoundedCornerShape(9.dp))
                    .background(if (on) Ui.surface2 else Color.Transparent)
                    .clickable(role = Role.Tab) { onSelect(value) },
                contentAlignment = Alignment.Center,
            ) {
                Text(label, style = MaterialTheme.typography.labelLarge, color = if (on) Ui.text else Ui.muted, maxLines = 1)
            }
        }
    }
}
