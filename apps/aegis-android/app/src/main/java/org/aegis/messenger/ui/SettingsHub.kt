package org.aegis.messenger.ui

import androidx.compose.runtime.LaunchedEffect
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.aegis.messenger.BuildConfig
import org.aegis.messenger.R
import org.aegis.messenger.app.Boot
import org.aegis.messenger.app.Session
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.data.Look
import org.aegis.messenger.data.VaultData

/** What a settings page gets from the navigator. */
class SettingsHost(
    val session: Session,
    val d: VaultData,
    val onBack: () -> Unit,
    val onLanguage: () -> Unit,
    val onGuide: () -> Unit,
)

class SettingsEntry(val id: String, val title: Int, val hint: Int, val content: @Composable (SettingsHost) -> Unit)

/** Settings pages in display order. A new page is one more entry; a new toggle goes into its page. */
val SETTINGS_SECTIONS: List<SettingsEntry> = listOf(
    SettingsEntry("privacy", R.string.sec_privacy, R.string.sec_privacy_hint) {
        SettingsScreen(it.session, it.d, it.onBack, {}, it.onLanguage, part = "privacy")
    },
    SettingsEntry("network", R.string.sec_network, R.string.sec_network_hint) {
        SettingsScreen(it.session, it.d, it.onBack, {}, it.onLanguage, part = "network")
    },
    SettingsEntry("appearance", R.string.sec_appearance, R.string.sec_appearance_hint) { AppearanceScreen(it) },
    SettingsEntry("notifications", R.string.notifications, R.string.sec_notifications_hint) {
        SettingsScreen(it.session, it.d, it.onBack, {}, it.onLanguage, part = "notifications")
    },
    SettingsEntry("account", R.string.account, R.string.sec_account_hint) {
        SettingsScreen(it.session, it.d, it.onBack, {}, it.onLanguage, part = "account")
    },
    SettingsEntry("about", R.string.about, R.string.sec_about_hint) { AboutScreen(it.onBack, it.onGuide) },
)

@Composable
fun SettingsHub(d: VaultData, onBack: () -> Unit, onOpen: (String) -> Unit) {
    val ed = remember(d.edSk.toList()) { Crypto.ed25519Public(d.edSk) }
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.settings), onBack = onBack)
        HeadLine()
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Row(
                Modifier.fillMaxWidth().clickable { onOpen("profile") }.padding(horizontal = 16.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                AvatarView(ed, 56)
                Column(Modifier.weight(1f)) {
                    Text(d.profile.name.ifBlank { d.settings.displayName }.ifBlank { "@" + d.username }, style = MaterialTheme.typography.titleMedium, color = Ui.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("@" + d.username, style = MaterialTheme.typography.bodySmall.copy(fontFamily = GeistMono), color = Ui.muted)
                }
            }
            Divider()
            SETTINGS_SECTIONS.forEach { s ->
                Row(
                    Modifier.fillMaxWidth().clickable(role = Role.Button) { onOpen(s.id) }.padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(s.title), style = MaterialTheme.typography.bodyLarge, color = Ui.text)
                        Text(stringResource(s.hint), style = MaterialTheme.typography.bodySmall, color = Ui.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Text("›", style = MaterialTheme.typography.titleLarge, color = Ui.muted)
                }
            }
            Note(stringResource(R.string.version_line, BuildConfig.VERSION_NAME).let { "    $it" })
        }
    }
}

@Composable
fun SettingsPage(id: String, host: SettingsHost) {
    val entry = SETTINGS_SECTIONS.firstOrNull { it.id == id } ?: return host.onBack()
    entry.content(host)
}

// ---- appearance -----------------------------------------------------------

private val PRESET_NAMES = mapOf(
    "mono" to R.string.look_mono, "ocean" to R.string.look_ocean, "dusk" to R.string.look_dusk,
    "aurora" to R.string.look_aurora, "ember" to R.string.look_ember, "slate" to R.string.look_slate,
)

private fun hue(rgb: Int): Float {
    val hsv = FloatArray(3)
    android.graphics.Color.RGBToHSV(rgb shr 16 and 0xFF, rgb shr 8 and 0xFF, rgb and 0xFF, hsv)
    return hsv[0]
}

private fun fromHue(h: Float): Int = android.graphics.Color.HSVToColor(floatArrayOf(h, 0.62f, 0.9f)) and 0xFFFFFF

@Composable
fun AppearanceScreen(host: SettingsHost) {
    val ctx = LocalContext.current
    val saved = host.d.look
    var l by remember { mutableStateOf(saved) }
    // Leaving the page drops any unsaved slider position.
    DisposableEffect(Unit) { onDispose { Ui.apply(host.session.data?.look ?: Look()) } }
    fun preview(n: Look) { l = n.sanitize(); Ui.apply(l) }
    fun commit(n: Look) { preview(n); host.session.saveLook(l) }
    val wide = LocalConfiguration.current.screenWidthDp >= 600
    // A new photo arrives through the saved look after it is cleaned in the background.
    LaunchedEffect(saved.photo) { if (saved.photo != l.photo) l = l.copy(photo = saved.photo, wall = saved.wall) }
    val pickPhoto = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri -> uri?.let { host.session.setWallPhoto(it) } }
    val scopes = listOf("chat" to stringResource(R.string.look_scope_chat), "full" to stringResource(R.string.look_scope_full))

    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.sec_appearance), onBack = host.onBack)
        HeadLine()
        LookPreview(Modifier.padding(16.dp))
        Divider()
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Section(stringResource(R.string.look_theme)) {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Look.PRESETS.forEach { (id, stops) ->
                        Swatch(stops.map(Ui::rgb), stringResource(PRESET_NAMES.getValue(id)), l.theme == id) { commit(l.copy(theme = id)) }
                    }
                    Swatch(l.custom.ifEmpty { l.stops() }.map(Ui::rgb), stringResource(R.string.look_custom), l.theme == "custom") {
                        commit(l.copy(theme = "custom", custom = l.custom.ifEmpty { l.stops() }))
                    }
                }
                if (l.theme == "custom") {
                    l.custom.forEachIndexed { k, c ->
                        Text(stringResource(R.string.look_color_n, k + 1), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                        Slider(
                            hue(c), { h -> preview(l.copy(custom = l.custom.toMutableList().also { it[k] = fromHue(h) })) },
                            valueRange = 0f..359f, onValueChangeFinished = { commit(l) }, colors = sliderColors(Ui.rgb(c)),
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (l.custom.size < 3) Secondary(stringResource(R.string.look_add_color), modifier = Modifier.weight(1f)) {
                            commit(l.copy(custom = l.custom + fromHue((hue(l.custom.last()) + 60f) % 360f)))
                        }
                        if (l.custom.size > 2) Secondary(stringResource(R.string.look_remove_color), modifier = Modifier.weight(1f)) {
                            commit(l.copy(custom = l.custom.dropLast(1)))
                        }
                    }
                }
                Toggle(stringResource(R.string.look_animated), l.animated) { commit(l.copy(animated = it)) }
                Note(stringResource(R.string.look_animated_note))
            }
            Divider()
            Section(stringResource(R.string.look_motion)) {
                Choices(
                    listOf("off" to stringResource(R.string.look_motion_off), "subtle" to stringResource(R.string.look_motion_subtle), "full" to stringResource(R.string.look_motion_full)),
                    l.motion,
                ) { commit(l.copy(motion = it)) }
                if (!systemAnimations()) Note(stringResource(R.string.look_motion_system))
                Toggle(stringResource(R.string.look_depth), l.depth) { commit(l.copy(depth = it)) }
                Note(stringResource(R.string.look_depth_note))
            }
            Divider()
            Section(stringResource(R.string.look_layout)) {
                Text(stringResource(R.string.look_list), color = Ui.text)
                val lists = if (wide) listOf("left" to R.string.look_list_left, "right" to R.string.look_list_right, "top" to R.string.look_list_top)
                else listOf("left" to R.string.look_list_default, "top" to R.string.look_list_top)
                Choices(lists.map { it.first to stringResource(it.second) }, if (!wide && l.list == "right") "left" else l.list) { commit(l.copy(list = it)) }
                Note(stringResource(if (wide) R.string.look_list_note_wide else R.string.look_list_note))
                Text(stringResource(R.string.look_density), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                Choices(
                    listOf("comfortable" to stringResource(R.string.look_comfortable), "compact" to stringResource(R.string.look_compact)),
                    l.density,
                ) { commit(l.copy(density = it)) }
            }
            Divider()
            Section(stringResource(R.string.look_messages)) {
                Text(stringResource(R.string.look_bubble), color = Ui.text)
                Choices(
                    listOf("rounded" to stringResource(R.string.look_rounded), "sharp" to stringResource(R.string.look_sharp), "minimal" to stringResource(R.string.look_minimal)),
                    l.bubble,
                ) { commit(l.copy(bubble = it)) }
                Text(stringResource(R.string.look_radius, l.radius), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                Slider(
                    l.radius.toFloat(), { preview(l.copy(radius = it.toInt())) }, valueRange = 0f..Look.RADIUS_MAX.toFloat(),
                    steps = Look.RADIUS_MAX - 1, onValueChangeFinished = { commit(l) }, colors = sliderColors(Ui.accent),
                )
                Text(stringResource(R.string.look_font, l.font), color = Ui.text)
                Slider(
                    l.font.toFloat(), { preview(l.copy(font = it.toInt())) }, valueRange = Look.FONT_MIN.toFloat()..Look.FONT_MAX.toFloat(),
                    steps = Look.FONT_MAX - Look.FONT_MIN - 1, onValueChangeFinished = { commit(l) }, colors = sliderColors(Ui.accent),
                )
                Text(stringResource(R.string.look_avatar), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                Choices(
                    listOf("circle" to stringResource(R.string.look_circle), "rounded" to stringResource(R.string.look_rounded), "square" to stringResource(R.string.look_square)),
                    l.avatar,
                ) { commit(l.copy(avatar = it)) }
            }
            Divider()
            Section(stringResource(R.string.look_backdrop)) {
                Text(stringResource(R.string.look_wall), color = Ui.text)
                Choices(
                    listOfNotNull(
                        "none" to stringResource(R.string.look_wall_none), "solid" to stringResource(R.string.look_wall_solid),
                        "gradient" to stringResource(R.string.look_wall_gradient), if (l.photo.isNotEmpty()) "photo" to stringResource(R.string.look_wall_photo) else null,
                    ),
                    l.wall,
                ) { commit(l.copy(wall = it)) }
                Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Secondary(stringResource(R.string.look_photo_pick), modifier = Modifier.weight(1f)) { pickPhoto.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) }
                    if (l.photo.isNotEmpty()) Secondary(stringResource(R.string.look_photo_remove), modifier = Modifier.weight(1f)) { commit(l.copy(photo = "")) }
                }
                Text(stringResource(R.string.look_wall_scope), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                Choices(scopes, l.wallScope) { commit(l.copy(wallScope = it)) }
                if (l.wall == "photo") {
                    Text(stringResource(R.string.look_dim, l.dim), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                    Slider(
                        l.dim.toFloat(), { preview(l.copy(dim = it.toInt())) }, valueRange = 0f..Look.DIM_MAX.toFloat(),
                        onValueChangeFinished = { commit(l) }, colors = sliderColors(Ui.accent),
                    )
                }
                Note(stringResource(R.string.look_photo_note))
                Text(stringResource(R.string.look_effect), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                Look.EFFECTS.chunked(3).forEach { row ->
                    Box(Modifier.padding(bottom = 6.dp)) {
                        Choices(row.map { it to stringResource(fxLabel(it)) }, l.effect) { commit(l.copy(effect = it)) }
                    }
                }
                Text(stringResource(R.string.look_effect_scope), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
                Choices(scopes, l.effectScope) { commit(l.copy(effectScope = it)) }
            }
            Divider()
            Section(stringResource(R.string.language)) {
                Choices(
                    listOf("" to stringResource(R.string.lang_system), "en" to "English", "ru" to "Русский"),
                    Boot.language(ctx),
                ) { Boot.setLanguage(ctx, it); host.onLanguage() }
            }
            Divider()
            Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                Secondary(stringResource(R.string.look_reset), enabled = l != Look()) { commit(Look()) }
            }
        }
    }
}

@Composable
private fun sliderColors(c: Color) = SliderDefaults.colors(
    thumbColor = c, activeTrackColor = c, inactiveTrackColor = Ui.border,
    activeTickColor = Color.Transparent, inactiveTickColor = Color.Transparent,
)

@Composable
private fun Toggle(label: String, on: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Ui.text, modifier = Modifier.weight(1f))
        Switch(
            on, onChange,
            colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
        )
    }
}

@Composable
private fun Swatch(stops: List<Color>, label: String, on: Boolean, onClick: () -> Unit) {
    Column(
        Modifier.width(60.dp).clickable(role = Role.RadioButton, onClick = onClick),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            Modifier.size(44.dp).clip(CircleShape).border(2.dp, if (on) Ui.text else Color.Transparent, CircleShape)
                .padding(4.dp).clip(CircleShape).background(Brush.linearGradient(stops)),
        )
        Text(label, style = MaterialTheme.typography.labelMedium, color = if (on) Ui.text else Ui.muted, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.padding(top = 4.dp))
    }
}

/** A small chat drawn with the current look. */
@Composable
private fun LookPreview(modifier: Modifier) {
    val shape = RoundedCornerShape(16.dp)
    Box(modifier.fillMaxWidth().clip(shape).background(Ui.bg).border(1.dp, Ui.border, shape)) {
        LookGround()
        Column(Modifier.fillMaxWidth()) {
            Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(30.dp).clip(avatarShape()).background(Ui.avatarGradient))
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(stringResource(R.string.look_preview_name), style = MaterialTheme.typography.titleMedium, color = Ui.text)
                    Text(stringResource(R.string.look_preview_status), style = MaterialTheme.typography.bodySmall, color = Ui.muted)
                }
            }
            HeadLine()
            Column(Modifier.fillMaxWidth().wallPreview().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                PreviewBubble(stringResource(R.string.look_preview_in), false)
                PreviewBubble(stringResource(R.string.look_preview_out), true)
            }
        }
    }
}

@Composable
private fun PreviewBubble(text: String, out: Boolean) {
    val shape = bubbleShape(out, true)
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (out) Arrangement.End else Arrangement.Start) {
        Box(Modifier.widthIn(max = 240.dp).clip(shape).background(bubbleFill(out)).bubbleEdge(out, shape).padding(horizontal = 12.dp, vertical = 7.dp)) {
            Text(text, style = MaterialTheme.typography.bodyLarge, color = bubbleInk(out))
        }
    }
}

private fun fxLabel(id: String): Int = when (id) {
    "rain" -> R.string.look_fx_rain
    "snow" -> R.string.look_fx_snow
    "dust" -> R.string.look_fx_dust
    "embers" -> R.string.look_fx_embers
    "stars" -> R.string.look_fx_stars
    else -> R.string.look_fx_none
}
