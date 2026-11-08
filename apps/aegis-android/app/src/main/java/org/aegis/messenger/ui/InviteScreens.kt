package org.aegis.messenger.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.core.Qr
import org.aegis.messenger.core.Text as CoreText
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.data.dmKey

/** Dark modules on white with the four-module quiet zone, as scanners expect. */
@Composable
fun QrImage(code: Qr.Code, desc: String) {
    Box(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(220.dp).clip(RoundedCornerShape(12.dp)).background(Color.White).semantics { contentDescription = desc }) {
            val cell = size.width / (code.size + 8)
            for (y in 0 until code.size) for (x in 0 until code.size) {
                if (code[x, y]) drawRect(Color.Black, Offset((x + 4) * cell, (y + 4) * cell), Size(cell + 0.5f, cell + 0.5f))
            }
        }
    }
}

/** The link holds a secret, so the clip is marked sensitive and kept out of clipboard previews. */
private fun copySecret(ctx: Context, text: String) {
    val cm = ctx.getSystemService(ClipboardManager::class.java) ?: return
    val clip = ClipData.newPlainText("aegis", text)
    clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
    cm.setPrimaryClip(clip)
}

private fun pasteText(ctx: Context): String? {
    val cm = ctx.getSystemService(ClipboardManager::class.java) ?: return null
    return cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
}

/** Making an invite link and opening one (spec section 29). */
@Composable
fun InviteSections(session: Session, onOpen: (String) -> Unit) {
    val ctx = LocalContext.current
    var makeError by remember { mutableStateOf<Int?>(null) }
    var openError by remember { mutableStateOf<Int?>(null) }
    var copied by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf(session.linkIn ?: "") }
    LaunchedEffect(session.linkIn) { session.linkIn?.let { link = it; openError = null } }

    Section(stringResource(R.string.invite_title)) {
        val made = session.inviteLink
        if (made != null) {
            val code = remember(made) { Qr.encode(CoreText.utf8(made)) }
            QrImage(code, stringResource(R.string.invite_qr))
            Text(made, color = Ui.text, fontFamily = FontFamily.Monospace, fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp))
            Secondary(stringResource(R.string.invite_copy)) { copySecret(ctx, made); copied = true }
            if (copied) Note(stringResource(R.string.invite_copied), Ui.accent)
        }
        Note(stringResource(R.string.invite_note))
        makeError?.let { Note(stringResource(it), Ui.danger) }
        Primary(stringResource(if (made == null) R.string.invite_create else R.string.invite_another), enabled = !session.busy) {
            makeError = null
            copied = false
            session.createInvite { e -> makeError = e }
        }
    }
    Divider()
    Section(stringResource(R.string.invite_open_title)) {
        Field(link, { link = it; openError = null }, stringResource(R.string.field_invite_link), keyboard = KeyboardType.Uri, mono = true)
        Note(stringResource(R.string.invite_open_note))
        openError?.let { Note(stringResource(it), Ui.danger) }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Secondary(stringResource(R.string.invite_paste), modifier = Modifier.weight(1f)) {
                pasteText(ctx)?.let { link = it.trim(); openError = null }
            }
            Secondary(stringResource(R.string.invite_open), enabled = link.isNotBlank() && !session.busy, modifier = Modifier.weight(1f)) {
                session.redeemInvite(link) { u, e ->
                    openError = e
                    if (u != null) { link = ""; onOpen(dmKey(u)) }
                }
            }
        }
    }
}

/** The directory switch of settings (spec section 29.4). */
@Composable
fun HiddenProfileSection(session: Session, d: VaultData) {
    var error by remember { mutableStateOf<Int?>(null) }
    Section(stringResource(R.string.profile_lookup)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Text(stringResource(R.string.hide_profile), color = Ui.text, modifier = Modifier.weight(1f))
            Switch(
                d.settings.hidden, { on -> error = null; session.setHidden(on) { e -> error = e } },
                enabled = !session.busy,
                colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
            )
        }
        Note(stringResource(R.string.hide_profile_note))
        error?.let { Note(stringResource(it), Ui.danger) }
    }
}
