package org.aegis.messenger.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aegis.messenger.R
import org.aegis.messenger.app.Session

private enum class PinStage { Idle, Set1, Set2, Remove, DuressReal, Duress1, Duress2 }

/** PIN and duress PIN setup inside the account cabinet. */
@Composable
fun PinSection(session: Session) {
    var stage by remember { mutableStateOf(PinStage.Idle) }
    var digits by remember { mutableStateOf(4) }
    var first by remember { mutableStateOf("") }
    var real by remember { mutableStateOf("") }
    var value by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<Int?>(null) }

    fun reset() { stage = PinStage.Idle; first = ""; real = ""; value = ""; error = null }
    fun finish(e: Int?) { if (e == null) reset() else { error = e; value = ""; if (stage == PinStage.Set2 || stage == PinStage.Duress2) { stage = PinStage.Idle; first = "" } } }

    fun submit() {
        if (session.busy) return
        val len = if (stage == PinStage.Remove || stage == PinStage.DuressReal) session.pinDigits else digits
        if (value.length != len) return
        val v = value
        when (stage) {
            PinStage.Set1 -> { first = v; value = ""; stage = PinStage.Set2 }
            PinStage.Set2 -> {
                if (v != first) { error = R.string.pin_mismatch; value = ""; first = ""; stage = PinStage.Set1 }
                else session.pinSetup(v) { finish(it) }
            }
            PinStage.Remove -> session.pinRemove(v) { finish(it) }
            PinStage.DuressReal -> { real = v; value = ""; stage = PinStage.Duress1 }
            PinStage.Duress1 -> {
                if (v == real) { error = R.string.duress_same; value = "" } else { first = v; value = ""; stage = PinStage.Duress2 }
            }
            PinStage.Duress2 -> {
                if (v != first) { error = R.string.pin_mismatch; value = ""; first = ""; stage = PinStage.Duress1 }
                else session.duressSetup(real, v) { finish(it) }
            }
            PinStage.Idle -> {}
        }
    }

    Text(stringResource(R.string.pin_title), color = Ui.text, modifier = Modifier.padding(top = 14.dp))
    Note(stringResource(R.string.pin_note))
    error?.let { Note(stringResource(it), Ui.danger) }

    if (stage == PinStage.Idle) {
        if (!session.pinSet) {
            Choices(listOf(4 to stringResource(R.string.pin_digits_4), 6 to stringResource(R.string.pin_digits_6)), digits) { digits = it }
            Spacer(Modifier.height(8.dp))
            Primary(stringResource(R.string.pin_set)) { error = null; stage = PinStage.Set1 }
        } else {
            Secondary(stringResource(R.string.pin_remove), danger = true) { error = null; stage = PinStage.Remove }
            Text(stringResource(R.string.duress_title), color = Ui.text, modifier = Modifier.padding(top = 10.dp))
            Note(stringResource(R.string.duress_note))
            if (session.duressSet) {
                Secondary(stringResource(R.string.duress_remove)) { session.duressRemove() }
            } else {
                Secondary(stringResource(R.string.duress_set)) { error = null; digits = session.pinDigits; stage = PinStage.DuressReal }
            }
        }
    } else {
        val prompt = when (stage) {
            PinStage.DuressReal -> R.string.duress_real
            PinStage.Set1, PinStage.Duress1 -> R.string.pin_enter
            PinStage.Set2, PinStage.Duress2 -> R.string.pin_confirm
            else -> R.string.pin_remove_prompt
        }
        val len = if (stage == PinStage.Remove || stage == PinStage.DuressReal) session.pinDigits else digits
        Text(stringResource(if (stage == PinStage.Duress1) R.string.duress_enter else prompt), color = Ui.text, modifier = Modifier.padding(vertical = 10.dp))
        if (session.busy) {
            Row(Modifier.fillMaxWidth().padding(8.dp), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = Ui.accent, strokeWidth = 2.dp)
            }
        } else {
            PinPad(value, len, { value = it }, { submit() })
        }
        Secondary(stringResource(R.string.pin_cancel)) { reset() }
    }
}

/** Replaces the password form on the start screen while a PIN is set. */
@Composable
fun PinUnlockCard(session: Session, onError: (Int?) -> Unit, onPassword: () -> Unit) {
    val len = session.pinDigits
    var pin by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf<Int?>(null) }
    var left by remember { mutableStateOf<Int?>(null) }

    fun submit() {
        if (pin.length != len || session.busy) return
        val p = pin
        session.pinUnlock(p) { o ->
            pin = ""
            msg = o.msg
            left = o.left
            if (!session.pinSet && !session.pinGhost) onError(o.msg)
        }
    }

    Column(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(22.dp))
            .background(Brush.verticalGradient(listOf(Color(0xFF1A1A1E).copy(alpha = 0.78f), Color(0xFF0E0E10).copy(alpha = 0.86f))))
            .border(1.dp, Color(0xFF25262B), RoundedCornerShape(22.dp))
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.pin_unlock_title), style = MaterialTheme.typography.titleMedium, color = Ui.text)
        Spacer(Modifier.height(12.dp))
        left?.let { Note(stringResource(R.string.pin_left, it), Ui.danger) } ?: msg?.let { Note(stringResource(it), Ui.danger) }
        if (session.busy) {
            Row(Modifier.fillMaxWidth().padding(8.dp), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator(color = Ui.accent, strokeWidth = 2.dp)
            }
        } else {
            PinPad(pin, len, { pin = it; if (it.length == len) { msg = null; left = null } }, { submit() })
        }
        Spacer(Modifier.height(8.dp))
        Secondary(stringResource(R.string.pin_use_password)) { onPassword() }
    }
}
