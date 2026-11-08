package org.aegis.messenger.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import org.aegis.messenger.R
import org.aegis.messenger.app.UpdateState
import org.aegis.messenger.app.Updater

@Composable
fun UpdateSettings() {
    val ctx = LocalContext.current
    var auto by remember { mutableStateOf(Updater.auto(ctx)) }
    var allow by remember { mutableStateOf(false) }
    Section(stringResource(R.string.updates)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Text(stringResource(R.string.update_auto), color = Ui.text, modifier = Modifier.weight(1f))
            Switch(
                auto, { auto = it; Updater.setAuto(ctx, it) },
                colors = SwitchDefaults.colors(checkedTrackColor = Ui.accent, checkedThumbColor = Ui.onAccent, uncheckedTrackColor = Ui.surface2, uncheckedThumbColor = Ui.muted, uncheckedBorderColor = Ui.border),
            )
        }
        when (Updater.state) {
            UpdateState.Checking -> Note(stringResource(R.string.update_checking))
            UpdateState.Current -> Note(stringResource(R.string.update_current), Ui.accent)
            UpdateState.Ready -> Note(stringResource(R.string.update_ready, Updater.version), Ui.accent)
            UpdateState.Failed -> Note(stringResource(R.string.update_failed), Ui.danger)
            UpdateState.Rejected -> Note(stringResource(R.string.update_bad), Ui.danger)
            UpdateState.Idle -> {}
        }
        if (Updater.state == UpdateState.Ready) {
            Primary(stringResource(R.string.update_install)) { allow = !Updater.install(ctx) }
            if (allow) Note(stringResource(R.string.update_allow))
        } else {
            Secondary(stringResource(R.string.update_check), enabled = Updater.state != UpdateState.Checking) { Updater.checkNow() }
        }
        Note(stringResource(R.string.update_note))
    }
}
