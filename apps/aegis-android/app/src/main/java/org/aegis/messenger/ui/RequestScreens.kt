package org.aegis.messenger.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.core.Hex

/** Messages from a key that is not a contact and shares no group or channel with us. */
@Composable
fun RequestsScreen(session: Session, onBack: () -> Unit) {
    val tick = session.requestTick
    val list = remember(tick) { session.requests() }
    Column(Modifier.fillMaxSize().navigationBarsPadding()) {
        TopBar(stringResource(R.string.requests_title), onBack = onBack)
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
            Note(stringResource(R.string.requests_note))
            if (list.isEmpty()) Note(stringResource(R.string.requests_empty))
            for ((xHex, frames) in list) RequestCard(session, xHex, frames)
        }
    }
}

@Composable
private fun RequestCard(session: Session, xHex: String, frames: Int) {
    var name by remember(xHex) { mutableStateOf("") }
    var error by remember(xHex) { mutableStateOf<Int?>(null) }
    val fp = session.keyFingerprint(Hex.decode(xHex))
    Divider()
    Text(stringResource(R.string.request_key), color = Ui.muted, modifier = Modifier.padding(top = 10.dp))
    Text(fp, color = Ui.text, fontFamily = GeistMono)
    Note(stringResource(R.string.request_frames, frames))
    Field(name, { name = it }, stringResource(R.string.request_username), mono = true)
    error?.let { Note(stringResource(it), Ui.danger) }
    Primary(stringResource(R.string.request_accept), enabled = name.isNotBlank() && !session.busy) {
        error = null
        session.acceptRequest(xHex, name) { error = it }
    }
    Secondary(stringResource(R.string.request_block), danger = true) { session.blockRequest(xHex) }
}
