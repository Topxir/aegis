package org.aegis.messenger.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aegis.messenger.R
import org.aegis.messenger.app.Tor
import org.aegis.messenger.app.Transports
import org.aegis.messenger.net.Bridges
import org.aegis.messenger.net.Bridges.Mode

@Composable
private fun modeLabel(m: Mode): String = stringResource(
    when (m) {
        Mode.Off -> R.string.bridges_off
        Mode.Snowflake -> R.string.bridges_snowflake
        Mode.Obfs4 -> R.string.bridges_obfs4
        Mode.Custom -> R.string.bridges_custom
    },
)

/** Bridge choice under the Tor switch. A change restarts Tor with the new settings. */
@Composable
fun BridgeSettings() {
    val ctx = LocalContext.current
    var mode by remember { mutableStateOf(Transports.mode(ctx)) }
    var applied by remember { mutableStateOf(mode) }
    var lines by remember { mutableStateOf(Transports.custom(ctx)) }
    var error by remember { mutableStateOf<String?>(null) }
    val badLine = stringResource(R.string.err_bridge_line)
    val empty = stringResource(R.string.err_bridges_empty)
    val many = stringResource(R.string.err_bridges_many)

    fun apply(m: Mode, text: String) {
        val stored = try {
            Bridges.check(m, text)
        } catch (e: Bridges.Invalid) {
            error = when {
                e.empty -> empty
                e.tooMany -> many
                else -> "$badLine ${e.line}"
            }
            return
        }
        error = null
        Transports.save(ctx, m, if (m == Mode.Custom) stored else Transports.custom(ctx))
        if (m == Mode.Custom) lines = stored
        applied = m
        Tor.restart()
    }

    if (applied != Mode.Off) Note(stringResource(R.string.tor_bridge, modeLabel(applied)))
    Text(stringResource(R.string.bridges), color = Ui.text, modifier = Modifier.padding(top = 12.dp))
    Choices(Mode.entries.map { it to modeLabel(it) }, mode) { m ->
        mode = m
        error = null
        if (m != Mode.Custom && m != applied) apply(m, "")
    }
    if (mode == Mode.Custom) {
        Field(lines, { lines = it; error = null }, stringResource(R.string.bridge_lines), singleLine = false, mono = true)
        Secondary(stringResource(R.string.bridges_use)) { apply(Mode.Custom, lines) }
    }
    error?.let { Note(it, Ui.danger) }
    Note(stringResource(R.string.bridges_note))
}
