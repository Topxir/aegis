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
import org.aegis.messenger.R
import org.aegis.messenger.app.Session
import org.aegis.messenger.net.Endpoint

/** Shown whenever no account is unlocked. Asks for username and password every time. */
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

    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()
            .verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 32.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            stringResource(R.string.app_name).uppercase(),
            style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 4.sp), color = Ui.muted,
        )
        Spacer(Modifier.height(24.dp))
        Text(stringResource(R.string.start_headline), style = MaterialTheme.typography.displaySmall, color = Ui.text)
        Spacer(Modifier.height(10.dp))
        Text(stringResource(R.string.start_subline), style = MaterialTheme.typography.bodyMedium, color = Ui.muted)
        Spacer(Modifier.height(12.dp))
        listOf(R.string.start_point_1, R.string.start_point_2, R.string.start_point_3).forEach {
            Text(stringResource(it), style = MaterialTheme.typography.bodyMedium, color = Ui.muted, modifier = Modifier.padding(vertical = 2.dp))
        }
        Spacer(Modifier.height(20.dp))
        UnderlineTabs(
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
        Spacer(Modifier.height(8.dp))
        Note(stringResource(R.string.start_password_note))
    }
}
