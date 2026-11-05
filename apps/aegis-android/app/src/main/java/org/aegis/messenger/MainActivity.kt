package org.aegis.messenger

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.aegis.messenger.app.AegisApp
import org.aegis.messenger.app.Boot
import org.aegis.messenger.app.Session
import org.aegis.messenger.ui.AegisTheme
import org.aegis.messenger.ui.Root

class MainActivity : ComponentActivity() {
    private val session: Session get() = (application as AegisApp).session

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(Boot.localized(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applySecure()
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        setContent {
            AegisTheme { Root(session) { recreate() } }
        }
    }

    /** FLAG_SECURE follows the setting, on by default. */
    fun applySecure() {
        if (Boot.secureScreen(this)) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    override fun onStart() {
        super.onStart()
        session.onForeground()
        session.pollSoon()
    }

    override fun onStop() {
        session.onBackground()
        super.onStop()
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        session.touch()
    }
}
