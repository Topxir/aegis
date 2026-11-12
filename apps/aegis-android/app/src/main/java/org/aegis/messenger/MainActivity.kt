package org.aegis.messenger

import android.Manifest
import android.content.Context
import android.content.Intent
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
        if (savedInstanceState == null) takeLink(intent)
        setContent {
            AegisTheme { Root(session) { recreate() } }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeLink(intent)
    }

    /** An opened `aegis://invite/` link waits in the session until the user acts on it. */
    private fun takeLink(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val link = intent.dataString ?: return
        if (link.startsWith("aegis://invite/", ignoreCase = true)) session.linkIn = link
        intent.data = null
    }

    /**
     * FLAG_SECURE follows the setting, on by default. With it off but the app lock on, the task
     * switcher still gets no thumbnail, so no chat stays visible there while the app is locked.
     */
    fun applySecure() {
        val secure = Boot.secureScreen(this)
        if (secure) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(!secure && !Boot.appLock(this))
    }

    override fun onResume() {
        super.onResume()
        applySecure()
    }

    override fun onPause() {
        // Before Android 13 the thumbnail can only be kept out with FLAG_SECURE, set as the app leaves.
        if (Build.VERSION.SDK_INT < 33 && Boot.appLock(this)) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onPause()
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
