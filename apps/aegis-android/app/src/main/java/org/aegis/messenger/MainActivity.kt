package org.aegis.messenger

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.aegis.messenger.core.AegisRustBridge
import org.aegis.messenger.notify.AegisNotifications
import org.aegis.messenger.service.AegisBackgroundService
import org.aegis.messenger.ui.AegisComposeApp

class MainActivity : ComponentActivity() {

    private lateinit var rustBridge: AegisRustBridge

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        rustBridge = AegisRustBridge(applicationContext)
        AegisNotifications.ensureChannels(this)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            runCatching {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
            }
        }

        runCatching {
            val serviceIntent = Intent(this, AegisBackgroundService::class.java).apply {
                action = AegisBackgroundService.ACTION_START_TRANSPORT
            }
            startForegroundService(serviceIntent)
        }

        setContent {
            AegisComposeApp(
                bridge = rustBridge,
                onPanicWipeTriggered = {
                    rustBridge.triggerEmergencyPanicWipe()
                    runCatching {
                        stopService(Intent(this, AegisBackgroundService::class.java))
                    }
                }
            )
        }
    }

    override fun onResume() {
        super.onResume()
        AegisNotifications.isAppForeground = true
    }

    override fun onPause() {
        super.onPause()
        AegisNotifications.isAppForeground = false
        rustBridge.onAppBackgrounded()
    }

    companion object {
        fun secureKeyboardImeOptions(): Int {
            return EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_ACTION_SEND
        }
    }
}
