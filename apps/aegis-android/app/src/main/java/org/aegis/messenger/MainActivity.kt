package org.aegis.messenger

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.aegis.messenger.core.AegisRustBridge
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

    override fun onPause() {
        super.onPause()
        rustBridge.onAppBackgrounded()
    }

    companion object {
        fun secureKeyboardImeOptions(): Int {
            return EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_ACTION_SEND
        }
    }
}
