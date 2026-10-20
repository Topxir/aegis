package org.aegis.messenger

import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import org.aegis.messenger.core.AegisRustBridge
import org.aegis.messenger.service.AegisBackgroundService
import org.aegis.messenger.ui.AegisComposeApp

/**
 * Primary Android Activity for Aegis (`aegis-ui-android`).
 *
 * Security invariants enforced at the OS window boundary (`AGENTS.md §2.4`, `PLAN.md §9.2, §14`):
 * 1. `WindowManager.LayoutParams.FLAG_SECURE` is enabled by default to block screenshots,
 *    screen recording, and Android Recent Apps task switcher previews.
 * 2. Incognito keyboard flag (`EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`) prevents Gboard/OEM
 *    keyboards from caching typed messages or nicknames.
 * 3. Supports switching the launcher icon to `org.aegis.messenger.CalculatorDisguiseAlias`.
 */
class MainActivity : ComponentActivity() {

    private lateinit var rustBridge: AegisRustBridge

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1. Block screenshots, screen recordings, and task-switcher thumbnails (AGENTS.md §2.4)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        // 2. Initialize the unified FFI bridge to `aegis-ffi` + Android StrongBox Keystore
        rustBridge = AegisRustBridge(applicationContext)

        // 3. Start persistent zero-GMS background QUIC/WebSocket + Cover Traffic service
        val serviceIntent = Intent(this, AegisBackgroundService::class.java).apply {
            action = AegisBackgroundService.ACTION_START_TRANSPORT
        }
        startForegroundService(serviceIntent)

        // 4. Mount Jetpack Compose UI (Russian & English localized)
        setContent {
            AegisComposeApp(
                bridge = rustBridge,
                onToggleCalculatorLauncherIcon = { enableDisguise ->
                    setCalculatorLauncherAlias(enableDisguise)
                },
                onPanicWipeTriggered = {
                    rustBridge.triggerEmergencyPanicWipe()
                }
            )
        }
    }

    override fun onPause() {
        super.onPause()
        // Zeroize decrypted screen state if instant lock-on-background is configured
        rustBridge.onAppBackgrounded()
    }

    /**
     * Switches the Android launcher icon between "Aegis" and "Калькулятор" (`CalculatorDisguiseAlias`).
     */
    private fun setCalculatorLauncherAlias(enableCalculatorDisguise: Boolean) {
        val pm = packageManager
        val mainComp = ComponentName(this, MainActivity::class.java)
        val calcComp = ComponentName(this, "org.aegis.messenger.CalculatorDisguiseAlias")

        if (enableCalculatorDisguise) {
            pm.setComponentEnabledSetting(
                calcComp,
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                PackageManager.DONT_KILL_APP
            )
            pm.setComponentEnabledSetting(
                mainComp,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP
            )
        } else {
            pm.setComponentEnabledSetting(
                mainComp,
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                PackageManager.DONT_KILL_APP
            )
            pm.setComponentEnabledSetting(
                calcComp,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP
            )
        }
    }

    companion object {
        /**
         * Returns EditorInfo flags enforcing Incognito Keyboard mode (`IME_FLAG_NO_PERSONALIZED_LEARNING`).
         */
        fun secureKeyboardImeOptions(): Int {
            return EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_ACTION_SEND
        }
    }
}
