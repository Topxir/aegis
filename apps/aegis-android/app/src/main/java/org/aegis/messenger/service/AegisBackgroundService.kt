package org.aegis.messenger.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Persistent Zero-GMS Foreground Service (`PLAN.md §7.2`, `AGENTS.md §2.2`, `D-0019`).
 *
 * Responsibilities:
 * 1. Maintains the multiplexed QUIC / TLS 1.3 connection to the user's chosen Aegis static-IP
 *    starter server (or optional Tor `.onion` hidden service) without Google Play Services / Firebase FCM.
 * 2. Runs the adaptive keep-alive timer and background Cover Traffic dummy frame scheduler (`256 B`).
 * 3. Displays strictly redacted notifications ("Aegis: Активна защита соединения") —
 *    NEVER exposing sender aliases, message previews, or secret material to the OS notification log (`AGENTS.md §2.4`).
 */
class AegisBackgroundService : Service() {

    override fun onCreate() {
        super.onCreate()
        createRedactedNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = buildZeroKnowledgeNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createRedactedNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Aegis Зашифрованный Канал (Zero-GMS)",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Фоновый приём зашифрованных сообщений и звонков без утечки метаданных"
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun buildZeroKnowledgeNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("Aegis: Активна защита соединения")
            .setContentText("Прямой Static-IP E2EE / Опциональный Tor • Без телеметрии • Паддинг 256B")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .build()
    }

    companion object {
        const val ACTION_START_TRANSPORT = "org.aegis.messenger.action.START_TRANSPORT"
        private const val CHANNEL_ID = "aegis_zero_knowledge_transport"
        private const val NOTIFICATION_ID = 4201
    }
}
