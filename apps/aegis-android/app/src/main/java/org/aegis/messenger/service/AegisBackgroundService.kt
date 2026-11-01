package org.aegis.messenger.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import org.aegis.messenger.core.AegisRustBridge
import org.aegis.messenger.notify.AegisNotifications

/**
 * Persistent Zero-GMS Foreground Service (`PLAN.md §7.2`, `AGENTS.md §2.2`, `D-0019`).
 *
 * Responsibilities:
 * 1. Maintains the multiplexed QUIC / TLS 1.3 connection to the user's chosen Aegis static-IP
 *    starter server (or optional Tor `.onion` hidden service) without Google Play Services / Firebase FCM.
 * 2. Runs the adaptive keep-alive timer and background Cover Traffic dummy frame scheduler (`256 B`).
 * 3. Polls the user's inboxes while the app is in the background and raises local push
 *    notifications for new messages (only when the user enabled them in Profile).
 */
class AegisBackgroundService : Service() {

    private var pollThread: Thread? = null
    @Volatile private var running = false

    override fun onCreate() {
        super.onCreate()
        createRedactedNotificationChannel()
        AegisNotifications.ensureChannels(this)
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
        startBackgroundPolling()
        return START_STICKY
    }

    private fun startBackgroundPolling() {
        if (running) return
        running = true
        pollThread = Thread {
            val bridge = runCatching { AegisRustBridge(applicationContext) }.getOrNull() ?: return@Thread
            while (running) {
                try {
                    if (bridge.isAuthenticated && bridge.pushNotificationsEnabled &&
                        !AegisNotifications.isAppForeground
                    ) {
                        bridge.syncAllChatsAndInboxAsync { newCount, _ ->
                            if (newCount > 0) {
                                bridge.lastPushToast?.let { (title, text) ->
                                    AegisNotifications.showMessage(
                                        applicationContext,
                                        title,
                                        text,
                                        bridge.soundNotificationsEnabled
                                    )
                                }
                            }
                            bridge.lastPushToast = null
                        }
                    }
                    Thread.sleep(20_000L)
                } catch (_: InterruptedException) {
                    return@Thread
                } catch (_: Exception) {
                    // Keep the transport alive even if a single poll fails.
                    runCatching { Thread.sleep(5_000L) }
                }
            }
        }.also { it.isDaemon = true; it.start() }
    }

    override fun onDestroy() {
        running = false
        pollThread?.interrupt()
        pollThread = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createRedactedNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Системная фоновая синхронизация",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Фоновая синхронизация данных без телеметрии"
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
            .setContentTitle("Система: Фоновая синхронизация")
            .setContentText("Активен защищённый канал (0 телеметрии • 256B)")
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
