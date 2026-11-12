package org.aegis.messenger.app

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Keeps the process alive while an account is unlocked so the poller in [Session] keeps running.
 * It never runs while locked.
 */
class AegisService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val session = (application as AegisApp).session
        if (session.data == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        val n = Notifier.serviceNotification(this)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(2, n)
        }
        return START_NOT_STICKY
    }

    companion object {
        fun start(ctx: Context) {
            try {
                ctx.startForegroundService(Intent(ctx, AegisService::class.java))
            } catch (e: Exception) {
                // Not allowed to start a foreground service right now; the poller still runs while the app is open.
            }
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, AegisService::class.java))
        }
    }
}
