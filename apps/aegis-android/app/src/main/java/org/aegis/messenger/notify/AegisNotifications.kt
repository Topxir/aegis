package org.aegis.messenger.notify

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import org.aegis.messenger.MainActivity
import org.aegis.messenger.R

/**
 * Local push notifications for incoming Aegis messages.
 *
 * Notifications never include @usernames or secrets: only the clean chat title and the
 * message text, and only when the user has explicitly enabled push notifications.
 */
object AegisNotifications {
    const val CHANNEL_ID = "aegis_messages_v1"
    private const val CHANNEL_SOUND_ID = "aegis_messages_sound_v1"

    /** Set by [MainActivity]; the foreground service avoids duplicate notifications while the UI is open. */
    @Volatile
    var isAppForeground: Boolean = false

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val silent = NotificationChannel(
            CHANNEL_ID,
            "Aegis messages",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Incoming Aegis messages"
            setSound(null, null)
            enableVibration(false)
        }
        manager.createNotificationChannel(silent)

        val sound = NotificationChannel(
            CHANNEL_SOUND_ID,
            "Aegis messages (sound)",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Incoming Aegis messages with sound"
            val attrs = AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .build()
            setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION), attrs)
            enableVibration(true)
        }
        manager.createNotificationChannel(sound)
    }

    fun showMessage(
        context: Context,
        title: String,
        text: String,
        sound: Boolean,
        notificationId: Int = 0xA3615
    ) {
        ensureChannels(context)
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pending = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = NotificationCompat.Builder(
            context,
            if (sound) CHANNEL_SOUND_ID else CHANNEL_ID
        )
            .setSmallIcon(R.drawable.ic_launcher_aegis)
            .setContentTitle(title.ifBlank { "Aegis" })
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setContentIntent(pending)
            .setPriority(if (sound) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setSilent(!sound)
        if (sound) {
            builder.setDefaults(NotificationCompat.DEFAULT_SOUND or NotificationCompat.DEFAULT_VIBRATE)
        }
        runCatching {
            NotificationManagerCompat.from(context).notify(notificationId, builder.build())
        }
    }
}
