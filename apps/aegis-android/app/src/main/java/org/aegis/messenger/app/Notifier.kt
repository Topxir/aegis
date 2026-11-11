package org.aegis.messenger.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import org.aegis.messenger.MainActivity
import org.aegis.messenger.R

/**
 * New-message notifications. They carry no sender and no text unless the user switched content on
 * and the app is unlocked (see [NoteText]); the lock screen never shows more than "New message".
 */
object Notifier {
    const val CHANNEL_MESSAGES = "messages"
    const val CHANNEL_SERVICE = "service"
    private const val ID_MESSAGE = 1

    fun ensureChannels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_MESSAGES, ctx.getString(R.string.channel_messages), NotificationManager.IMPORTANCE_DEFAULT).apply {
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                enableLights(true)
                lightColor = ctx.getColor(R.color.notif_accent)
                setShowBadge(false)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_SERVICE, ctx.getString(R.string.channel_service), NotificationManager.IMPORTANCE_LOW).apply {
                setShowBadge(false)
            },
        )
    }

    private fun openApp(ctx: Context): PendingIntent = PendingIntent.getActivity(
        ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private fun base(ctx: Context, channel: String): Notification.Builder =
        Notification.Builder(ctx, channel)
            .setSmallIcon(R.drawable.ic_stat)
            .setColor(ctx.getColor(R.color.notif_accent))
            .setLargeIcon(BitmapFactory.decodeResource(ctx.resources, R.drawable.notif_large))
            .setShowWhen(true)

    private fun generic(ctx: Context, visibility: Int): Notification =
        base(ctx, CHANNEL_MESSAGES)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setContentTitle(ctx.getString(R.string.app_name))
            .setContentText(ctx.getString(R.string.notif_new_message))
            .setVisibility(visibility)
            .setAutoCancel(true)
            .setContentIntent(openApp(ctx))
            .build()

    /**
     * Posts the new-message notification. Without [m] (the vault is locked) or with content hidden it is
     * the generic one, kept off the lock screen entirely while the app lock is on. With content shown
     * the lock screen gets the generic version.
     */
    fun newMessage(ctx: Context, m: NoteText.Incoming? = null, showContent: Boolean = false) {
        val note = NoteText.note(m == null, showContent, ctx.getString(R.string.app_name), ctx.getString(R.string.notif_new_message), m)
        val hidden = Notification.VISIBILITY_PRIVATE
        val n = if (m == null || !showContent) {
            generic(ctx, if (Boot.appLock(ctx)) Notification.VISIBILITY_SECRET else hidden)
        } else {
            base(ctx, CHANNEL_MESSAGES)
                .setCategory(Notification.CATEGORY_MESSAGE)
                .setContentTitle(note.title)
                .setContentText(note.body)
                .setStyle(Notification.BigTextStyle().bigText(note.body))
                .setVisibility(hidden)
                .setPublicVersion(generic(ctx, Notification.VISIBILITY_PUBLIC))
                .setAutoCancel(true)
                .setContentIntent(openApp(ctx))
                .build()
        }
        try {
            ctx.getSystemService(NotificationManager::class.java).notify(ID_MESSAGE, n)
        } catch (e: SecurityException) {
            // Notification permission denied.
        }
    }

    fun cancelAll(ctx: Context) {
        ctx.getSystemService(NotificationManager::class.java).cancel(ID_MESSAGE)
    }

    fun serviceNotification(ctx: Context): Notification =
        Notification.Builder(ctx, CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_stat)
            .setColor(ctx.getColor(R.color.notif_accent))
            .setContentTitle(ctx.getString(R.string.app_name))
            .setContentText(ctx.getString(R.string.notif_service))
            .setOngoing(true)
            .setVisibility(Notification.VISIBILITY_SECRET)
            .setContentIntent(openApp(ctx))
            .build()
}
