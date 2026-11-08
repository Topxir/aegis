package org.aegis.messenger.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings as SystemSettings
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.FileProvider
import org.aegis.messenger.BuildConfig
import org.aegis.messenger.R
import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Update
import org.aegis.messenger.data.Settings
import org.aegis.messenger.net.Client
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

enum class UpdateState { Idle, Checking, Current, Ready, Failed, Rejected }

/** True if [f] is exactly the file [a] describes. */
fun isStaged(f: File, a: Update.Artifact): Boolean {
    if (!f.isFile || f.length() != a.size) return false
    val (sha, len) = FileInputStream(f).use { Update.hash(it) }
    return len == a.size && sha.contentEquals(a.sha256)
}

/**
 * Downloads [a] into [dir] through a `.part` file and returns the checked file. Other files in
 * [dir] are removed, so only one verified update is kept.
 */
fun stageUpdate(dir: File, a: Update.Artifact, chunk: (Long) -> ByteArray): File {
    if (!Update.validName(a.name)) throw AegisException.Update("file name")
    dir.mkdirs()
    val out = File(dir, a.name)
    if (isStaged(out, a)) return out
    dir.listFiles()?.forEach { it.delete() }
    val part = File(dir, a.name + ".part")
    try {
        FileOutputStream(part).use { Update.download(a, it, chunk) }
        if (!part.renameTo(out)) throw AegisException.Update("file rename")
    } finally {
        part.delete()
    }
    return out
}

/**
 * Signed updates (spec section 29): checks the manifest while the app is unlocked, downloads and
 * verifies the APK, and offers it to the system installer with one tap.
 */
object Updater {
    private const val PREFS = "aegis_update"
    private const val CHANNEL = "updates"
    private const val ID_NOTIFY = 3
    private const val INTERVAL_MS = 6 * 60 * 60 * 1000L
    private const val TICK_MIN = 15L

    var state by mutableStateOf(UpdateState.Idle)
        private set
    var version by mutableStateOf("")
        private set

    private var app: Context? = null
    private var settings: () -> Settings? = { null }
    private val worker = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "update").also { it.isDaemon = true } }

    fun init(ctx: Context, current: () -> Settings?) {
        app = ctx.applicationContext
        settings = current
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, ctx.getString(R.string.channel_updates), NotificationManager.IMPORTANCE_DEFAULT).apply {
                setShowBadge(false)
            },
        )
        worker.scheduleWithFixedDelay({ check(false) }, 1, TICK_MIN, TimeUnit.MINUTES)
    }

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** Automatic checks; on unless switched off. */
    fun auto(ctx: Context): Boolean = prefs(ctx).getBoolean("auto", true)

    fun setAuto(ctx: Context, on: Boolean) {
        prefs(ctx).edit().putBoolean("auto", on).apply()
    }

    fun checkNow() {
        worker.execute { check(true) }
    }

    private fun dir(ctx: Context) = File(ctx.cacheDir, "update")

    private fun check(manual: Boolean) {
        val ctx = app ?: return
        val p = prefs(ctx)
        if (!manual && (!auto(ctx) || System.currentTimeMillis() - p.getLong("checked", 0L) < INTERVAL_MS)) return
        // Only while unlocked: the saved server and proxy decide the route, over Tor when it is on.
        val s = settings() ?: return
        state = UpdateState.Checking
        try {
            val client = clientFor(s.endpoint, s.proxy)
            val signed = client.updateManifest()
            p.edit().putLong("checked", System.currentTimeMillis()).apply()
            if (signed == null) return finish(ctx, UpdateState.Current)
            val m = Update.open(signed, Update.trustedKey())
            val offer = Update.evaluate(m, Update.ANDROID, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE.toLong(), p.getLong("seq", 0L))
            p.edit().putLong("seq", m.seq).apply()
            if (offer !is Update.Offer.Newer) return finish(ctx, UpdateState.Current)
            val a = offer.artifact
            if (!a.name.endsWith(".apk")) throw AegisException.Update("file name")
            val apk = stageUpdate(dir(ctx), a) { off -> client.updateChunk(a.name, off) }
            if (!sameSigner(ctx, apk, a.code)) {
                apk.delete()
                throw AegisException.Update("apk signer")
            }
            version = a.version
            state = UpdateState.Ready
            notifyReady(ctx, apk)
        } catch (e: AegisException.Update) {
            state = UpdateState.Rejected
        } catch (e: AegisException.BadSignature) {
            state = UpdateState.Rejected
        } catch (e: Exception) {
            state = UpdateState.Failed
        }
    }

    private fun finish(ctx: Context, s: UpdateState) {
        dir(ctx).listFiles()?.forEach { it.delete() }
        ctx.getSystemService(NotificationManager::class.java).cancel(ID_NOTIFY)
        version = ""
        state = s
    }

    @Suppress("DEPRECATION")
    private fun signers(info: PackageInfo?): Set<String>? {
        val sigs = info?.signingInfo?.apkContentsSigners ?: info?.signatures ?: return null
        return sigs.map { Hex.encode(it.toByteArray()) }.toSet().takeIf { it.isNotEmpty() }
    }

    /** The APK is this app, newer than the installed build and signed by the same certificates. */
    @Suppress("DEPRECATION")
    private fun sameSigner(ctx: Context, apk: File, code: Long): Boolean {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_SIGNATURES
        val got = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageArchiveInfo(apk.path, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getPackageArchiveInfo(apk.path, flags)
        } ?: return false
        val mine = pm.getPackageInfo(ctx.packageName, flags)
        if (got.packageName != ctx.packageName) return false
        if (got.longVersionCode <= mine.longVersionCode || (code > 0 && got.longVersionCode != code)) return false
        val a = signers(got) ?: return false
        val b = signers(mine) ?: return false
        return a == b
    }

    private fun installIntent(ctx: Context, apk: File): Intent =
        Intent(Intent.ACTION_VIEW)
            .setDataAndType(FileProvider.getUriForFile(ctx, ctx.packageName + ".update", apk), "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)

    private fun staged(ctx: Context): File? =
        dir(ctx).listFiles()?.firstOrNull { it.isFile && it.name.endsWith(".apk") }

    private fun notifyReady(ctx: Context, apk: File) {
        val pi = PendingIntent.getActivity(ctx, 1, installIntent(ctx, apk), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = Notification.Builder(ctx, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(ctx.getString(R.string.notif_update))
            .setContentText(ctx.getString(R.string.notif_update_text, version))
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()
        try {
            ctx.getSystemService(NotificationManager::class.java).notify(ID_NOTIFY, n)
        } catch (e: SecurityException) {
            // Notification permission denied; the settings screen still offers the install.
        }
    }

    /** Opens the system installer for the verified update, or the permission screen first. */
    fun install(ctx: Context): Boolean {
        val apk = staged(ctx) ?: return false
        if (!ctx.packageManager.canRequestPackageInstalls()) {
            ctx.startActivity(
                Intent(SystemSettings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + ctx.packageName))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            return false
        }
        ctx.startActivity(installIntent(ctx, apk))
        return true
    }
}
