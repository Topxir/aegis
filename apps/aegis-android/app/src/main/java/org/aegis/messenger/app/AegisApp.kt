package org.aegis.messenger.app

import android.app.Application
import android.content.Context
import android.content.res.Configuration
import java.io.File
import java.security.KeyStore
import java.util.Locale

/** Non-secret boot settings kept outside the vault: UI language and the storage format marker. */
object Boot {
    private const val PREFS = "aegis_boot"
    private const val FMT = "fmt"
    private const val LANG = "lang"
    const val FORMAT = 2

    fun language(ctx: Context): String =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(LANG, "") ?: ""

    fun setLanguage(ctx: Context, lang: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(LANG, lang).apply()
    }

    /** FLAG_SECURE on the window; on unless switched off. Read before unlock, so it lives outside the vault. */
    fun secureScreen(ctx: Context): Boolean = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("secure", true)

    fun setSecureScreen(ctx: Context, on: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("secure", on).apply()
    }

    /** Route through the embedded Tor; on unless switched off. Read before unlock, so it lives outside the vault. */
    fun tor(ctx: Context): Boolean = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("tor", true)

    fun setTor(ctx: Context, on: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("tor", on).apply()
    }

    fun backgroundPoll(ctx: Context): Boolean = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("bgpoll", false)

    fun setBackgroundPoll(ctx: Context, on: Boolean) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("bgpoll", on).apply()
    }

    /** Cover traffic level: 0 off, 1 standard (default), 2 high. */
    fun coverMode(ctx: Context): Int = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt("cover", 1)

    fun setCoverMode(ctx: Context, v: Int) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putInt("cover", v).apply()
    }

    /** Local PIN record: account name, server origin and digit count. Empty user means no PIN. */
    fun pinUser(ctx: Context): String = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("pin_user", "") ?: ""
    fun pinEndpoint(ctx: Context): String = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("pin_ep", "") ?: ""
    fun pinDigits(ctx: Context): Int = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt("pin_digits", 4)

    fun pinProxy(ctx: Context): String = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("pin_proxy", "") ?: ""

    fun setPin(ctx: Context, user: String, endpoint: String, proxy: String, digits: Int) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("pin_user", user).putString("pin_ep", endpoint).putString("pin_proxy", proxy).putInt("pin_digits", digits).apply()
    }

    fun clearPin(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove("pin_user").remove("pin_ep").remove("pin_proxy").remove("pin_digits").apply()
    }

    fun format(ctx: Context): Int = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt(FMT, 0)

    fun markFormat(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putInt(FMT, FORMAT).apply()
    }

    /** Applies the chosen language to a base context; empty means follow the system. */
    fun localized(base: Context): Context {
        val lang = language(base)
        if (lang.isEmpty()) return base
        val conf = Configuration(base.resources.configuration)
        conf.setLocale(Locale(lang))
        return base.createConfigurationContext(conf)
    }
}

/**
 * The previous app version stored data in shared preferences, files and Keystore aliases.
 * Protocol v2 cannot read any of it, so it is removed once. Only app-private locations are touched.
 */
internal object LegacyWipe {
    fun run(ctx: Context) {
        if (Boot.format(ctx) >= Boot.FORMAT) return
        ctx.filesDir.listFiles()?.forEach { it.deleteRecursively() }
        ctx.noBackupFilesDir.listFiles()?.forEach { it.deleteRecursively() }
        ctx.cacheDir.listFiles()?.forEach { it.deleteRecursively() }
        ctx.databaseList().forEach { ctx.deleteDatabase(it) }
        val prefsDir = File(ctx.applicationInfo.dataDir, "shared_prefs")
        prefsDir.listFiles()?.forEach { f ->
            val name = f.name.removeSuffix(".xml")
            if (name != "aegis_boot") {
                ctx.deleteSharedPreferences(name)
                f.delete()
            }
        }
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            ks.aliases().toList().forEach { ks.deleteEntry(it) }
        } catch (e: Exception) {
            // No Keystore entries to remove.
        }
        Boot.markFormat(ctx)
    }
}

/** Pinned server keys, one per origin, kept outside the vault so a key change is caught before unlock. */
class PrefsPins(private val ctx: Context) : org.aegis.messenger.net.KeyPins {
    private fun prefs() = ctx.getSharedPreferences("aegis_pins", Context.MODE_PRIVATE)
    override fun get(origin: String): ByteArray? =
        prefs().getString(origin, null)?.let { org.aegis.messenger.core.Hex.decode(it) }

    override fun put(origin: String, key: ByteArray) {
        prefs().edit().putString(origin, org.aegis.messenger.core.Hex.encode(key)).apply()
    }

    override fun remove(origin: String) {
        prefs().edit().remove(origin).apply()
    }
}

object AppPins {
    @Volatile var pins: org.aegis.messenger.net.KeyPins = org.aegis.messenger.net.MemoryPins()

    /** Called with the origin when a pinned server key no longer matches. */
    @Volatile var onKeyChanged: ((String) -> Unit)? = null
}

/** Reports a changed server key to the app, then rethrows so the request stops. */
class KeyAlarmTransport(private val inner: org.aegis.messenger.net.Transport) : org.aegis.messenger.net.Transport {
    override fun request(ep: org.aegis.messenger.net.Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): org.aegis.messenger.net.Response {
        try {
            return inner.request(ep, method, pathQuery, body, contentType)
        } catch (e: org.aegis.messenger.core.AegisException.ServerKeyChanged) {
            AppPins.onKeyChanged?.invoke(ep.origin)
            throw e
        }
    }
}

class AegisApp : Application() {
    lateinit var session: Session
        private set

    override fun onCreate() {
        super.onCreate()
        LegacyWipe.run(this)
        AppPins.pins = PrefsPins(this)
        Tor.init(this, Boot.tor(this))
        session = Session(this)
        Notifier.ensureChannels(this)
        Updater.init(this) { session.data?.settings }
    }
}
