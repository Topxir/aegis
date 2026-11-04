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

class AegisApp : Application() {
    lateinit var session: Session
        private set

    override fun onCreate() {
        super.onCreate()
        LegacyWipe.run(this)
        session = Session(this)
        Notifier.ensureChannels(this)
    }
}
