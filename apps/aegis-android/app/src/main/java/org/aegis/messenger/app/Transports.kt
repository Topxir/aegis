package org.aegis.messenger.app

import android.content.Context
import IPtProxy.Controller
import IPtProxy.OnTransportEvents
import org.aegis.messenger.net.Bridges
import org.torproject.jni.TorService
import java.io.File
import java.io.IOException

/**
 * Bridge settings and the pluggable transports (IPtProxy: lyrebird and snowflake) that run inside
 * the app. The settings live outside the vault because Tor starts before unlock.
 */
object Transports {
    private const val PREFS = "aegis_bridges"

    private var controller: Controller? = null
    private val running = LinkedHashSet<String>()

    fun mode(ctx: Context): Bridges.Mode =
        Bridges.Mode.parse(prefs(ctx).getString("mode", "") ?: "") ?: Bridges.Mode.Off

    fun custom(ctx: Context): String = prefs(ctx).getString("custom", "") ?: ""

    fun save(ctx: Context, mode: Bridges.Mode, custom: String) {
        prefs(ctx).edit().putString("mode", mode.code).putString("custom", custom).apply()
    }

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val events = object : OnTransportEvents {
        override fun connected(transport: String) {}
        override fun error(transport: String, e: Exception) {}
        override fun stopped(transport: String, e: Exception) {}
    }

    private fun controller(ctx: Context): Controller =
        controller ?: Controller(File(ctx.noBackupFilesDir, "pt").apply { mkdirs() }.path, false, false, "ERROR", events)
            .also { controller = it }

    /**
     * Starts the transports the bridge settings need and writes the torrc that TorService reads on
     * start. Called with the Tor lock held, before the service is bound. Throws when bridges are
     * chosen but none can be used, so Tor never starts without them.
     */
    fun prepare(ctx: Context) {
        stop()
        val mode = mode(ctx)
        val custom = custom(ctx)
        val need = Bridges.transports(Bridges.linesFor(mode, custom))
        if (need.isNotEmpty()) {
            val c = controller(ctx)
            if ("snowflake" in need) {
                val o = Bridges.options(Bridges.linesFor(mode, custom), "snowflake")
                o["url"]?.let { c.snowflakeBrokerUrl = it }
                o["fronts"]?.let { c.snowflakeFrontDomains = it }
                o["ice"]?.let { c.snowflakeIceServers = it }
            }
            for (t in need) {
                try {
                    c.start(t, "")
                    running.add(t)
                } catch (_: Exception) {
                }
            }
        }
        val rc = Bridges.torrc(mode, custom) { t -> if (t in running) controller?.port(t)?.toInt() else null }
        if (mode != Bridges.Mode.Off && rc.isEmpty()) throw IllegalStateException("no usable bridge")
        try {
            TorService.getTorrc(ctx).writeText(rc)
        } catch (_: IOException) {
            // Without the file Tor would start without bridges.
            if (mode != Bridges.Mode.Off) throw IllegalStateException("torrc")
        }
    }

    fun stop() {
        val c = controller ?: return
        for (t in running) runCatching { c.stop(t) }
        running.clear()
    }
}
