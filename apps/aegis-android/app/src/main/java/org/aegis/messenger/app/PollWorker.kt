package org.aegis.messenger.app

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Official
import org.aegis.messenger.core.QueueIds
import org.aegis.messenger.net.Client
import org.aegis.messenger.net.DirectTransport
import org.aegis.messenger.net.Endpoint
import org.aegis.messenger.net.ProxyAddr
import org.aegis.messenger.net.Route
import org.aegis.messenger.net.SocksTransport
import java.util.concurrent.TimeUnit
import kotlin.random.Random

fun clientFor(endpoint: String, proxy: String, gate: ((org.aegis.messenger.net.Transport) -> org.aegis.messenger.net.Transport)? = null): Client {
    val route = Route.plan(Tor.enabled, endpoint, proxy)
    val ep = Endpoint.parse(route.endpoint)
    val inner = when {
        route.viaTor -> TorTransport()
        route.proxy.isBlank() -> DirectTransport()
        else -> SocksTransport(ProxyAddr.parse(route.proxy))
    }
    val t = KeyAlarmTransport(org.aegis.messenger.net.SealedTransport(inner, AppPins.pins))
    return Client(ep, gate?.invoke(t) ?: t)
}

/**
 * Background check while the vault is locked (spec section 21). It knows only public values: the
 * endpoint, the inbox queue derived from x_pk and the official channel queue. It reads no frame
 * contents and shows "New message" with no sender or text.
 */
class PollWorker(private val ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result {
        val p = BgState.prefs(ctx)
        val endpoint = p.getString("endpoint", "") ?: ""
        val inbox = p.getString("inbox", "") ?: ""
        if (endpoint.isEmpty() || inbox.isEmpty() || !Boot.backgroundPoll(ctx)) return Result.success()
        // While the app is unlocked in this process the foreground poller handles delivery.
        val s = (ctx.applicationContext as? AegisApp)?.session
        if (s?.data != null) return Result.success()
        return try {
            val client = clientFor(endpoint, p.getString("proxy", "") ?: "")
            var fresh = false
            for ((name, q) in listOf("inbox" to Hex.decode(inbox)) + (if (Official.available) listOf("official" to Official.queue()) else emptyList())) {
                val key = "cur_$name"
                val after = p.getLong(key, 0L)
                val r = client.poll(q, after)
                if (r.frames.isNotEmpty()) {
                    fresh = true
                    p.edit().putLong(key, r.next).apply()
                }
            }
            if (fresh) Notifier.newMessage(ctx)
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}

/** Public routing values the worker needs; written whenever an unlocked account changes them. */
object BgState {
    private const val PREFS = "aegis_bg"
    fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun store(ctx: Context, endpoint: String, proxy: String, xSk: ByteArray) {
        val inbox = Hex.encode(QueueIds.inbox(Crypto.x25519Public(xSk)))
        val p = prefs(ctx)
        val same = p.getString("inbox", "") == inbox && p.getString("endpoint", "") == endpoint
        val e = p.edit().putString("endpoint", endpoint).putString("proxy", proxy).putString("inbox", inbox)
        if (!same) e.remove("cur_inbox").remove("cur_official")
        e.apply()
    }

    fun clear(ctx: Context) {
        prefs(ctx).edit().clear().apply()
    }

    /** At most every 15 minutes (WorkManager's floor), with a random start offset. */
    fun schedule(ctx: Context, on: Boolean) {
        val wm = WorkManager.getInstance(ctx)
        if (!on) {
            wm.cancelUniqueWork("aegis-poll")
            return
        }
        val req = PeriodicWorkRequestBuilder<PollWorker>(15, TimeUnit.MINUTES)
            .setInitialDelay(Random.nextLong(1, 6), TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        wm.enqueueUniquePeriodicWork("aegis-poll", ExistingPeriodicWorkPolicy.UPDATE, req)
    }
}
