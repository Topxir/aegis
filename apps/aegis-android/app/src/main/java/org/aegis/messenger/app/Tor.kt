package org.aegis.messenger.app

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.IBinder
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import org.aegis.messenger.core.AegisException
import org.aegis.messenger.net.Endpoint
import org.aegis.messenger.net.ProxyAddr
import org.aegis.messenger.net.Response
import org.aegis.messenger.net.SocksTransport
import org.aegis.messenger.net.TOR_TIMEOUT_MS
import org.aegis.messenger.net.Transport
import org.torproject.jni.TorService

enum class TorStatus { Off, Starting, Connected, Failed }

/** The Tor client that runs inside this app (Guardian Project TorService) and its local SOCKS5 port. */
object Tor {
    private const val BOOTSTRAP_WAIT_MS = 120_000L

    var status by mutableStateOf(TorStatus.Off)
        private set

    /** Whether requests go through Tor. Set from [Boot.tor] at startup and by the settings switch. */
    @Volatile var enabled = true
        private set

    private val lock = Object()
    private var app: Context? = null
    private var bound = false
    private var service: TorService? = null
    private var circuit = false
    private var socks: ProxyAddr? = null

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            synchronized(lock) {
                service = (binder as TorService.LocalBinder).service
                publish()
            }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            synchronized(lock) {
                service = null
                circuit = false
                socks = null
                if (bound) status = TorStatus.Failed
                lock.notifyAll()
            }
        }
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            synchronized(lock) {
                if (!bound) return
                if (intent.action == TorService.ACTION_ERROR) {
                    status = TorStatus.Failed
                } else when (intent.getStringExtra(TorService.EXTRA_STATUS)) {
                    TorService.STATUS_ON -> { circuit = true; publish() }
                    TorService.STATUS_STARTING -> { circuit = false; status = TorStatus.Starting }
                    TorService.STATUS_STOPPING, TorService.STATUS_OFF -> { circuit = false; socks = null; status = TorStatus.Failed }
                }
                lock.notifyAll()
            }
        }
    }

    fun init(ctx: Context, on: Boolean) {
        app = ctx.applicationContext
        setEnabled(on)
    }

    fun setEnabled(on: Boolean) {
        enabled = on
        if (on) start() else stop()
    }

    /** Applies changed bridge settings: Tor restarts with the new torrc. */
    fun restart() {
        if (!enabled) return
        stop()
        start()
    }

    private fun publish() {
        val port = service?.socksPort ?: -1
        if (circuit && port > 0) {
            socks = ProxyAddr("127.0.0.1", port)
            status = TorStatus.Connected
            lock.notifyAll()
        }
    }

    private fun start() {
        val ctx = app ?: return
        synchronized(lock) {
            if (bound) return
            status = TorStatus.Starting
            try {
                Transports.prepare(ctx)
            } catch (_: Exception) {
                Transports.stop()
                status = TorStatus.Failed
                return
            }
            val f = IntentFilter().apply { addAction(TorService.ACTION_STATUS); addAction(TorService.ACTION_ERROR) }
            LocalBroadcastManager.getInstance(ctx).registerReceiver(receiver, f)
            bound = ctx.bindService(Intent(ctx, TorService::class.java), connection, Context.BIND_AUTO_CREATE)
            if (!bound) {
                LocalBroadcastManager.getInstance(ctx).unregisterReceiver(receiver)
                Transports.stop()
                status = TorStatus.Failed
            }
        }
    }

    private fun stop() {
        val ctx = app ?: return
        synchronized(lock) {
            if (bound) {
                LocalBroadcastManager.getInstance(ctx).unregisterReceiver(receiver)
                try { ctx.unbindService(connection) } catch (_: IllegalArgumentException) {}
            }
            Transports.stop()
            bound = false
            service = null
            circuit = false
            socks = null
            status = TorStatus.Off
            lock.notifyAll()
        }
    }

    /** The SOCKS5 address once Tor has a circuit; starts it if needed and waits for it. Never returns a clearnet route. */
    fun awaitSocks(): ProxyAddr {
        if (!enabled) throw AegisException.Network("tor off")
        val deadline = SystemClock.elapsedRealtime() + BOOTSTRAP_WAIT_MS
        synchronized(lock) {
            if (status == TorStatus.Failed) stop()
            start()
            while (true) {
                socks?.let { return it }
                if (!enabled || status == TorStatus.Failed) throw AegisException.Network("tor failed")
                val left = deadline - SystemClock.elapsedRealtime()
                if (left <= 0) throw AegisException.Network("tor timeout")
                lock.wait(left)
            }
        }
    }
}

/** Sends every request through the embedded Tor; names, onion ones included, are resolved by Tor. */
class TorTransport : Transport {
    override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response =
        SocksTransport(Tor.awaitSocks(), TOR_TIMEOUT_MS).request(ep, method, pathQuery, body, contentType)
}
