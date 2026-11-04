package org.aegis.messenger.net

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Json
import org.aegis.messenger.core.Pad
import org.aegis.messenger.core.Pow
import org.aegis.messenger.core.Registration
import org.aegis.messenger.core.Text

class DirEntry(val u: String, val title: String, val x: ByteArray, val ed: ByteArray)

class Polled(val frames: List<Pair<Long, ByteArray>>, val next: Long)

/** Blocking protocol v2 client. Call from a background thread only. */
class Client(private val ep: Endpoint, private val transport: Transport) {
    companion object {
        const val POW_BITS = 18
        const val MAX_POLL = 100
        private const val FORM = "application/x-www-form-urlencoded"
        private const val PLAIN = "text/plain"
    }

    private fun obj(r: Response): Map<String, Any?> = try {
        Json.parseObject(String(r.body, Charsets.UTF_8))
    } catch (e: Json.ParseException) {
        throw AegisException.BadResponse()
    } catch (e: ClassCastException) {
        throw AegisException.BadResponse()
    }

    fun health(): Boolean {
        val r = transport.request(ep, "GET", "/health", null, null)
        if (r.code != 200) throw AegisException.Http(r.code)
        val o = obj(r)
        return o["status"] == "ok" && o["protocol"] == 2L
    }

    /** Returns null when the username is unknown. */
    fun lookup(username: String): DirEntry? {
        val r = transport.request(ep, "GET", "/api/v2/dir/lookup?u=" + Text.pctEncode(username), null, null)
        if (r.code == 404) return null
        if (r.code != 200) throw AegisException.Http(r.code)
        val o = obj(r)
        val u = o["u"] as? String
        val title = o["title"] as? String
        val x = o["x"] as? String
        val ed = o["ed"] as? String
        if (u != username || title == null || x == null || ed == null) throw AegisException.BadResponse()
        try {
            return DirEntry(u, Text.sanitizeDisplay(title), Hex.decodeFixed(x, 32), Hex.decodeFixed(ed, 32))
        } catch (e: AegisException.InvalidHex) {
            throw AegisException.BadResponse()
        }
    }

    /** Mines the proof of work (seconds of CPU) and registers. A taken username surfaces as Http(409). */
    fun register(reg: Registration) {
        reg.mine(POW_BITS)
        val r = transport.request(ep, "POST", "/api/v2/dir/register", Text.utf8(reg.toForm()), FORM)
        if (r.code != 200) throw AegisException.Http(r.code)
    }

    fun send(queue: ByteArray, frame: ByteArray): Long {
        val body = Text.utf8(Hex.encode(Pad.pad(frame)))
        val q = Hex.encode(queue)
        val ts = System.currentTimeMillis() / 1000
        val pow = Pow.mine(q, ts, Pow.bodyHashHex(body), POW_BITS)
        val r = transport.request(ep, "POST", "/api/v2/queue/send?q=$q&ts=$ts&pow=$pow", body, PLAIN)
        if (r.code != 200) throw AegisException.Http(r.code)
        return (obj(r)["seq"] as? Long) ?: throw AegisException.BadResponse()
    }

    fun poll(queue: ByteArray, after: Long): Polled {
        val r = transport.request(ep, "GET", "/api/v2/queue/poll?q=${Hex.encode(queue)}&after=$after", null, null)
        if (r.code != 200) throw AegisException.Http(r.code)
        val o = obj(r)
        val list = o["frames"] as? List<*> ?: throw AegisException.BadResponse()
        val next = o["next"] as? Long ?: throw AegisException.BadResponse()
        if (list.size > MAX_POLL) throw AegisException.BadResponse()
        val out = ArrayList<Pair<Long, ByteArray>>(list.size)
        var last = after
        for (f in list) {
            val m = f as? Map<*, *> ?: throw AegisException.BadResponse()
            val seq = m["seq"] as? Long ?: throw AegisException.BadResponse()
            val d = m["d"] as? String ?: throw AegisException.BadResponse()
            if (seq <= last) throw AegisException.BadResponse()
            last = seq
            val padded = try { Hex.decode(d) } catch (e: AegisException.InvalidHex) { throw AegisException.BadResponse() }
            out.add(seq to padded)
        }
        if (next != last) throw AegisException.BadResponse()
        return Polled(out, next)
    }
}
