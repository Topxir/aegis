package org.aegis.messenger.net

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Cover
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Json
import org.aegis.messenger.core.Pad
import org.aegis.messenger.core.Pin
import org.aegis.messenger.core.Pow
import org.aegis.messenger.core.Prekeys
import org.aegis.messenger.core.Registration
import org.aegis.messenger.core.Text
import org.aegis.messenger.core.Update
import org.aegis.messenger.core.X3dh

class DirEntry(val u: String, val title: String, val x: ByteArray, val ed: ByteArray)

class Polled(val frames: List<Pair<Long, ByteArray>>, val next: Long, val hasMore: Boolean = false)

sealed class PinOpen {
    class Ok(val s: ByteArray) : PinOpen()
    class Wrong(val left: Int) : PinOpen()
    object Gone : PinOpen()
    object Throttled : PinOpen()
}

/** Blocking protocol v2 client. Call from a background thread only. */
class Client(private val ep: Endpoint, private val transport: Transport) {
    /** Called with (request body size, response body size) of real sends and polls; request size is -1 when there is none. */
    @Volatile var observe: ((Int, Int) -> Unit)? = null

    companion object {
        const val POW_BITS = 18
        const val MAX_POW_BITS = 28
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

    /** Random starting point for the proof search, so a repeated request never repeats its proof. */
    private fun powStart(): ULong = (java.security.SecureRandom().nextInt().toLong() and 0xFFFFFFFFL).toULong()

    /** The bits asked for by a 429 answer, within the allowed range, or null. */
    private fun bitsWanted(r: Response): Int? {
        if (r.code != 429) return null
        return try {
            val b = (Json.parseObject(String(r.body, Charsets.UTF_8))["bits"] as? Long)?.toInt()
            b?.takeIf { it in POW_BITS + 1..MAX_POW_BITS }
        } catch (e: Json.ParseException) {
            null
        } catch (e: ClassCastException) {
            null
        }
    }

    fun send(queue: ByteArray, frame: ByteArray): Long {
        val body = Text.utf8(Hex.encode(Pad.pad(frame)))
        val q = Hex.encode(queue)
        var bits = POW_BITS
        var r: Response
        var tries = 0
        do {
            val ts = System.currentTimeMillis() / 1000
            val pow = Pow.mine(q, ts, Pow.bodyHashHex(body), bits, powStart())
            r = transport.request(ep, "POST", "/api/v2/queue/send?q=$q&ts=$ts&pow=$pow", body, PLAIN)
            val more = if (tries == 0) bitsWanted(r) else null
            if (more == null) break
            bits = more
            tries++
        } while (true)
        if (r.code != 200) throw AegisException.Http(r.code)
        observe?.invoke(body.size, r.body.size)
        return (obj(r)["seq"] as? Long) ?: throw AegisException.BadResponse()
    }

    /** Publishes prekeys (spec 27.1). Returns the number of one-time prekeys the server now holds. */
    fun prekeysPut(form: String): Int {
        val r = transport.request(ep, "POST", "/api/v2/prekeys/put", Text.utf8(form), FORM)
        if (r.code != 200) throw AegisException.Http(r.code)
        return ((obj(r)["opks"] as? Long) ?: throw AegisException.BadResponse()).toInt()
    }

    /** Fetches and consumes a prekey bundle. Null means the contact has none (they need to update). */
    fun prekeysTake(u: String): X3dh.Bundle? {
        val ts = System.currentTimeMillis() / 1000
        val pow = Pow.mine(Prekeys.takeScope(u), ts, Prekeys.takeBodyHash(u, ts), POW_BITS, powStart())
        val r = transport.request(ep, "POST", "/api/v2/prekeys/take", Text.utf8(Prekeys.takeForm(u, ts, pow)), FORM)
        if (r.code == 404) return null
        if (r.code != 200) throw AegisException.Http(r.code)
        return X3dh.Bundle.fromJson(r.body)
    }

    /** Dummy request for cover traffic (spec section 26). The answer is ignored. */
    fun nop(reqLen: Int, respLen: Int): Int {
        val body = Cover.nopBody(reqLen, respLen)
        val r = transport.request(ep, "POST", "/api/v2/nop", body, "application/octet-stream")
        if (r.code != 200) throw AegisException.Http(r.code)
        return r.body.size
    }

    private fun pinPost(path: String, slotHex: String, hashInput: String, fields: String): Response {
        val ts = System.currentTimeMillis() / 1000
        val pow = Pow.mine(Pin.powScope(slotHex), ts, Pow.bodyHashHex(Text.utf8(hashInput)), POW_BITS, powStart())
        return transport.request(ep, "POST", path, Text.utf8("$fields&ts=$ts&pow=$pow"), FORM)
    }

    /** Stores S for a new PIN slot. An existing slot surfaces as Http(409). */
    fun pinCreate(slot: ByteArray, verifier: ByteArray, s: ByteArray) {
        val sl = Hex.encode(slot)
        val v = Hex.encode(verifier)
        val sh = Hex.encode(s)
        val r = pinPost("/api/v2/pin/create", sl, Pin.createHashInput(sl, v, sh), "slot=$sl&v=$v&s=$sh")
        if (r.code != 200) throw AegisException.Http(r.code)
    }

    fun pinOpen(slot: ByteArray, verifier: ByteArray): PinOpen {
        val sl = Hex.encode(slot)
        val v = Hex.encode(verifier)
        var throttled = 0
        while (true) {
            val r = pinPost("/api/v2/pin/open", sl, Pin.openHashInput(sl, v), "slot=$sl&v=$v")
            when (r.code) {
                200 -> {
                    val sHex = obj(r)["s"] as? String ?: throw AegisException.BadResponse()
                    return try { PinOpen.Ok(Hex.decodeFixed(sHex, 32)) } catch (e: AegisException.InvalidHex) { throw AegisException.BadResponse() }
                }
                403 -> return PinOpen.Wrong(((obj(r)["left"] as? Long) ?: throw AegisException.BadResponse()).toInt())
                404 -> return PinOpen.Gone
                429 -> {
                    if (++throttled > 2) return PinOpen.Throttled
                    try { Thread.sleep(1100) } catch (e: InterruptedException) { return PinOpen.Throttled }
                }
                else -> throw AegisException.Http(r.code)
            }
        }
    }

    fun pinDelete(slot: ByteArray, verifier: ByteArray) {
        val sl = Hex.encode(slot)
        val v = Hex.encode(verifier)
        val r = pinPost("/api/v2/pin/delete", sl, Pin.openHashInput(sl, v), "slot=$sl&v=$v")
        if (r.code != 200 && r.code != 404) throw AegisException.Http(r.code)
    }

    fun poll(queue: ByteArray, after: Long): Polled {
        val r = transport.request(ep, "GET", "/api/v2/queue/poll?q=${Hex.encode(queue)}&after=$after", null, null)
        if (r.code != 200) throw AegisException.Http(r.code)
        observe?.invoke(-1, r.body.size)
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
        return Polled(out, next, o["has_more"] == true)
    }

    /** Uploads one encrypted chunk (spec section 14). A taken id surfaces as Http(409). */
    fun blobPut(id: ByteArray, chunk: ByteArray) {
        val hex = Hex.encode(id)
        val ts = System.currentTimeMillis() / 1000
        val pow = Pow.mine("blob:$hex", ts, Pow.bodyHashHex(chunk), POW_BITS, powStart())
        val r = transport.request(ep, "POST", "/api/v2/blob/put?id=$hex&ts=$ts&pow=$pow", chunk, "application/octet-stream")
        if (r.code != 200) throw AegisException.Http(r.code)
    }

    /** Returns null when the blob is unknown or expired. */
    fun blobGet(id: ByteArray): ByteArray? {
        val r = transport.request(ep, "GET", "/api/v2/blob/get?id=" + Hex.encode(id), null, null)
        if (r.code == 404) return null
        if (r.code != 200) throw AegisException.Http(r.code)
        return r.body
    }

    /** The signed update manifest (spec section 29), or null when none is published. */
    fun updateManifest(): ByteArray? {
        val r = transport.request(ep, "GET", "/api/v2/update/manifest", null, null)
        return when {
            r.code == 404 -> null
            r.code != 200 -> throw AegisException.Http(r.code)
            r.body.isEmpty() || r.body.size > Update.MAX_MANIFEST -> throw AegisException.BadResponse()
            else -> r.body
        }
    }

    /** Up to one chunk of a published update file, starting at byte [off]. */
    fun updateChunk(name: String, off: Long): ByteArray {
        if (!Update.validName(name)) throw AegisException.Update("file name")
        val r = transport.request(ep, "GET", "/api/v2/update/file?name=$name&off=$off", null, null)
        if (r.code != 200) throw AegisException.Http(r.code)
        if (r.body.isEmpty() || r.body.size > Update.CHUNK) throw AegisException.BadResponse()
        return r.body
    }
}
