package org.aegis.messenger.net

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Bytes
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Json
import org.aegis.messenger.core.Text

/** Sealed transport (spec section 23): every request travels as one padded AEAD blob to /api/v2/s. */
object Sealed {
    val BUCKETS = intArrayOf(1024, 4096, 16384, 65536, 262144, 1048576, 1114112)
    const val MAX_OUTER = 32 + 1114112 + 16
    private val AAD_REQ = Text.utf8("aegis-v2 sealed-req")
    private val AAD_RESP = Text.utf8("aegis-v2 sealed-resp")

    fun bucketFor(dataLen: Int): Int =
        BUCKETS.firstOrNull { it.toLong() >= dataLen.toLong() + 4 } ?: throw AegisException.FrameTooLarge()

    fun pad(data: ByteArray): ByteArray {
        val total = bucketFor(data.size)
        val out = ByteArray(total)
        Bytes.putBe32(out, 0, data.size.toLong())
        System.arraycopy(data, 0, out, 4, data.size)
        return out
    }

    fun unpad(padded: ByteArray): ByteArray {
        if (padded.size !in BUCKETS.toList()) throw AegisException.BadPadding()
        val len = Bytes.be32(padded, 0)
        if (len > padded.size - 4) throw AegisException.BadPadding()
        val end = 4 + len.toInt()
        if (bucketFor(len.toInt()) != padded.size) throw AegisException.BadPadding()
        for (i in end until padded.size) if (padded[i].toInt() != 0) throw AegisException.BadPadding()
        return padded.copyOfRange(4, end)
    }

    /** The sealed request and the key that opens its response. */
    class Request(val outer: ByteArray, val kResp: ByteArray)

    private fun keys(shared: ByteArray, ePk: ByteArray, srvPk: ByteArray): Pair<ByteArray, ByteArray> {
        val salt = Bytes.concat(ePk, srvPk)
        return Crypto.hkdf32(shared, salt, Text.utf8("aegis-v2 sealed-req")) to
            Crypto.hkdf32(shared, salt, Text.utf8("aegis-v2 sealed-resp"))
    }

    fun sealRequest(srvPk: ByteArray, method: String, target: String, body: ByteArray): Request =
        sealRequestAt(Crypto.randomBytes(32), srvPk, method, target, body, System.currentTimeMillis() / 1000)

    fun sealRequestWith(eSk: ByteArray, srvPk: ByteArray, method: String, target: String, body: ByteArray): Request =
        sealRequestAt(eSk, srvPk, method, target, body, null)

    /** Like [sealRequestWith], with an optional timestamp after the method (`GET 1700000000`). */
    fun sealRequestAt(eSk: ByteArray, srvPk: ByteArray, method: String, target: String, body: ByteArray, ts: Long?): Request {
        if (method.contains('\n') || target.contains('\n')) throw AegisException.InvalidText()
        val ePk = Crypto.x25519Public(eSk)
        val shared = Crypto.dh(eSk, srvPk)
        val (kReq, kResp) = keys(shared, ePk, srvPk)
        val inner = Bytes.concat(Text.utf8(if (ts != null) "$method $ts" else method), byteArrayOf(10), Text.utf8(target), byteArrayOf(10), body)
        val ct = Crypto.aeadSeal(kReq, ByteArray(12), Bytes.concat(AAD_REQ, ePk), pad(inner))
        return Request(Bytes.concat(ePk, ct), kResp)
    }

    fun sealResponseWith(nonce: ByteArray, kResp: ByteArray, status: Int, body: ByteArray): ByteArray {
        val inner = Bytes.concat(byteArrayOf((status ushr 8).toByte(), status.toByte()), body)
        return Bytes.concat(nonce, Crypto.aeadSeal(kResp, nonce, AAD_RESP, pad(inner)))
    }

    /** Status and body of a sealed response. */
    fun openResponse(kResp: ByteArray, sealed: ByteArray): Response {
        if (sealed.size <= 12) throw AegisException.Length()
        val padded = Crypto.aeadOpen(kResp, sealed.copyOfRange(0, 12), AAD_RESP, sealed.copyOfRange(12, sealed.size))
        val inner = unpad(padded)
        if (inner.size < 2) throw AegisException.Length()
        val code = ((inner[0].toInt() and 0xFF) shl 8) or (inner[1].toInt() and 0xFF)
        return Response(code, inner.copyOfRange(2, inner.size))
    }
}

/** Where the pinned server keys live. */
interface KeyPins {
    fun get(origin: String): ByteArray?
    fun put(origin: String, key: ByteArray)
    fun remove(origin: String)
}

class MemoryPins : KeyPins {
    private val m = HashMap<String, ByteArray>()
    override fun get(origin: String): ByteArray? = m[origin]?.copyOf()
    override fun put(origin: String, key: ByteArray) { m[origin] = key.copyOf() }
    override fun remove(origin: String) { m.remove(origin) }
}

/**
 * Wraps another transport. The server key is fetched once, pinned on first use, and any later
 * change is a hard stop (ServerKeyChanged). Each request uses a fresh ephemeral key.
 */
class SealedTransport(private val inner: Transport, private val pins: KeyPins) : Transport {
    private var cached: Pair<String, ByteArray>? = null

    private fun fetchKey(ep: Endpoint): ByteArray {
        val r = inner.request(ep, "GET", "/api/v2/key", null, null)
        if (r.code != 200) throw AegisException.Http(r.code)
        try {
            val o = Json.parseObject(String(r.body, Charsets.UTF_8))
            return Hex.decodeFixed(o["x"] as? String ?: throw AegisException.BadResponse(), 32)
        } catch (e: Json.ParseException) {
            throw AegisException.BadResponse()
        } catch (e: AegisException.InvalidHex) {
            throw AegisException.BadResponse()
        }
    }

    private fun serverKey(ep: Endpoint, refresh: Boolean): ByteArray {
        val origin = ep.origin
        val builtIn = if (origin == Endpoint.DEFAULT) Endpoint.DEFAULT_SERVER_X_PK else null
        val pinned = builtIn ?: pins.get(origin)
        if (!refresh) {
            cached?.let { if (it.first == origin) return it.second }
            if (pinned != null) { cached = origin to pinned; return pinned }
        }
        val k = fetchKey(ep)
        if (pinned != null && !Bytes.eq(pinned, k)) throw AegisException.ServerKeyChanged()
        if (pinned == null) pins.put(origin, k)
        if (builtIn != null && !Bytes.eq(builtIn, k)) throw AegisException.ServerKeyChanged()
        cached = origin to k
        return k
    }

    override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response {
        val key = serverKey(ep, false)
        val first = attempt(ep, key, method, pathQuery, body)
        if (first != null) return first
        // The sealed exchange failed: check whether the server key moved before giving up.
        val again = serverKey(ep, true)
        return attempt(ep, again, method, pathQuery, body) ?: throw AegisException.BadResponse()
    }

    private fun attempt(ep: Endpoint, key: ByteArray, method: String, pathQuery: String, body: ByteArray?): Response? {
        val req = Sealed.sealRequest(key, method, pathQuery, body ?: ByteArray(0))
        val r = inner.request(ep, "POST", "/api/v2/s", req.outer, "application/octet-stream")
        if (r.code != 200) return null
        return try {
            Sealed.openResponse(req.kResp, r.body)
        } catch (e: AegisException) {
            null
        }
    }
}
