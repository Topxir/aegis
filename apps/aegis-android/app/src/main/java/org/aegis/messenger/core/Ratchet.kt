package org.aegis.messenger.core

/** Append-only binary writer for the local state formats. */
class StateWriter {
    private val out = java.io.ByteArrayOutputStream()
    fun raw(b: ByteArray) = apply { out.write(b, 0, b.size) }
    fun u8(v: Int) = apply { out.write(v) }
    fun u16(v: Int) = apply { out.write(v ushr 8); out.write(v) }
    fun u32(v: Long) = apply { for (s in intArrayOf(24, 16, 8, 0)) out.write((v ushr s).toInt()) }
    fun u64(v: Long) = apply { for (s in 56 downTo 0 step 8) out.write((v ushr s).toInt()) }
    fun opt32(v: ByteArray?) = apply { if (v == null) u8(0) else { u8(1); raw(v) } }
    fun optU64(v: Long?) = apply { if (v == null) u8(0) else { u8(1); u64(v) } }
    fun flag(v: Boolean) = apply { u8(if (v) 1 else 0) }
    fun str(s: String) = apply {
        val b = Text.utf8(s)
        val n = minOf(b.size, 255)
        u8(n)
        raw(b.copyOf(n))
    }
    fun finish(): ByteArray = out.toByteArray()
}

class StateReader(private val b: ByteArray) {
    private var o = 0
    fun take(n: Int): ByteArray {
        if (n < 0 || b.size - o < n) throw AegisException.Session("state")
        return b.copyOfRange(o, o + n).also { o += n }
    }
    fun magic(m: String) { if (!Bytes.eq(take(4), Text.utf8(m))) throw AegisException.Session("state") }
    fun u8(): Int = take(1)[0].toInt() and 0xFF
    fun u16(): Int = (u8() shl 8) or u8()
    fun u32(): Long = Bytes.be32(take(4), 0)
    fun u64(): Long { var v = 0L; for (x in take(8)) v = (v shl 8) or (x.toLong() and 0xFF); return v }
    fun opt32(): ByteArray? = when (u8()) { 0 -> null; 1 -> take(32); else -> throw AegisException.Session("state") }
    fun flag(): Boolean = when (u8()) { 0 -> false; 1 -> true; else -> throw AegisException.Session("state") }
    fun optU64(): Long? = if (flag()) u64() else null
    fun str(): String = String(take(u8()), Charsets.UTF_8)
    fun end() { if (o != b.size) throw AegisException.Session("state") }
}

/** Key derivation shared by the ratchet and sender keys (spec sections 27.3 and 28). */
object Kdf {
    fun ck(ck: ByteArray): Pair<ByteArray, ByteArray> =
        Crypto.hmacSha256(ck, byteArrayOf(1)) to Crypto.hmacSha256(ck, byteArrayOf(2))

    /** Key and nonce from a message key. */
    fun msgKey(mk: ByteArray, info: String): Pair<ByteArray, ByteArray> {
        val kn = Crypto.hkdfN(mk, ByteArray(32), Text.utf8(info), 44)
        return kn.copyOfRange(0, 32) to kn.copyOfRange(32, 44)
    }

    fun rk(rk: ByteArray, dh: ByteArray): Pair<ByteArray, ByteArray> {
        val o = Crypto.hkdfN(dh, rk, Text.utf8("aegis-v2 ratchet"), 64)
        return o.copyOfRange(0, 32) to o.copyOfRange(32, 64)
    }
}

/** Double Ratchet (spec section 27.3). */
class Ratchet private constructor(
    val ad: ByteArray,
    private var dhsSk: ByteArray,
    private var dhr: ByteArray?,
    private var rk: ByteArray,
    private var cks: ByteArray?,
    private var ckr: ByteArray?,
    private var ns: Long,
    private var nr: Long,
    private var pn: Long,
    private val skipped: MutableList<Skipped>,
) {
    private class Skipped(val dh: ByteArray, val n: Long, val mk: ByteArray, val ts: Long)

    private fun copy() = Ratchet(ad, dhsSk, dhr, rk, cks, ckr, ns, nr, pn, skipped.toMutableList())

    val skippedLen: Int get() = skipped.size
    fun canSend(): Boolean = cks != null

    private fun header(pk: ByteArray, pn: Long, n: Long): ByteArray {
        val h = ByteArray(HEADER_LEN)
        System.arraycopy(pk, 0, h, 0, 32)
        Bytes.putBe32(h, 32, pn)
        Bytes.putBe32(h, 36, n)
        return h
    }

    /** ratchet_msg = header || AEAD(key, nonce, AD || header, plaintext). */
    fun encrypt(plain: ByteArray): ByteArray {
        val c = cks ?: throw AegisException.Session("no sending chain")
        val (mk, next) = Kdf.ck(c)
        val h = header(Crypto.x25519Public(dhsSk), pn, ns)
        val (key, nonce) = Kdf.msgKey(mk, "aegis-v2 msg-key")
        val ct = Crypto.aeadSeal(key, nonce, Bytes.concat(ad, h), plain)
        if (ns >= 0xFFFFFFFFL) throw AegisException.Session("counter")
        ns++
        cks = next
        return Bytes.concat(h, ct)
    }

    fun decrypt(msg: ByteArray, now: Long): ByteArray = decryptWith(Crypto.randomBytes(32), msg, now)

    /** Decrypts on a copy and replaces this state only if the AEAD check passes. */
    fun decryptWith(newDhsSk: ByteArray, msg: ByteArray, now: Long): ByteArray {
        val c = copy()
        val plain = c.decryptInner(newDhsSk, msg, now)
        dhsSk = c.dhsSk; dhr = c.dhr; rk = c.rk; cks = c.cks; ckr = c.ckr
        ns = c.ns; nr = c.nr; pn = c.pn
        skipped.clear(); skipped.addAll(c.skipped)
        return plain
    }

    fun expire(now: Long) {
        skipped.removeAll { now >= it.ts + SKIPPED_TTL_SECS }
    }

    private fun decryptInner(newDhsSk: ByteArray, msg: ByteArray, now: Long): ByteArray {
        if (msg.size < HEADER_LEN + 16) throw AegisException.Length()
        expire(now)
        val h = msg.copyOfRange(0, HEADER_LEN)
        val ct = msg.copyOfRange(HEADER_LEN, msg.size)
        val dhPk = h.copyOfRange(0, 32)
        val pnH = Bytes.be32(h, 32)
        val n = Bytes.be32(h, 36)
        val aad = Bytes.concat(ad, h)
        val i = skipped.indexOfFirst { it.n == n && Bytes.eq(it.dh, dhPk) }
        if (i >= 0) {
            val (key, nonce) = Kdf.msgKey(skipped[i].mk, "aegis-v2 msg-key")
            val plain = Crypto.aeadOpen(key, nonce, aad, ct)
            skipped.removeAt(i)
            return plain
        }
        val cur = dhr
        if (cur == null || !Bytes.eq(cur, dhPk)) {
            skipUntil(pnH, now)
            dhStep(dhPk, newDhsSk)
        }
        skipUntil(n, now)
        val c = ckr ?: throw AegisException.Session("no receiving chain")
        val (mk, next) = Kdf.ck(c)
        val (key, nonce) = Kdf.msgKey(mk, "aegis-v2 msg-key")
        val plain = Crypto.aeadOpen(key, nonce, aad, ct)
        ckr = next
        nr++
        return plain
    }

    private fun skipUntil(until: Long, now: Long) {
        var ck = ckr ?: return
        if (until <= nr) return
        val need = until - nr
        if (need > MAX_SKIP_STEP || skipped.size + need > MAX_SKIPPED) throw AegisException.Session("too many skipped messages")
        val d = dhr ?: throw AegisException.Session("no receiving chain")
        while (nr < until) {
            val (mk, next) = Kdf.ck(ck)
            skipped.add(Skipped(d, nr, mk, now))
            ck = next
            nr++
        }
        ckr = ck
    }

    private fun dhStep(dhPk: ByteArray, newDhsSk: ByteArray) {
        pn = ns
        ns = 0
        nr = 0
        dhr = dhPk
        val (r1, newCkr) = Kdf.rk(rk, Crypto.dh(dhsSk, dhPk))
        dhsSk = newDhsSk.copyOf()
        val (r2, newCks) = Kdf.rk(r1, Crypto.dh(dhsSk, dhPk))
        rk = r2
        ckr = newCkr
        cks = newCks
    }

    fun encode(): ByteArray {
        val w = StateWriter().raw(Text.utf8("AGR1")).raw(ad).raw(dhsSk).opt32(dhr).raw(rk).opt32(cks).opt32(ckr)
            .u32(ns).u32(nr).u32(pn).u16(minOf(skipped.size, 0xFFFF))
        for (s in skipped) w.raw(s.dh).u32(s.n).raw(s.mk).u64(s.ts)
        return w.finish()
    }

    companion object {
        const val MAX_SKIP_STEP = 1000L
        const val MAX_SKIPPED = 2000
        const val SKIPPED_TTL_SECS = 30L * 24 * 3600
        const val HEADER_LEN = 40

        fun initInitiator(sk: ByteArray, ad: ByteArray, bSpk: ByteArray): Ratchet =
            initInitiatorWith(Crypto.randomBytes(32), sk, ad, bSpk)

        fun initInitiatorWith(dhsSk: ByteArray, sk: ByteArray, ad: ByteArray, bSpk: ByteArray): Ratchet {
            val (rk, cks) = Kdf.rk(sk, Crypto.dh(dhsSk, bSpk))
            return Ratchet(ad.copyOf(), dhsSk.copyOf(), bSpk.copyOf(), rk, cks, null, 0, 0, 0, mutableListOf())
        }

        fun initResponder(sk: ByteArray, ad: ByteArray, spkSk: ByteArray): Ratchet =
            Ratchet(ad.copyOf(), spkSk.copyOf(), null, sk.copyOf(), null, null, 0, 0, 0, mutableListOf())

        fun decode(bytes: ByteArray): Ratchet {
            val r = StateReader(bytes)
            r.magic("AGR1")
            val ad = r.take(128)
            val dhs = r.take(32)
            val dhr = r.opt32()
            val rk = r.take(32)
            val cks = r.opt32()
            val ckr = r.opt32()
            val ns = r.u32(); val nr = r.u32(); val pn = r.u32()
            val count = r.u16()
            if (count > MAX_SKIPPED) throw AegisException.Session("state")
            val sk = ArrayList<Skipped>(count)
            repeat(count) { sk.add(Skipped(r.take(32), r.u32(), r.take(32), r.u64())) }
            r.end()
            return Ratchet(ad, dhs, dhr, rk, cks, ckr, ns, nr, pn, sk)
        }
    }
}
