package org.aegis.messenger.core

/** X3DH key agreement and prekey bundles (spec sections 27.1 and 27.2). */
object X3dh {
    const val SPK_ROTATE_SECS = 7L * 24 * 3600
    const val SPK_KEEP_SECS = 14L * 24 * 3600
    const val SPK_MAX_AGE_SECS = SPK_ROTATE_SECS + SPK_KEEP_SECS
    const val OPK_REFILL_TO = 50
    const val OPK_LOW = 10
    private const val FUTURE_SKEW_SECS = 600L

    class SignedPrekey(val sk: ByteArray, val pk: ByteArray, val ts: Long, val sig: ByteArray) {
        companion object {
            fun fromSecret(id: Identity, sk: ByteArray, ts: Long): SignedPrekey {
                val pk = Crypto.x25519Public(sk)
                return SignedPrekey(sk.copyOf(), pk, ts, id.sign(Prekeys.spkMessage(Hex.encode(pk), ts)))
            }

            fun generate(id: Identity, ts: Long) = fromSecret(id, Crypto.randomBytes(32), ts)
        }
    }

    fun opksNeeded(remaining: Int): Int = if (remaining < OPK_LOW) maxOf(0, OPK_REFILL_TO - remaining) else 0

    class Bundle(val spk: ByteArray, val spkTs: Long, val spkSig: ByteArray, val opk: ByteArray?) {
        fun check(peerEd: ByteArray, now: Long) {
            if (!Crypto.ed25519Verify(peerEd, Prekeys.spkMessage(Hex.encode(spk), spkTs), spkSig)) throw AegisException.BadSignature()
            if (spkTs > now + FUTURE_SKEW_SECS || now - spkTs > SPK_MAX_AGE_SECS) throw AegisException.Session("signed prekey too old")
        }

        companion object {
            fun fromJson(body: ByteArray): Bundle {
                try {
                    val o = Json.parseObject(String(body, Charsets.UTF_8))
                    val opk = o["opk"] as? String ?: throw AegisException.BadResponse()
                    return Bundle(
                        Hex.decodeFixed(o["spk"] as? String ?: throw AegisException.BadResponse(), 32),
                        o["spk_ts"] as? Long ?: throw AegisException.BadResponse(),
                        Hex.decodeFixed(o["spk_sig"] as? String ?: throw AegisException.BadResponse(), 64),
                        if (opk.isEmpty()) null else Hex.decodeFixed(opk, 32),
                    )
                } catch (e: Json.ParseException) {
                    throw AegisException.BadResponse()
                } catch (e: AegisException.InvalidHex) {
                    throw AegisException.BadResponse()
                }
            }
        }
    }

    /** Long-term keys of both sides, used for AD. */
    class Parties(val aEd: ByteArray, val aX: ByteArray, val bEd: ByteArray, val bX: ByteArray) {
        fun ad(): ByteArray = Bytes.concat(aEd, aX, bEd, bX)
    }

    private fun derive(vararg dhs: ByteArray): ByteArray =
        Crypto.hkdf32(Bytes.concat(ByteArray(32) { 0xFF.toByte() }, *dhs), ByteArray(32), Text.utf8("aegis-v2 x3dh"))

    fun initiateWith(ekSk: ByteArray, aXSk: ByteArray, bXPk: ByteArray, b: Bundle): ByteArray {
        val d1 = Crypto.dh(aXSk, b.spk)
        val d2 = Crypto.dh(ekSk, bXPk)
        val d3 = Crypto.dh(ekSk, b.spk)
        val o = b.opk ?: return derive(d1, d2, d3)
        return derive(d1, d2, d3, Crypto.dh(ekSk, o))
    }

    fun respond(bXSk: ByteArray, spkSk: ByteArray, opkSk: ByteArray?, aXPk: ByteArray, ekPk: ByteArray): ByteArray {
        val d1 = Crypto.dh(spkSk, aXPk)
        val d2 = Crypto.dh(bXSk, ekPk)
        val d3 = Crypto.dh(spkSk, ekPk)
        if (opkSk == null) return derive(d1, d2, d3)
        return derive(d1, d2, d3, Crypto.dh(opkSk, ekPk))
    }
}
