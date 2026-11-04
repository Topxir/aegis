package org.aegis.messenger.core

import org.bouncycastle.crypto.digests.SHA256Digest

/** Hashcash-style proof of work (spec section 4). */
object Pow {
    const val DEFAULT_BITS = 18
    const val MAX_SKEW_SECS = 600L

    fun bodyHashHex(body: ByteArray): String = Hex.encode(Crypto.sha256(body))

    private fun prefix(scope: String, ts: Long, bodyHash: String): SHA256Digest {
        val d = SHA256Digest()
        val b = Text.utf8("aegis-v2 pow\n$scope\n$ts\n$bodyHash\n")
        d.update(b, 0, b.size)
        return d
    }

    fun hash(scope: String, ts: Long, bodyHash: String, pow: ULong): ByteArray {
        val d = prefix(scope, ts, bodyHash)
        val n = Text.utf8(pow.toString())
        d.update(n, 0, n.size)
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }

    fun leadingZeroBits(h: ByteArray): Int {
        var n = 0
        for (x in h) {
            val b = x.toInt() and 0xFF
            if (b == 0) {
                n += 8
            } else {
                n += Integer.numberOfLeadingZeros(b) - 24
                break
            }
        }
        return n
    }

    fun verify(scope: String, ts: Long, bodyHash: String, pow: ULong, bits: Int): Boolean =
        leadingZeroBits(hash(scope, ts, bodyHash, pow)) >= bits

    /** Smallest nonce satisfying [bits], searching upward from zero. Blocking: call off the main thread. */
    fun mine(scope: String, ts: Long, bodyHash: String, bits: Int): ULong {
        val base = prefix(scope, ts, bodyHash)
        val work = SHA256Digest(base)
        val out = ByteArray(32)
        var n = 0UL
        while (true) {
            work.reset(base)
            val s = Text.utf8(n.toString())
            work.update(s, 0, s.size)
            work.doFinal(out, 0)
            if (leadingZeroBits(out) >= bits || n == ULong.MAX_VALUE) return n
            n++
        }
    }
}
