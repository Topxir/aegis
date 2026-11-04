package org.aegis.messenger.core

/** Bucket padding: BE32(len) || frame || zeros. */
object Pad {
    val BUCKETS = intArrayOf(256, 512, 1024, 2048, 4096, 8192, 16384)
    const val MAX_FRAME = 16384 - 4

    fun isBucket(n: Int): Boolean = BUCKETS.contains(n)

    fun bucketFor(len: Int): Int {
        if (len < 0 || len > MAX_FRAME) throw AegisException.FrameTooLarge()
        return BUCKETS.firstOrNull { it >= len + 4 } ?: throw AegisException.FrameTooLarge()
    }

    fun pad(frame: ByteArray): ByteArray {
        val total = bucketFor(frame.size)
        val out = ByteArray(total)
        Bytes.putBe32(out, 0, frame.size.toLong())
        System.arraycopy(frame, 0, out, 4, frame.size)
        return out
    }

    /** Strict inverse of [pad]: bucket length, minimal bucket and zero fill are enforced. */
    fun unpad(padded: ByteArray): ByteArray {
        if (!isBucket(padded.size)) throw AegisException.BadPadding()
        val len = Bytes.be32(padded, 0)
        if (len > MAX_FRAME || len + 4 > padded.size) throw AegisException.BadPadding()
        val n = len.toInt()
        if (bucketFor(n) != padded.size) throw AegisException.BadPadding()
        for (i in 4 + n until padded.size) if (padded[i].toInt() != 0) throw AegisException.BadPadding()
        return padded.copyOfRange(4, 4 + n)
    }
}

object Bytes {
    fun be32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xFF) shl 24) or ((b[off + 1].toLong() and 0xFF) shl 16) or
            ((b[off + 2].toLong() and 0xFF) shl 8) or (b[off + 3].toLong() and 0xFF)

    fun putBe32(b: ByteArray, off: Int, v: Long) {
        b[off] = (v ushr 24).toByte()
        b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte()
        b[off + 3] = v.toByte()
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var o = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, o, p.size)
            o += p.size
        }
        return out
    }

    fun eq(a: ByteArray, b: ByteArray): Boolean = java.security.MessageDigest.isEqual(a, b)
}
