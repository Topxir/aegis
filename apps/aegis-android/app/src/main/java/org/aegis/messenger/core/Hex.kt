package org.aegis.messenger.core

/** Lowercase hex, strict on decode. */
object Hex {
    private const val DIGITS = "0123456789abcdef"

    fun encode(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xFF
            sb.append(DIGITS[v ushr 4]).append(DIGITS[v and 15])
        }
        return sb.toString()
    }

    private fun nib(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        else -> -1
    }

    fun decode(s: String): ByteArray {
        if (s.length % 2 != 0) throw AegisException.InvalidHex()
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            val h = nib(s[2 * i])
            val l = nib(s[2 * i + 1])
            if (h < 0 || l < 0) throw AegisException.InvalidHex()
            out[i] = ((h shl 4) or l).toByte()
        }
        return out
    }

    fun decodeFixed(s: String, bytes: Int): ByteArray {
        if (s.length != bytes * 2) throw AegisException.InvalidHex()
        return decode(s)
    }

    fun isHexLen(s: String, bytes: Int): Boolean =
        s.length == bytes * 2 && s.all { nib(it) >= 0 }
}
