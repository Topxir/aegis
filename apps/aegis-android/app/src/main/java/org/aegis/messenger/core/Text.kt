package org.aegis.messenger.core

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** Percent-encoding and display-text helpers (spec section 5). */
object Text {
    private const val HEX_UP = "0123456789ABCDEF"

    fun utf8(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    /** Strict UTF-8 decoding: malformed input is an error, never U+FFFD. */
    fun utf8Strict(b: ByteArray): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(b)).toString()
    } catch (_: CharacterCodingException) {
        throw AegisException.InvalidText()
    }

    private fun unreserved(b: Int): Boolean =
        (b in 'A'.code..'Z'.code) || (b in 'a'.code..'z'.code) || (b in '0'.code..'9'.code) ||
            b == '-'.code || b == '_'.code || b == '.'.code || b == '~'.code

    fun pctEncode(s: String): String {
        val sb = StringBuilder()
        for (x in utf8(s)) {
            val b = x.toInt() and 0xFF
            if (unreserved(b)) {
                sb.append(b.toChar())
            } else {
                sb.append('%').append(HEX_UP[b ushr 4]).append(HEX_UP[b and 15])
            }
        }
        return sb.toString()
    }

    private fun upNib(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    /** Strict inverse of [pctEncode]: raw reserved bytes, lowercase and truncated escapes are rejected. */
    fun pctDecodeStrict(s: String): String {
        val out = java.io.ByteArrayOutputStream(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%') {
                if (i + 2 >= s.length) throw AegisException.InvalidText()
                val h = upNib(s[i + 1])
                val l = upNib(s[i + 2])
                if (h < 0 || l < 0) throw AegisException.InvalidText()
                out.write((h shl 4) or l)
                i += 3
            } else if (c.code < 128 && unreserved(c.code)) {
                out.write(c.code)
                i++
            } else {
                throw AegisException.InvalidText()
            }
        }
        return utf8Strict(out.toByteArray())
    }

    /** Canonical unsigned decimal: digits only, no sign, no leading zeros, fits in u64. */
    fun parseU64(s: String): ULong {
        val ok = s.isNotEmpty() && s.length <= 20 && s.all { it in '0'..'9' } &&
            (s == "0" || s[0] != '0')
        if (!ok) throw AegisException.InvalidText()
        return s.toULongOrNull() ?: throw AegisException.InvalidText()
    }

    /** Bidi controls and zero-width characters that let a name or caption read as another one. */
    fun isSpoofing(cp: Int): Boolean = isHiddenFormatChar(cp)

    private fun isHiddenFormatChar(it: Int): Boolean =
        it in 0x200B..0x200F || it in 0x202A..0x202E || it in 0x2060..0x2064 ||
            it in 0x2066..0x206F || it in 0x2028..0x2029 || it in 0xFFF9..0xFFFB ||
            it in 0xE0000..0xE007F || it == 0xFEFF || it == 0x00AD || it == 0x061C || it == 0x180E

    /** Drops control and invisible/bidi formatting characters and keeps at most 64 code points. */
    fun sanitizeDisplay(s: String): String {
        val sb = StringBuilder()
        var count = 0
        var i = 0
        while (i < s.length && count < 64) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            val isControl = Character.getType(cp) == Character.CONTROL.toInt()
            if (isControl || isHiddenFormatChar(cp)) continue
            sb.appendCodePoint(cp)
            count++
        }
        return sb.toString()
    }

    /** Message bodies keep their text but lose bidi overrides and hidden formatting that could spoof layout. */
    fun sanitizeBody(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) {
            if (c == '\n' || c == '\t') { sb.append(c); continue }
            if (Character.getType(c) == Character.CONTROL.toInt()) continue
            if (isHiddenFormatChar(c.code) && c.code != 0x200D) continue
            sb.append(c)
        }
        return sb.toString()
    }
}
