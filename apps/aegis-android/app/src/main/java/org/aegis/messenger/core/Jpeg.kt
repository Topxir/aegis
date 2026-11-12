package org.aegis.messenger.core

/**
 * Keeps only the segments a decoder needs (tables, frame header, scan data) and drops every
 * APPn, COM and unknown segment, so no EXIF, XMP, ICC, thumbnail or comment survives.
 */
object Jpeg {
    private fun keep(marker: Int): Boolean = when (marker) {
        0xDB, 0xC4, 0xDD, 0xDA -> true
        in 0xC0..0xCF -> marker != 0xC8 && marker != 0xCC
        else -> false
    }

    fun stripMetadata(j: ByteArray): ByteArray {
        if (j.size < 4 || j[0] != 0xFF.toByte() || j[1] != 0xD8.toByte()) throw AegisException.Media("jpeg")
        val out = java.io.ByteArrayOutputStream(j.size)
        out.write(0xFF); out.write(0xD8)
        var i = 2
        var sawScan = false
        while (i < j.size) {
            if (j[i] != 0xFF.toByte()) throw AegisException.Media("jpeg")
            while (i < j.size && j[i] == 0xFF.toByte()) i++
            if (i >= j.size) throw AegisException.Media("jpeg")
            val marker = j[i].toInt() and 0xFF
            i++
            if (marker == 0xD9) {
                if (!sawScan) throw AegisException.Media("jpeg")
                out.write(0xFF); out.write(0xD9)
                return out.toByteArray()
            }
            if (marker == 0x00 || marker == 0x01 || marker in 0xD0..0xD7) continue
            if (i + 2 > j.size) throw AegisException.Media("jpeg")
            val len = ((j[i].toInt() and 0xFF) shl 8) or (j[i + 1].toInt() and 0xFF)
            if (len < 2 || i + len > j.size) throw AegisException.Media("jpeg")
            if (keep(marker)) {
                out.write(0xFF); out.write(marker)
                out.write(j, i, len)
            }
            i += len
            if (marker == 0xDA) {
                sawScan = true
                // Entropy-coded data: copy until a marker that is neither a stuffed zero nor a restart.
                val start = i
                while (i < j.size) {
                    if (j[i] == 0xFF.toByte() && i + 1 < j.size) {
                        val n = j[i + 1].toInt() and 0xFF
                        if (n != 0x00 && n !in 0xD0..0xD7 && n != 0xFF) break
                        if (n == 0xFF) { i++; continue }
                    }
                    i++
                }
                out.write(j, start, i - start)
            }
        }
        throw AegisException.Media("jpeg")
    }

    /** True if any APPn or COM segment is present before the end of the file. */
    fun hasMetadata(j: ByteArray): Boolean {
        var i = 2
        while (i + 4 <= j.size) {
            if (j[i] != 0xFF.toByte()) return true
            val m = j[i + 1].toInt() and 0xFF
            if (m == 0xFF) { i++; continue }
            if (m == 0xD9) return false
            if (m in 0xE0..0xEF || m == 0xFE) return true
            val len = ((j[i + 2].toInt() and 0xFF) shl 8) or (j[i + 3].toInt() and 0xFF)
            i += 2 + len
            if (m == 0xDA) {
                while (i + 1 < j.size && !(j[i] == 0xFF.toByte() && j[i + 1] != 0.toByte() && (j[i + 1].toInt() and 0xFF) !in 0xD0..0xD7)) i++
            }
        }
        return false
    }
}
