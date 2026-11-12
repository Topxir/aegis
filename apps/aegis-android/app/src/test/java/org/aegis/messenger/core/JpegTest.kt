package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class JpegTest {
    private fun seg(marker: Int, payload: ByteArray): ByteArray {
        val len = payload.size + 2
        return byteArrayOf(0xFF.toByte(), marker.toByte(), (len shr 8).toByte(), len.toByte()) + payload
    }

    private val scan = byteArrayOf(0x12, 0xFF.toByte(), 0x00, 0x34, 0xFF.toByte(), 0xD0.toByte(), 0x56)

    private fun jpeg(vararg extra: ByteArray): ByteArray =
        byteArrayOf(0xFF.toByte(), 0xD8.toByte()) + extra.fold(ByteArray(0)) { a, b -> a + b } +
            seg(0xDB, ByteArray(65) { 1 }) + seg(0xC0, ByteArray(15) { 2 }) + seg(0xC4, ByteArray(20) { 3 }) +
            seg(0xDA, ByteArray(10) { 4 }) + scan + byteArrayOf(0xFF.toByte(), 0xD9.toByte())

    @Test
    fun dropsExifXmpIccAndComments() {
        val exif = seg(0xE1, "Exif\u0000\u0000GPS 59.9N 30.3E".toByteArray())
        val xmp = seg(0xE1, "http://ns.adobe.com/xap/1.0/\u0000<x:xmpmeta/>".toByteArray())
        val icc = seg(0xE2, "ICC_PROFILE\u0000....".toByteArray())
        val jfif = seg(0xE0, "JFIF\u0000thumbnail".toByteArray())
        val com = seg(0xFE, "made with phone".toByteArray())
        val src = jpeg(jfif, exif, xmp, icc, com)
        assertTrue(Jpeg.hasMetadata(src))
        val out = Jpeg.stripMetadata(src)
        assertFalse(Jpeg.hasMetadata(out))
        assertFalse(String(out, Charsets.ISO_8859_1).contains("Exif"))
        assertFalse(String(out, Charsets.ISO_8859_1).contains("GPS"))
        assertArrayEquals(jpeg(), out)
    }

    @Test
    fun rejectsNonJpegAndMissingScan() {
        try { Jpeg.stripMetadata(byteArrayOf(1, 2, 3, 4)); fail() } catch (_: AegisException) {}
        val noScan = byteArrayOf(0xFF.toByte(), 0xD8.toByte()) + seg(0xDB, ByteArray(65)) + byteArrayOf(0xFF.toByte(), 0xD9.toByte())
        try { Jpeg.stripMetadata(noScan); fail() } catch (_: AegisException) {}
        val trunc = jpeg().copyOf(30)
        try { Jpeg.stripMetadata(trunc); fail() } catch (_: AegisException) {}
    }
}
