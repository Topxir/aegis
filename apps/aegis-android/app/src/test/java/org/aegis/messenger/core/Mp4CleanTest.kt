package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Synthetic MP4 builder, same layout as the Rust fixture that produced the vector. */
object Mp4Fixture {
    const val TIME_MARK: Byte = 0x5a
    val GPS_SAMPLE = "GPS+55.7558+037.6173".toByteArray()
    val GPS_UDTA = "+55.7558+037.6173/".toByteArray()
    val MDAT_SECRET = "UNREFERENCED-MDAT!".toByteArray()
    const val HDLR_NAME = "SecretHandlerName"
    val COMPRESSOR = "SecretCompressor".toByteArray()
    val VENDOR = "VNDR".toByteArray()
    val ENTRY_JUNK = "entry-junk".toByteArray()
    val STBL_JUNK = "stbl-junk".toByteArray()
    val DREF_URL = "http://secret.test/x".toByteArray()
    val EDTS_JUNK = "edts-junk".toByteArray()

    class Built(val bytes: ByteArray, val video: List<IntArray>, val audio: IntArray, val meta: IntArray, val mdatPos: Int)

    private fun cat(vararg p: ByteArray) = Bytes.concat(*p)
    private fun be(v: Long): ByteArray = ByteArray(4).also { Bytes.putBe32(it, 0, v) }
    private fun u32s(vararg v: Long) = cat(*v.map { be(it) }.toTypedArray())
    private fun z(n: Int) = ByteArray(n)
    private fun bx(typ: ByteArray, payload: ByteArray) = cat(be(payload.size + 8L), typ, payload)
    private fun bx(typ: String, payload: ByteArray) = bx(typ.toByteArray(Charsets.ISO_8859_1), payload)
    private fun fullbox(typ: String, ver: Int, payload: ByteArray) =
        bx(typ, cat(byteArrayOf(ver.toByte(), 0, 0, 0), payload))

    private fun mark(n: Int) = ByteArray(n) { TIME_MARK }

    private fun tkhd(ver: Int, id: Long, w: Long, h: Long): ByteArray {
        val p = if (ver == 0) cat(mark(8), u32s(id, 0, 1000))
        else cat(mark(16), u32s(id, 0), byteArrayOf(0, 0, 0, 0, 0, 0, 3, 0xe8.toByte()))
        return fullbox("tkhd", ver, cat(p, z(8 + 8 + 36), u32s(w shl 16, h shl 16)))
    }

    private fun mdhd(ver: Int, timescale: Long, dur: Long): ByteArray {
        val p = if (ver == 0) cat(mark(8), u32s(timescale, dur), z(4))
        else cat(mark(16), u32s(timescale), u32s(0, dur), z(4))
        return fullbox("mdhd", ver, p)
    }

    private fun hdlr(kind: String, name: String) =
        fullbox("hdlr", 0, cat(z(4), kind.toByteArray(), z(12), name.toByteArray(), z(1)))

    private fun sampleEntry(kind: String): ByteArray {
        val junk = bx("junk", ENTRY_JUNK)
        return if (kind == "vide") {
            val comp = COMPRESSOR.copyOf(32)
            val p = cat(z(8), z(16), byteArrayOf(1, 0x40, 0, 0xf0.toByte()), z(14), comp, z(4))
            check(p.size == 78)
            bx("avc1", cat(p, bx("avcC", byteArrayOf(1, 2, 3, 4)), junk))
        } else {
            val p = cat(z(8), z(4), VENDOR, byteArrayOf(0, 2, 0, 16, 0, 0, 0, 0, 0xbb.toByte(), 0x80.toByte(), 0, 0))
            check(p.size == 28)
            bx("mp4a", cat(p, bx("esds", byteArrayOf(5, 6, 7, 8)), junk))
        }
    }

    private fun stbl(kind: String, sizes: List<Long>, off: Long): ByteArray {
        val n = sizes.size.toLong()
        val stsd = if (kind == "vide" || kind == "soun") fullbox("stsd", 0, cat(u32s(1), sampleEntry(kind)))
        else fullbox("stsd", 0, u32s(0))
        val stsc = fullbox("stsc", 0, u32s(1, 1, n, 1))
        val stsz = fullbox("stsz", 0, cat(u32s(0, n), u32s(*sizes.toLongArray())))
        val stco = fullbox("stco", 0, u32s(1, off))
        val junk = bx("sgpd", STBL_JUNK)
        return bx("stbl", cat(stsd, junk, stsc, stsz, stco))
    }

    private fun trak(kind: String, tkVer: Int, mdVer: Int, id: Long, sizes: List<Long>, off: Long, extra: ByteArray): ByteArray {
        val mediaHdr = when (kind) {
            "vide" -> fullbox("vmhd", 0, z(8))
            "soun" -> fullbox("smhd", 0, z(4))
            else -> fullbox("nmhd", 0, z(0))
        }
        val url = fullbox("url ", 0, cat(DREF_URL, z(1)))
        val dinf = bx("dinf", fullbox("dref", 0, cat(u32s(1), url)))
        val minf = bx("minf", cat(mediaHdr, dinf, stbl(kind, sizes, off)))
        val mdia = bx("mdia", cat(mdhd(mdVer, 90000, 225_000), hdlr(kind, HDLR_NAME), minf))
        val (w, h) = if (kind == "vide") 320L to 240L else 0L to 0L
        val edts = bx("edts", cat(fullbox("elst", 0, u32s(0)), bx("junk", EDTS_JUNK)))
        return bx("trak", cat(tkhd(tkVer, id, w, h), edts, mdia, extra))
    }

    fun build(): Built {
        val videoSamples = cat(ByteArray(24) { 0x11 }, ByteArray(16) { 0x12 })
        val audioSamples = ByteArray(32) { 0x33 }
        val metaSamples = cat(GPS_SAMPLE, GPS_SAMPLE)
        val xyz = bx(byteArrayOf(0xa9.toByte(), 'x'.code.toByte(), 'y'.code.toByte(), 'z'.code.toByte()),
            cat(byteArrayOf(0, 0x12, 0x15, 0xc7.toByte()), GPS_UDTA))
        val udta = bx("udta", xyz)
        val tref = bx("tref", bx("cdsc", byteArrayOf(0, 0, 0, 1)))

        fun moov(ov: Long, om: Long, oa: Long): ByteArray {
            val mvhd = fullbox("mvhd", 0, cat(mark(8), u32s(1000, 2500, 0x0001_0000), z(4 + 10 + 36 + 24 + 4)))
            val v = trak("vide", 0, 0, 1, listOf(24L, 16L), ov, cat(udta, tref))
            val a = trak("soun", 1, 1, 2, listOf(32L), oa, z(0))
            val m = trak("mebx", 0, 0, 3, listOf(20L, 20L), om, z(0))
            return bx("moov", cat(mvhd, v, a, m, udta))
        }

        val ftyp = bx("ftyp", cat("isom".toByteArray(), byteArrayOf(0, 0, 2, 0), "isommp41XSEC".toByteArray()))
        val junkPayload = "free-secret-bytes".toByteArray()
        val junkSize = 16L + junkPayload.size
        val junk = cat(be(1), "free".toByteArray(), be(0), be(junkSize), junkPayload)
        val metaBox = fullbox("meta", 0, bx("keys", GPS_UDTA))
        val head = moov(0, 0, 0).size + ftyp.size + junk.size + metaBox.size
        val base = head + 8L
        val ov = base
        val om = base + videoSamples.size
        val oa = base + videoSamples.size + metaSamples.size
        val mdat = bx("mdat", cat(videoSamples, metaSamples, audioSamples, MDAT_SECRET))
        val bytes = cat(ftyp, moov(ov, om, oa), junk, metaBox, mdat)
        val vs = base.toInt()
        val ms = vs + videoSamples.size
        return Built(
            bytes, listOf(intArrayOf(vs, vs + 24), intArrayOf(vs + 24, vs + 40)),
            intArrayOf(oa.toInt(), oa.toInt() + 32), intArrayOf(ms, ms + metaSamples.size), head,
        )
    }
}

class Mp4CleanTest {
    private fun find(hay: ByteArray, needle: ByteArray): Boolean {
        outer@ for (i in 0..hay.size - needle.size) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray, from: Int = 0): Int {
        outer@ for (i in from..hay.size - needle.size) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    private fun rejects(b: ByteArray) {
        try {
            Mp4Clean.sanitize(b)
            fail("accepted")
        } catch (_: AegisException) {
        }
    }

    @Test
    fun stripsMetadataKeepsMedia() {
        val f = Mp4Fixture.build()
        assertTrue(find(f.bytes, Mp4Fixture.GPS_SAMPLE) && find(f.bytes, Mp4Fixture.GPS_UDTA))
        assertTrue(find(f.bytes, "free-secret-bytes".toByteArray()))
        val v = Mp4Clean.sanitize(f.bytes)
        assertEquals(f.bytes.size, v.bytes.size)
        assertFalse(find(v.bytes, Mp4Fixture.GPS_SAMPLE))
        assertFalse(find(v.bytes, "GPS+".toByteArray()))
        assertFalse(find(v.bytes, Mp4Fixture.GPS_UDTA))
        assertFalse(find(v.bytes, "+55.7558".toByteArray()))
        assertFalse(find(v.bytes, ByteArray(4) { Mp4Fixture.TIME_MARK }))
        assertFalse(find(v.bytes, "free-secret-bytes".toByteArray()))
        for (r in f.video + listOf(f.audio)) {
            assertArrayEquals(f.bytes.copyOfRange(r[0], r[1]), v.bytes.copyOfRange(r[0], r[1]))
        }
        assertTrue(v.bytes.copyOfRange(f.meta[0], f.meta[1]).all { it.toInt() == 0 })
        assertEquals(320L, v.width)
        assertEquals(240L, v.height)
        assertEquals(2500L, v.durationMs)
        assertArrayEquals(v.bytes, Mp4Clean.sanitize(v.bytes).bytes)
        assertTrue(find(v.bytes, "free".toByteArray()))
        for (dropped in listOf("udta", "tref", "meta")) assertFalse(find(v.bytes, dropped.toByteArray()))
        assertFalse(find(v.bytes, byteArrayOf(0xa9.toByte(), 'x'.code.toByte(), 'y'.code.toByte(), 'z'.code.toByte())))
    }

    @Test
    fun mdatToEndVariant() {
        val f = Mp4Fixture.build()
        val b = f.bytes.copyOf()
        for (i in 0 until 4) b[f.mdatPos + i] = 0
        val v = Mp4Clean.sanitize(b)
        assertEquals(b.size, v.bytes.size)
        assertArrayEquals(b.copyOfRange(f.audio[0], f.audio[1]), v.bytes.copyOfRange(f.audio[0], f.audio[1]))
        assertTrue(v.bytes.copyOfRange(f.meta[0], f.meta[1]).all { it.toInt() == 0 })
    }

    @Test
    fun rejectsStructuralProblems() {
        val f = Mp4Fixture.build()
        val b = f.bytes
        rejects(b + byteArrayOf(0, 0, 0, 8) + "moof".toByteArray())
        val noFtyp = b.copyOf()
        "skip".toByteArray().copyInto(noFtyp, 4)
        rejects(noFtyp)
        val noMoov = b.copyOf()
        "moox".toByteArray().copyInto(noMoov, indexOf(b, "moov".toByteArray()))
        rejects(noMoov)
        val noVide = b.copyOf()
        "subt".toByteArray().copyInto(noVide, indexOf(b, "vide".toByteArray()))
        rejects(noVide)
        val far = b.copyOf()
        val om = ByteArray(4).also { Bytes.putBe32(it, 0, f.meta[0].toLong()) }
        val p = indexOf(b, om, indexOf(b, "mebx".toByteArray()))
        Bytes.putBe32(far, p, 0x7fff_ffffL)
        rejects(far)
        val size = b.copyOf()
        Bytes.putBe32(size, 0, 0x7fff_ffffL)
        rejects(size)
        val small = b.copyOf()
        Bytes.putBe32(small, 0, 4)
        rejects(small)
        rejects(ByteArray(Mp4Clean.MAX_VIDEO + 1))
        rejects(ByteArray(0))
        rejects(ByteArray(100) { 0xff.toByte() })
    }

    @Test
    fun rejectsStz2AndDuplicates() {
        val f = Mp4Fixture.build()
        val b = f.bytes.copyOf()
        // Turn the stsz of the dropped metadata track (the last one) into stz2.
        var p = indexOf(b, "stsz".toByteArray())
        while (true) {
            val n = indexOf(b, "stsz".toByteArray(), p + 4)
            if (n < 0) break
            p = n
        }
        "stz2".toByteArray().copyInto(b, p)
        rejects(b)
        // A second mvhd.
        val d = f.bytes.copyOf()
        val first = indexOf(d, "trak".toByteArray())
        val q = indexOf(d, "trak".toByteArray(), first + 4)
        assertTrue(q > first)
        "mvhd".toByteArray().copyInto(d, q)
        rejects(d)
    }

    @Test
    fun zerosFreeSkipWide() {
        val f = Mp4Fixture.build()
        for (name in listOf("skip", "wide")) {
            val pay = "secret-in-$name".toByteArray()
            val extra = Bytes.concat(ByteArray(4).also { Bytes.putBe32(it, 0, 8L + pay.size) }, name.toByteArray(), pay)
            // Appending a box after mdat is a valid top-level layout.
            val out = Mp4Clean.sanitize(Bytes.concat(f.bytes, extra))
            assertFalse(find(out.bytes, pay))
            assertEquals(f.bytes.size + extra.size, out.bytes.size)
            assertFalse(find(out.bytes, name.toByteArray()))
        }
    }

    @Test
    fun everyTruncationRejected() {
        val f = Mp4Fixture.build()
        for (n in 0 until f.bytes.size) rejects(f.bytes.copyOf(n))
    }

    @Test
    fun mutationFuzzOnlyTypedErrors() {
        val f = Mp4Fixture.build()
        var x = 0x1234_5678_9abc_def1L
        fun next(): Long {
            x = x xor (x shl 13)
            x = x xor (x ushr 7)
            x = x xor (x shl 17)
            return x
        }
        fun r(n: Int): Int = java.lang.Long.remainderUnsigned(next(), n.toLong()).toInt()
        repeat(30_000) {
            var b = f.bytes.copyOf()
            repeat(r(4) + 1) {
                val i = r(b.size)
                b[i] = when (r(3)) { 0 -> 0; 1 -> 0xff.toByte(); else -> (next() and 0xff).toByte() }
            }
            if (r(8) == 0) b = b.copyOf(r(b.size))
            try {
                assertEquals(b.size, Mp4Clean.sanitize(b).bytes.size)
            } catch (_: AegisException) {
            }
        }
    }
}
