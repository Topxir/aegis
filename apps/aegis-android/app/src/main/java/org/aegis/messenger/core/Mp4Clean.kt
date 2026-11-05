package org.aegis.messenger.core

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/** Sanitized video and the values shown to the user. */
class SanitizedVideo(val bytes: ByteArray, val width: Long, val height: Long, val durationMs: Long)

/**
 * MP4/MOV sanitizer (spec section 16). The output has exactly the length of the input, so
 * stco/co64 offsets stay valid: whatever is not on the allowlist becomes one zeroed free box
 * at the end of its container, and mdat bytes that no kept sample refers to are zeroed.
 */
object Mp4Clean {
    const val MAX_VIDEO = 31 * 1024 * 1024
    private const val MAX_BOXES = 10_000

    private fun bad(why: String) = AegisException.Media(why)

    private class Box(val start: Int, val hdr: Int, val end: Int, val typ: String) {
        val payload: Int get() = start + hdr
        val payloadLen: Int get() = end - start - hdr
    }

    private class Plan {
        val zero = ArrayList<IntArray>()
        val set = ArrayList<Pair<Int, ByteArray>>()
        fun zeroLen(start: Int, len: Int) {
            zero.add(intArrayOf(start, start + len))
        }
    }

    private fun lat1(s: String) = s.toByteArray(Charsets.ISO_8859_1)

    private fun be32(b: ByteArray, o: Long): Long {
        if (o < 0 || o + 4 > b.size) throw bad("truncated")
        val i = o.toInt()
        return ((b[i].toLong() and 0xFF) shl 24) or ((b[i + 1].toLong() and 0xFF) shl 16) or
            ((b[i + 2].toLong() and 0xFF) shl 8) or (b[i + 3].toLong() and 0xFF)
    }

    /** 64-bit read where the top bit is kept (an unsigned duration). */
    private fun be64Raw(b: ByteArray, o: Long): Long {
        if (o < 0 || o + 8 > b.size) throw bad("truncated")
        var v = 0L
        for (k in 0 until 8) v = (v shl 8) or (b[o.toInt() + k].toLong() and 0xFF)
        return v
    }

    /** 64-bit read for sizes and offsets; values at or above 2^63 cannot be file positions. */
    private fun be64(b: ByteArray, o: Long): Long {
        val v = be64Raw(b, o)
        if (v < 0) throw bad("offset")
        return v
    }

    private fun type4(b: ByteArray, o: Int): String {
        if (o < 0 || o + 4 > b.size) throw bad("truncated")
        return String(b, o, 4, Charsets.ISO_8859_1)
    }

    private fun parseBoxes(buf: ByteArray, start: Int, end: Int): List<Box> {
        val out = ArrayList<Box>()
        var pos = start
        while (pos < end) {
            val left = end - pos
            if (left < 8) throw bad("trailing bytes")
            val size32 = be32(buf, pos.toLong())
            val typ = type4(buf, pos + 4)
            val hdr: Int
            val size: Long
            when (size32) {
                0L -> { hdr = 8; size = left.toLong() }
                1L -> {
                    if (left < 16) throw bad("box header")
                    hdr = 16
                    size = be64(buf, pos + 8L)
                }
                else -> { hdr = 8; size = size32 }
            }
            if (size < hdr || size > left) throw bad("box size")
            out.add(Box(pos, hdr, pos + size.toInt(), typ))
            if (out.size > MAX_BOXES) throw bad("too many boxes")
            pos += size.toInt()
        }
        return out
    }

    private fun children(buf: ByteArray, b: Box) = parseBoxes(buf, b.payload, b.end)

    private fun one(list: List<Box>, typ: String): Box? {
        val m = list.filter { it.typ == typ }
        if (m.size > 1) throw bad("duplicate box")
        return m.firstOrNull()
    }

    /** Returns (timescale, duration) and schedules the creation and modification times for zeroing. */
    private fun zeroTimesAndDuration(buf: ByteArray, b: Box, plan: Plan): LongArray {
        val p = b.payload
        if (p >= buf.size) throw bad("truncated")
        return when (buf[p].toInt()) {
            0 -> {
                if (b.payloadLen < 20) throw bad("header version")
                plan.zeroLen(p + 4, 8)
                longArrayOf(be32(buf, p + 12L), be32(buf, p + 16L))
            }
            1 -> {
                if (b.payloadLen < 32) throw bad("header version")
                plan.zeroLen(p + 4, 16)
                longArrayOf(be32(buf, p + 20L), be64Raw(buf, p + 24L))
            }
            else -> throw bad("header version")
        }
    }

    private fun tkhd(buf: ByteArray, b: Box, plan: Plan): LongArray {
        val p = b.payload
        if (p >= buf.size) throw bad("truncated")
        val (zero, wo) = when {
            buf[p].toInt() == 0 && b.payloadLen >= 84 -> 8 to 76
            buf[p].toInt() == 1 && b.payloadLen >= 96 -> 16 to 88
            else -> throw bad("tkhd")
        }
        plan.zeroLen(p + 4, zero)
        return longArrayOf(be32(buf, (p + wo).toLong()), be32(buf, (p + wo + 4).toLong()))
    }

    private fun handler(buf: ByteArray, mdia: List<Box>): String? {
        val h = one(mdia, "hdlr") ?: return null
        if (h.payloadLen < 12) throw bad("hdlr")
        return type4(buf, h.payload + 8)
    }

    private fun sampleRanges(buf: ByteArray, stbl: Box, budget: LongArray, out: MutableList<IntArray>) {
        val kids = children(buf, stbl)
        if (kids.any { it.typ == "stz2" }) throw bad("stz2")
        val stsc = one(kids, "stsc") ?: throw bad("stsc missing")
        val stsz = one(kids, "stsz") ?: throw bad("stsz missing")
        val stco = one(kids, "stco")
        val co64 = one(kids, "co64")
        val co: Box
        val wide: Boolean
        if (stco != null && co64 == null) {
            co = stco; wide = false
        } else if (stco == null && co64 != null) {
            co = co64; wide = true
        } else {
            throw bad("chunk offsets")
        }

        val zp = stsz.payload
        if (stsz.payloadLen < 12) throw bad("stsz")
        val constSize = be32(buf, zp + 4L)
        val count = be32(buf, zp + 8L)
        if (constSize == 0L && (stsz.payloadLen - 12L) / 4 < count) throw bad("stsz table")
        if (count == 0L) return

        val sp = stsc.payload
        if (stsc.payloadLen < 8) throw bad("stsc")
        val entries = be32(buf, sp + 4L)
        if (entries == 0L || (stsc.payloadLen - 8L) / 12 < entries) throw bad("stsc table")
        val ne = entries.toInt()
        fun first(i: Int) = be32(buf, sp + 8L + i * 12L)
        fun spcOf(i: Int) = be32(buf, sp + 12L + i * 12L)
        var prev = 0L
        for (i in 0 until ne) {
            val f = first(i)
            if (f <= prev || spcOf(i) == 0L || (i == 0 && f != 1L)) throw bad("stsc entries")
            prev = f
        }

        val cp = co.payload
        if (co.payloadLen < 8) throw bad("chunk offsets")
        val chunks = be32(buf, cp + 4L)
        val esz = if (wide) 8 else 4
        if ((co.payloadLen - 8L) / esz < chunks) throw bad("chunk offset table")

        var consumed = 0L
        var idx = 0
        for (j in 0 until chunks.toInt()) {
            val chunkNo = j + 1L
            while (idx + 1 < ne && first(idx + 1) <= chunkNo) idx++
            val spc = spcOf(idx)
            if (spc > count - consumed) throw bad("samples exceed stsz")
            var bytes: Long
            if (constSize != 0L) {
                bytes = spc * constSize
            } else {
                bytes = 0L
                for (k in 0 until spc) {
                    bytes += be32(buf, (consumed + k) * 4 + zp + 12)
                }
            }
            consumed += spc
            val off = if (wide) be64(buf, cp + 8L + j * 8L) else be32(buf, cp + 8L + j * 4L)
            val end = off + bytes
            if (bytes < 0 || end < 0 || end > buf.size) throw bad("samples outside file")
            if (bytes > budget[0]) throw bad("overlapping samples")
            budget[0] -= bytes
            if (bytes > 0) out.add(intArrayOf(off.toInt(), (off + bytes).toInt()))
        }
        if (consumed != count) throw bad("samples do not match stsz")
    }

    private val BRANDS = setOf("isom", "iso2", "iso4", "iso5", "iso6", "mp41", "mp42", "avc1", "qt  ", "M4V ", "M4A ", "hvc1")

    /** Brands that are not on the list become the major brand. */
    private fun ftypPlan(buf: ByteArray, b: Box, plan: Plan) {
        val p = b.payload
        val len = b.payloadLen
        val major = type4(buf, p).let { if (it in BRANDS) it else "isom" }
        val new = ByteArrayOutputStream(len)
        new.write(lat1(major))
        new.write(ByteArray(4))
        var o = p + 8
        while (o + 4 <= b.end) {
            val t = type4(buf, o)
            new.write(lat1(if (t in BRANDS) t else major))
            o += 4
        }
        plan.set.add(p to new.toByteArray().copyOf(len))
    }

    private fun trakHandler(buf: ByteArray, trak: Box): String? {
        val kids = children(buf, trak)
        val m = one(kids, "mdia") ?: return null
        return handler(buf, children(buf, m))
    }

    private const val VISUAL_FIXED = 78
    private const val VIS_COMP_FROM = 42
    private const val VIS_COMP_TO = 74
    private const val AUD_VENDOR_FROM = 12
    private const val AUD_VENDOR_TO = 16

    /** Offset of the first child box of a sample entry. */
    private fun entryChildrenAt(buf: ByteArray, e: Box, hd: String): Int {
        val p = e.payload
        val rel = if (hd == "vide") {
            VISUAL_FIXED
        } else {
            if (p + 10 > buf.size) throw bad("sample entry")
            when (((buf[p + 8].toInt() and 0xFF) shl 8) or (buf[p + 9].toInt() and 0xFF)) {
                0 -> 28
                1 -> 44
                2 -> 64
                else -> throw bad("sample entry")
            }
        }
        if (e.payloadLen < rel) throw bad("sample entry")
        return p + rel
    }

    /** Schedules the free-text fields of a kept track for zeroing and checks its dref and stsd. */
    private fun scrubTrackText(buf: ByteArray, mdiaKids: List<Box>, minf: List<Box>, hd: String, plan: Plan) {
        one(mdiaKids, "hdlr")?.let { h ->
            plan.zeroLen(h.payload + 12, maxOf(0, h.payloadLen - 12))
        }
        one(minf, "dinf")?.let { dinf ->
            val kids = children(buf, dinf)
            one(kids, "dref")?.let { dref ->
                if (dref.payloadLen < 8) throw bad("dref")
                val n = be32(buf, dref.payload + 4L)
                val ents = parseBoxes(buf, dref.payload + 8, dref.end)
                if (ents.size.toLong() != n) throw bad("dref")
                for (e in ents) {
                    if (e.typ != "url " && e.typ != "urn ") throw bad("dref")
                    val v = ByteArray(e.payloadLen)
                    if (v.size > 3) v[3] = 1
                    plan.set.add((e.start + 4) to lat1("url "))
                    plan.set.add(e.payload to v)
                }
            }
        }
        val stbl = one(minf, "stbl") ?: return
        val kids = children(buf, stbl)
        val stsd = one(kids, "stsd") ?: return
        if (stsd.payloadLen < 8) throw bad("stsd")
        val n = be32(buf, stsd.payload + 4L)
        val ents = parseBoxes(buf, stsd.payload + 8, stsd.end)
        if (ents.size.toLong() != n) throw bad("stsd")
        for (e in ents) {
            entryChildrenAt(buf, e, hd)
            val p = e.payload
            if (hd == "vide") plan.zeroLen(p + VIS_COMP_FROM, VIS_COMP_TO - VIS_COMP_FROM)
            else plan.zeroLen(p + AUD_VENDOR_FROM, AUD_VENDOR_TO - AUD_VENDOR_FROM)
        }
    }

    /** Returns (width, height) in 16.16 for a video track, (-1, -1) for audio, null for a dropped track. */
    private fun processTrack(
        buf: ByteArray, trak: Box, plan: Plan, budget: LongArray,
        dropped: MutableList<IntArray>, kept: MutableList<IntArray>,
    ): LongArray? {
        val kids = children(buf, trak)
        val tk = one(kids, "tkhd")
        val mdia = one(kids, "mdia")
        val mdiaKids = if (mdia != null) children(buf, mdia) else emptyList()
        val hdlr = handler(buf, mdiaKids)
        val minfBox = one(mdiaKids, "minf")
        val minf = if (minfBox != null) children(buf, minfBox) else emptyList()
        val stbl = one(minf, "stbl")

        if (hdlr != "vide" && hdlr != "soun") {
            if (stbl != null) sampleRanges(buf, stbl, budget, dropped)
            return null
        }
        val dims = tkhd(buf, tk ?: throw bad("tkhd missing"), plan)
        val mdhd = one(mdiaKids, "mdhd") ?: throw bad("mdhd missing")
        zeroTimesAndDuration(buf, mdhd, plan)
        sampleRanges(buf, stbl ?: throw bad("stbl missing"), budget, kept)
        scrubTrackText(buf, mdiaKids, minf, hdlr, plan)
        return if (hdlr == "vide") dims else longArrayOf(-1, -1)
    }

    private enum class K { Moov, Trak, Edts, Mdia, Minf, Dinf, Stbl, Stsd, Entry, Leaf }

    private val ENTRY_KEEP = setOf(
        "avcC", "hvcC", "av1C", "vpcC", "vvcC", "esds", "colr", "pasp", "clap", "btrt", "dac3", "dec3", "dOps", "dfLa",
    )
    private val STBL_LEAVES = setOf("stts", "ctts", "stss", "stsc", "stsz", "stco", "co64", "cslg")

    /** What a child of a [kind] box becomes; null drops it. */
    private fun childKind(buf: ByteArray, kind: K, k: Box): K? {
        val t = k.typ
        return when (kind) {
            K.Moov -> when (t) {
                "mvhd" -> K.Leaf
                "trak" -> trakHandler(buf, k).let { if (it == "vide" || it == "soun") K.Trak else null }
                else -> null
            }
            K.Trak -> when (t) { "tkhd" -> K.Leaf; "edts" -> K.Edts; "mdia" -> K.Mdia; else -> null }
            K.Edts -> if (t == "elst") K.Leaf else null
            K.Mdia -> when (t) { "mdhd", "hdlr" -> K.Leaf; "minf" -> K.Minf; else -> null }
            K.Minf -> when (t) { "vmhd", "smhd" -> K.Leaf; "dinf" -> K.Dinf; "stbl" -> K.Stbl; else -> null }
            K.Dinf -> if (t == "dref") K.Leaf else null
            K.Stbl -> if (t == "stsd") K.Stsd else if (t in STBL_LEAVES) K.Leaf else null
            K.Stsd -> K.Entry
            K.Entry -> if (t in ENTRY_KEEP) K.Leaf else null
            K.Leaf -> null
        }
    }

    private fun pushFree(out: ByteArrayOutputStream, total: Int) {
        if (total >= 8) {
            val h = ByteArray(8)
            Bytes.putBe32(h, 0, total.toLong())
            System.arraycopy(lat1("free"), 0, h, 4, 4)
            out.write(h)
            out.write(ByteArray(total - 8))
        }
    }

    /** Same total length: allowed children in order, then one free box with the bytes of the dropped ones. */
    private fun emit(w: ByteArray, b: Box, kind: K, hd0: String?, out: ByteArrayOutputStream) {
        val hd = if (kind == K.Trak) trakHandler(w, b) else hd0
        val first = when (kind) {
            K.Stsd -> b.payload + 8
            K.Entry -> entryChildrenAt(w, b, hd ?: throw bad("hdlr"))
            else -> b.payload
        }
        val kids = parseBoxes(w, first, b.end)
        out.write(w, b.start, first - b.start)
        var freed = 0
        for (k in kids) {
            val ck = childKind(w, kind, k)
            when (ck) {
                K.Leaf -> out.write(w, k.start, k.end - k.start)
                null -> freed += k.end - k.start
                else -> emit(w, k, ck, hd, out)
            }
        }
        pushFree(out, freed)
    }

    fun sanitize(input: ByteArray): SanitizedVideo {
        if (input.size > MAX_VIDEO) throw bad("video too large")
        val top = parseBoxes(input, 0, input.size)
        val plan = Plan()
        var moov: Box? = null
        var ftyp = false
        for (b in top) {
            when (b.typ) {
                "ftyp" -> {
                    if (b.payloadLen < 8 || ftyp) throw bad("ftyp")
                    ftypPlan(input, b, plan)
                    ftyp = true
                }
                "moov" -> {
                    if (moov != null) throw bad("duplicate moov")
                    moov = b
                }
                "moof" -> throw bad("fragmented video")
            }
        }
        if (moov == null) throw bad("moov missing")
        if (!ftyp) throw bad("ftyp missing")

        val kids = children(input, moov)
        val mvhd = one(kids, "mvhd") ?: throw bad("mvhd missing")
        val td = zeroTimesAndDuration(input, mvhd, plan)
        val timescale = td[0]
        if (timescale == 0L) throw bad("timescale")

        val budget = longArrayOf(input.size.toLong())
        val dropped = ArrayList<IntArray>()
        val kept = ArrayList<IntArray>()
        var dims: LongArray? = null
        for (t in kids.filter { it.typ == "trak" }) {
            val d = processTrack(input, t, plan, budget, dropped, kept)
            if (dims == null && d != null && d[0] >= 0) dims = d
        }
        val dm = dims ?: throw bad("no video track")

        val w = input.copyOf()
        for ((pos, v) in plan.set) {
            if (pos < 0 || pos + v.size > w.size) throw bad("truncated")
            System.arraycopy(v, 0, w, pos, v.size)
        }
        for (r in plan.zero + dropped) if (r[0] >= 0 && r[0] <= r[1] && r[1] <= w.size) w.fill(0, r[0], r[1])
        // Inside mdat only the samples of kept tracks survive.
        kept.sortWith(compareBy({ it[0] }, { it[1] }))
        for (b in top.filter { it.typ == "mdat" }) {
            var cur = b.payload
            for (r in kept) {
                val s = r[0]
                val e = r[1]
                if (e <= cur || s >= b.end) continue
                w.fill(0, cur, maxOf(s, cur))
                cur = maxOf(cur, e)
            }
            w.fill(0, minOf(cur, b.end), b.end)
        }

        // Rebuild the top level at the same positions: kept boxes stay, runs of the rest become one free box.
        val out = ByteArrayOutputStream(w.size)
        var run = 0
        for (b in top) {
            if (b.typ != "ftyp" && b.typ != "moov" && b.typ != "mdat") {
                run += b.end - b.start
                continue
            }
            pushFree(out, run)
            run = 0
            if (b.typ == "moov") emit(w, b, K.Moov, null, out) else out.write(w, b.start, b.end - b.start)
        }
        pushFree(out, run)
        val res = out.toByteArray()
        if (res.size != input.size) throw bad("structure damaged")
        parseBoxes(res, 0, res.size)

        val ms = BigInteger(java.lang.Long.toUnsignedString(td[1])).multiply(BigInteger.valueOf(1000))
            .divide(BigInteger.valueOf(timescale))
        val msL = if (ms.bitLength() > 62) Long.MAX_VALUE else ms.toLong()
        return SanitizedVideo(res, dm[0] ushr 16, dm[1] ushr 16, msL)
    }
}
