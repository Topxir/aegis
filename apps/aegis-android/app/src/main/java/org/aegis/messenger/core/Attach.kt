package org.aegis.messenger.core

enum class MediaKind(val wire: String) {
    Image("image"), Video("video");

    fun hasMagic(m: ByteArray): Boolean = when (this) {
        Image -> m.size >= 3 && m[0] == 0xFF.toByte() && m[1] == 0xD8.toByte() && m[2] == 0xFF.toByte()
        Video -> m.size >= 8 && m[4] == 'f'.code.toByte() && m[5] == 't'.code.toByte() &&
            m[6] == 'y'.code.toByte() && m[7] == 'p'.code.toByte()
    }

    companion object {
        fun parse(s: String): MediaKind = values().firstOrNull { it.wire == s } ?: throw AegisException.Media("kind")
    }
}

/** Everything about an attachment except its bytes: the body of a dmf, gmf or cmf envelope. */
class AttachmentDescriptor(
    val kind: MediaKind,
    val size: Long,
    val sha256: ByteArray,
    val key: ByteArray,
    val width: Long,
    val height: Long,
    val durationMs: Long,
    val ids: List<ByteArray>,
    val caption: String,
) {
    override fun toString(): String = "AttachmentDescriptor($kind, ${ids.size} chunks)"

    private fun validate() {
        val n = Attach.chunkCount(size) ?: throw AegisException.Media("size")
        if (size == 0L || ids.size != n || n > Attach.MAX_CHUNKS || n == 0) throw AegisException.Media("chunk count")
        if (caption.codePointCount(0, caption.length) > Attach.MAX_CAPTION ||
            caption.codePoints().anyMatch { Character.isISOControl(it) || Text.isSpoofing(it) }
        ) throw AegisException.Media("caption")
        if (width > Attach.MAX_DIMENSION || height > Attach.MAX_DIMENSION || durationMs > Attach.MAX_DURATION_MS) {
            throw AegisException.Media("dimensions")
        }
        if (kind == MediaKind.Image && durationMs != 0L) throw AegisException.Media("duration")
    }

    /** The 10-line envelope body (before percent-encoding). */
    fun encode(): String {
        validate()
        return listOf(
            "AT1", kind.wire, size.toString(), Hex.encode(sha256), Hex.encode(key),
            width.toString(), height.toString(), durationMs.toString(),
            ids.joinToString(",") { Hex.encode(it) }, caption,
        ).joinToString("\n")
    }

    companion object {
        private fun dec(s: String): Long {
            val v = try {
                Text.parseU64(s)
            } catch (_: AegisException) {
                throw AegisException.Media("number")
            }
            if (v > Long.MAX_VALUE.toULong()) throw AegisException.Media("number")
            return v.toLong()
        }

        /** Strict parser: exactly 10 lines, header AT1, lowercase hex, canonical decimals. */
        fun parse(body: String): AttachmentDescriptor {
            val l = body.split('\n')
            if (l.size != 10) throw AegisException.Media("line count")
            if (l[0] != "AT1") throw AegisException.Media("header")
            if (!Hex.isHexLen(l[3], 32) || !Hex.isHexLen(l[4], 32)) throw AegisException.Media("hex")
            val ids = ArrayList<ByteArray>()
            for (id in l[8].split(',')) {
                if (ids.size >= Attach.MAX_CHUNKS || !Hex.isHexLen(id, 32)) throw AegisException.Media("ids")
                ids.add(Hex.decode(id))
            }
            val d = AttachmentDescriptor(
                MediaKind.parse(l[1]), dec(l[2]), Hex.decode(l[3]), Hex.decode(l[4]),
                dec(l[5]), dec(l[6]), dec(l[7]), ids, l[9],
            )
            d.validate()
            return d
        }
    }
}

class AttachmentMeta(
    val kind: MediaKind,
    val width: Long,
    val height: Long,
    val durationMs: Long,
    val caption: String,
)

class SealedAttachment(val descriptor: AttachmentDescriptor, val chunks: List<ByteArray>)

/** Attachments: chunked encryption of sanitized media (spec section 13). */
object Attach {
    const val CHUNK = 1 shl 20
    const val MAX_CHUNKS = 32
    const val MAX_CAPTION = 1024
    const val MAX_DIMENSION = 16_384L
    const val MAX_DURATION_MS = 86_400_000L
    const val MAX_SIZE = 31 * CHUNK
    private const val MIN_PADDED = 1 shl 16
    private const val TAG = 16

    /** Padded length of BE64(size) || m: next power of two, at least 65536. Null when too large. */
    fun paddedLen(size: Long): Int? {
        if (size < 0 || size > MAX_SIZE) return null
        val need = size.toInt() + 8
        var p = MIN_PADDED
        while (p < need) p = p shl 1
        return p
    }

    fun chunkCount(size: Long): Int? = paddedLen(size)?.let { (it + CHUNK - 1) / CHUNK }

    private fun nonce(i: Int): ByteArray = ByteArray(12).also { Bytes.putBe32(it, 8, i.toLong()) }

    private fun aad(i: Int, n: Int): ByteArray {
        val a = ByteArray(4)
        val b = ByteArray(4)
        Bytes.putBe32(a, 0, i.toLong())
        Bytes.putBe32(b, 0, n.toLong())
        return Bytes.concat(Text.utf8("aegis-v2 blob"), a, b)
    }

    fun sealWith(meta: AttachmentMeta, m: ByteArray, key: ByteArray, ids: List<ByteArray>): SealedAttachment {
        val n = chunkCount(m.size.toLong()) ?: throw AegisException.Media("too large")
        if (ids.size != n || m.isEmpty() || !meta.kind.hasMagic(m)) throw AegisException.Media("attachment")
        val total = paddedLen(m.size.toLong())!!
        val padded = ByteArray(total)
        for (i in 0 until 8) padded[i] = (m.size.toLong() ushr (56 - 8 * i)).toByte()
        System.arraycopy(m, 0, padded, 8, m.size)
        val chunks = ArrayList<ByteArray>(n)
        for (i in 0 until n) {
            val part = padded.copyOfRange(i * CHUNK, minOf(total, (i + 1) * CHUNK))
            chunks.add(Crypto.aeadSeal(key, nonce(i), aad(i, n), part))
        }
        padded.fill(0)
        val d = AttachmentDescriptor(
            meta.kind, m.size.toLong(), Crypto.sha256(m), key.copyOf(), meta.width, meta.height,
            meta.durationMs, ids.toList(), meta.caption,
        )
        d.encode()
        return SealedAttachment(d, chunks)
    }

    /** Fresh random key and unrelated random chunk ids. */
    fun seal(meta: AttachmentMeta, m: ByteArray): SealedAttachment {
        val n = chunkCount(m.size.toLong()) ?: throw AegisException.Media("too large")
        return sealWith(meta, m, Crypto.randomBytes(32), List(n) { Crypto.randomBytes(32) })
    }

    /** Decrypts downloaded chunks in order, then verifies length, SHA-256 and magic bytes. */
    fun open(desc: AttachmentDescriptor, chunks: List<ByteArray>): ByteArray {
        desc.encode()
        val n = desc.ids.size
        val total = paddedLen(desc.size) ?: throw AegisException.Media("too large")
        if (chunks.size != n) throw AegisException.Media("chunk count")
        val padded = ByteArray(total)
        var off = 0
        for ((i, ct) in chunks.withIndex()) {
            val want = minOf(CHUNK, maxOf(0, total - i * CHUNK)) + TAG
            if (ct.size != want) throw AegisException.Media("chunk length")
            val pt = Crypto.aeadOpen(desc.key, nonce(i), aad(i, n), ct)
            System.arraycopy(pt, 0, padded, off, pt.size)
            off += pt.size
            pt.fill(0)
        }
        if (off != total) throw AegisException.Media("padded length")
        var len = 0L
        for (i in 0 until 8) len = (len shl 8) or (padded[i].toLong() and 0xFF)
        if (len != desc.size || len < 0 || len > total - 8) throw AegisException.Media("length")
        val m = padded.copyOfRange(8, 8 + len.toInt())
        padded.fill(0)
        if (!Bytes.eq(Crypto.sha256(m), desc.sha256)) throw AegisException.Media("sha256")
        if (!desc.kind.hasMagic(m)) throw AegisException.Media("magic bytes")
        return m
    }
}
