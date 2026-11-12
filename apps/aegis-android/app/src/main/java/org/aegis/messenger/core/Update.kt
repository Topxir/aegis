package org.aegis.messenger.core

import org.bouncycastle.crypto.digests.SHA256Digest
import java.io.InputStream
import java.io.OutputStream

/**
 * Signed application updates (spec section 29), the same rules as `aegis_core::update`.
 * The signed file is the 64-byte signature followed by the manifest bytes; nothing is parsed
 * before the signature of [TRUSTED_KEY_HEX] checks out.
 */
object Update {
    /** The only key manifests are accepted from. The secret half stays offline with the owner. */
    const val TRUSTED_KEY_HEX = "d0477ef7f2cd4618395408fc518c8691ff528ea290514dd50822cebbc41d6761"
    const val SIG_CONTEXT = "aegis-update-v1\n"
    const val MAX_MANIFEST = 64 * 1024
    const val MAX_FILE = 512L * 1024 * 1024
    const val CHUNK = 1 shl 20
    const val FORMAT = 1L
    const val WINDOWS = "windows-x86_64"
    const val ANDROID = "android"

    fun trustedKey(): ByteArray = Hex.decode(TRUSTED_KEY_HEX)

    class Artifact(
        val name: String,
        val size: Long,
        val sha256: ByteArray,
        val version: String,
        val min: String,
        /** Android versionCode; 0 elsewhere. */
        val code: Long,
    )

    class Manifest(val seq: Long, val version: String, val files: Map<String, Artifact>)

    sealed class Offer {
        object Current : Offer()
        /** [required] when the running version is below the supported minimum. */
        class Newer(val artifact: Artifact, val required: Boolean) : Offer()
    }

    private fun bad(why: String) = AegisException.Update(why)

    /** A file name the server serves: no separators, no leading dot. */
    fun validName(name: String): Boolean =
        name.isNotEmpty() && name.length <= 96 && !name.startsWith('.') && !name.contains("..") &&
            name.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '.' || it == '-' || it == '_' }

    /** `major.minor.patch` (more or fewer parts allowed); anything after `-` or `+` is ignored. */
    fun parseVersion(v: String): List<Long>? {
        val core = v.split('-', '+').first()
        if (core.isEmpty() || core.length > 32) return null
        return core.split('.').map { p ->
            if (p.isEmpty() || p.length > 9 || !p.all { it in '0'..'9' }) return null
            p.toLong()
        }
    }

    /** Negative, zero or positive like compareTo; null if either does not parse. */
    fun compareVersions(a: String, b: String): Int? {
        val x = parseVersion(a) ?: return null
        val y = parseVersion(b) ?: return null
        for (i in 0 until maxOf(x.size, y.size)) {
            val c = x.getOrElse(i) { 0L }.compareTo(y.getOrElse(i) { 0L })
            if (c != 0) return c
        }
        return 0
    }

    fun open(signed: ByteArray, pk: ByteArray): Manifest {
        if (signed.size <= 64 || signed.size > MAX_MANIFEST) throw bad("manifest size")
        val sig = signed.copyOfRange(0, 64)
        val body = signed.copyOfRange(64, signed.size)
        if (!Crypto.ed25519Verify(pk, Text.utf8(SIG_CONTEXT) + body, sig)) throw AegisException.BadSignature()
        return parse(body)
    }

    private fun parse(body: ByteArray): Manifest {
        val o = try {
            Json.parseObject(String(body, Charsets.UTF_8))
        } catch (_: Json.ParseException) {
            throw bad("manifest json")
        }
        if (o["v"] != FORMAT) throw bad("manifest format")
        val seq = o["seq"] as? Long ?: throw bad("manifest seq")
        if (seq < 0) throw bad("manifest seq")
        val version = o["version"] as? String ?: throw bad("manifest version")
        val files = o["files"] as? Map<*, *> ?: throw bad("manifest files")
        val out = HashMap<String, Artifact>()
        for ((k, f) in files) {
            val m = f as? Map<*, *> ?: throw bad("manifest entry")
            fun s(key: String) = m[key] as? String ?: throw bad("manifest entry")
            val name = s("name")
            val size = m["size"] as? Long ?: throw bad("manifest entry")
            val ver = s("version")
            val min = s("min")
            if (!validName(name)) throw bad("file name")
            if (size <= 0 || size > MAX_FILE) throw bad("file size")
            if (parseVersion(ver) == null || parseVersion(min) == null) throw bad("manifest version")
            val sha = try { Hex.decode(s("sha256")) } catch (_: AegisException.InvalidHex) { throw bad("manifest entry") }
            if (sha.size != 32) throw bad("manifest entry")
            val code = (m["code"] as? Long)?.takeIf { it > 0 } ?: 0L
            out[k as String] = Artifact(name, size, sha, ver, min, code)
        }
        return Manifest(seq, version, out)
    }

    /**
     * Decides on a verified manifest. A sequence below [lastSeq] is a replayed old manifest.
     * With [code] > 0 the versionCode decides, otherwise the dotted version.
     */
    fun evaluate(m: Manifest, platform: String, current: String, code: Long, lastSeq: Long): Offer {
        if (m.seq < lastSeq) throw bad("manifest rollback")
        val a = m.files[platform] ?: return Offer.Current
        val newer = if (code > 0) a.code > code else (compareVersions(a.version, current) ?: 0) > 0
        if (!newer) return Offer.Current
        val required = (compareVersions(current, a.min) ?: 0) < 0
        return Offer.Newer(a, required)
    }

    /** Streams [a] into [out] chunk by chunk and checks the size and the hash. */
    fun download(a: Artifact, out: OutputStream, chunk: (Long) -> ByteArray) {
        if (a.size <= 0 || a.size > MAX_FILE || !validName(a.name)) throw bad("file size")
        val d = SHA256Digest()
        var off = 0L
        while (off < a.size) {
            val part = chunk(off)
            if (part.isEmpty() || part.size > CHUNK || off + part.size > a.size) throw bad("file size")
            d.update(part, 0, part.size)
            out.write(part)
            off += part.size
        }
        val got = ByteArray(32)
        d.doFinal(got, 0)
        if (!got.contentEquals(a.sha256)) throw bad("file hash")
        out.flush()
    }

    /** SHA-256 and length of a stream. */
    fun hash(input: InputStream): Pair<ByteArray, Long> {
        val d = SHA256Digest()
        val buf = ByteArray(64 * 1024)
        var len = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            d.update(buf, 0, n)
            len += n
        }
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out to len
    }
}
