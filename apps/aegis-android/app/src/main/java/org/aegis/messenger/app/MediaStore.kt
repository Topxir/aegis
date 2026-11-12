package org.aegis.messenger.app

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Text
import java.io.File

/**
 * Attachments at rest (spec section 13): `nonce(12) || AEAD(media_key, nonce, "aegis-v2 media", m)`
 * under `<vault name>.media/`. Plaintext is never written to disk; callers decode from memory.
 */
class MediaStore(private val dir: File) {
    private val aad = Text.utf8("aegis-v2 media")

    private fun path(name: String): File {
        if (!Regex("[0-9a-f]{32}[.]bin").matches(name)) throw AegisException.Media("file name")
        return File(dir, name)
    }

    fun save(mediaKey: ByteArray, m: ByteArray): String {
        dir.mkdirs()
        val name = Hex.encode(Crypto.randomBytes(16)) + ".bin"
        val nonce = Crypto.randomBytes(12)
        val out = nonce + Crypto.aeadSeal(mediaKey, nonce, aad, m)
        val f = path(name)
        val tmp = File(dir, "$name.tmp")
        tmp.writeBytes(out)
        if (!tmp.renameTo(f)) {
            tmp.delete()
            throw java.io.IOException("rename")
        }
        return name
    }

    fun load(mediaKey: ByteArray, name: String): ByteArray {
        val b = path(name).readBytes()
        if (b.size < 12 + 16) throw AegisException.Length()
        return Crypto.aeadOpen(mediaKey, b.copyOfRange(0, 12), aad, b.copyOfRange(12, b.size))
    }

    fun delete(name: String) {
        try { path(name).delete() } catch (_: AegisException) {}
    }

    fun deleteAll() {
        dir.listFiles()?.forEach { it.delete() }
        dir.delete()
    }
}
