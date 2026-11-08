package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File

/** Signed update manifests: the shared vector plus signature, hash, rollback, size and name checks. */
class UpdateTest {
    @Suppress("UNCHECKED_CAST")
    private val v: Map<String, Any?> by lazy {
        val path = System.getProperty("aegis.vectors") ?: error("aegis.vectors not set")
        Json.parseObject(File(path).readText(Charsets.UTF_8))["update"] as Map<String, Any?>
    }

    private val sk = ByteArray(32) { 7 }

    private fun art(data: ByteArray) =
        Update.Artifact("aegis.apk", data.size.toLong(), Crypto.sha256(data), "0.3.0", "0.2.0", 0)

    private fun sign(key: ByteArray, body: String): ByteArray {
        val b = Text.utf8(body)
        return Crypto.ed25519Sign(key, Text.utf8(Update.SIG_CONTEXT) + b) + b
    }

    private fun manifest(seq: Long, entry: String) =
        """{"files":{"android":$entry},"seq":$seq,"v":1,"version":"0.3.0"}"""

    private fun expectUpdate(why: String, f: () -> Unit) {
        try {
            f()
            fail("expected $why")
        } catch (e: AegisException.Update) {
            assertEquals(why, e.why)
        }
    }

    @Test
    fun vectorVerifiesAndDecides() {
        val signed = Hex.decode(v["signed"] as String)
        val pk = Hex.decode(v["pk"] as String)
        assertArrayEquals(pk, Crypto.ed25519Public(Hex.decode(v["sk"] as String)))
        assertEquals(v["manifest_text"], String(signed.copyOfRange(64, signed.size), Charsets.UTF_8))
        val m = Update.open(signed, pk)
        assertEquals(7L, m.seq)
        assertEquals("0.3.0", m.version)
        val win = m.files.getValue(Update.WINDOWS)
        assertArrayEquals(Crypto.sha256(Text.utf8(v["windows_file_text"] as String)), win.sha256)
        assertEquals("aegis-desktop.exe", win.name)
        val apk = Text.utf8(v["android_file_text"] as String)
        val offer = Update.evaluate(m, Update.ANDROID, "0.2.0-alpha", 2, 7)
        assertTrue(offer is Update.Offer.Newer)
        offer as Update.Offer.Newer
        assertFalse(offer.required)
        assertEquals(3L, offer.artifact.code)
        val out = ByteArrayOutputStream()
        Update.download(offer.artifact, out) { off -> apk.copyOfRange(off.toInt(), apk.size) }
        assertArrayEquals(apk, out.toByteArray())
        assertTrue(Update.evaluate(m, Update.ANDROID, "0.3.0", 3, 7) is Update.Offer.Current)
    }

    @Test
    fun badSignatureIsRefused() {
        val signed = Hex.decode(v["signed"] as String)
        val pk = Hex.decode(v["pk"] as String)
        for (i in listOf(0, 63, 64, signed.size - 1)) {
            val t = signed.copyOf()
            t[i] = (t[i].toInt() xor 1).toByte()
            try {
                Update.open(t, pk)
                fail("tampered byte $i accepted")
            } catch (_: AegisException.BadSignature) {
            }
        }
        try {
            Update.open(signed, Update.trustedKey())
            fail("foreign key accepted")
        } catch (_: AegisException.BadSignature) {
        }
        expectUpdate("manifest size") { Update.open(ByteArray(64), pk) }
        expectUpdate("manifest size") { Update.open(ByteArray(Update.MAX_MANIFEST + 1), pk) }
    }

    @Test
    fun wrongHashOrSizeFailsTheDownload() {
        val body = Text.utf8("the new apk")
        val a = art(body)
        expectUpdate("file hash") { Update.download(a, ByteArrayOutputStream()) { Text.utf8("the old apk") } }
        expectUpdate("file size") { Update.download(a, ByteArrayOutputStream()) { ByteArray(body.size + 1) } }
        expectUpdate("file size") { Update.download(a, ByteArrayOutputStream()) { ByteArray(0) } }
        val huge = Update.Artifact("a.apk", Update.MAX_FILE + 1, ByteArray(32), "1.0", "0.1", 0)
        expectUpdate("file size") { Update.download(huge, ByteArrayOutputStream()) { ByteArray(1) } }
        val pk = Crypto.ed25519Public(sk)
        val big = """{"code":3,"min":"0.1.0","name":"a.apk","sha256":"${"00".repeat(32)}","size":${Update.MAX_FILE + 1},"version":"0.3.0"}"""
        expectUpdate("file size") { Update.open(sign(sk, manifest(1, big)), pk) }
    }

    @Test
    fun downgradeAndReplayAreRefused() {
        val pk = Crypto.ed25519Public(sk)
        val e = """{"code":3,"min":"0.1.0","name":"a.apk","sha256":"${"00".repeat(32)}","size":5,"version":"0.3.0"}"""
        val m = Update.open(sign(sk, manifest(5, e)), pk)
        expectUpdate("manifest rollback") { Update.evaluate(m, Update.ANDROID, "0.2.0", 2, 6) }
        assertTrue(Update.evaluate(m, Update.ANDROID, "0.4.0", 4, 5) is Update.Offer.Current)
        assertTrue(Update.evaluate(m, Update.ANDROID, "0.3.0", 3, 5) is Update.Offer.Current)
        val req = Update.evaluate(m, Update.ANDROID, "0.0.9", 2, 0)
        assertTrue(req is Update.Offer.Newer && req.required)
        assertTrue(Update.evaluate(m, Update.WINDOWS, "0.0.1", 0, 0) is Update.Offer.Current)
    }

    @Test
    fun namesAndVersionsArePlain() {
        assertTrue(Update.validName("aegis-messenger-0.3.0.apk"))
        for (n in listOf("", ".hidden", "../x", "a/b", "a\b", "a..b", "c:x", "a b", "x".repeat(97))) {
            assertFalse(n, Update.validName(n))
        }
        val pk = Crypto.ed25519Public(sk)
        val e = """{"min":"0.1.0","name":"../a.apk","sha256":"${"00".repeat(32)}","size":5,"version":"0.3.0"}"""
        expectUpdate("file name") { Update.open(sign(sk, manifest(1, e)), pk) }
        assertEquals(1, Update.compareVersions("0.10.0", "0.9.9"))
        assertEquals(0, Update.compareVersions("0.2.0-alpha", "0.2"))
        assertEquals(-1, Update.compareVersions("1.0.0", "1.0.1"))
        assertNull(Update.compareVersions("1.x", "1.0"))
        assertNull(Update.compareVersions("", "1.0"))
    }
}
