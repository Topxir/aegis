package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/** Reproduces every vector of docs/test-vectors.json byte for byte, plus negative cases. */
class VectorsTest {
    companion object {
        lateinit var v: Map<String, Any?>
        var vectorCount = 0

        @BeforeClass
        @JvmStatic
        fun load() {
            val path = System.getProperty("aegis.vectors") ?: error("aegis.vectors not set")
            val f = File(path)
            assertTrue("vector file missing: $path", f.isFile)
            v = Json.parseObject(f.readText(Charsets.UTF_8))
            assertEquals(2L, v["protocol"])
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun obj(m: Map<String, Any?>, k: String) = m[k] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private fun list(m: Map<String, Any?>, k: String) = m[k] as List<Map<String, Any?>>

    private fun s(m: Map<String, Any?>, k: String) = m[k] as String
    private fun h(m: Map<String, Any?>, k: String) = Hex.decode(s(m, k))
    private fun n(m: Map<String, Any?>, k: String) = m[k] as Long

    private fun envFrom(e: Map<String, Any?>): Envelope = Envelope(
        Kind.parse(s(e, "kind")), s(e, "msg_id"), s(e, "sender"), s(e, "sender_name_text"),
        h(e, "sender_ed"), n(e, "ts_ms"), n(e, "ttl_s"), s(e, "group_id"), s(e, "body_text"),
        s(e, "group_key").let { if (it.isEmpty()) null else Hex.decode(it) },
        s(e, "members").let { if (it.isEmpty()) emptyList() else it.split(',') },
    )

    private fun assertEnvelopeVector(e: Map<String, Any?>) {
        val env = envFrom(e)
        val enc = env.encode()
        assertEquals(s(e, "encoded"), Hex.encode(enc))
        assertEquals(s(e, "encoded_text"), String(enc, Charsets.UTF_8))
        val back = Envelope.decode(Hex.decode(s(e, "encoded")))
        assertArrayEquals(enc, back.encode())
        assertEquals(env.body, back.body)
        assertEquals(env.senderName, back.senderName)
        assertEquals(env.members, back.members)
        assertEquals(env.kind, back.kind)
        assertEquals(env.tsMs, back.tsMs)
        assertEquals(env.ttlS, back.ttlS)
    }

    @Test
    fun safetyNumber() {
        val m = obj(v, "safety_number")
        val num = Safety.number(h(m, "a_ed"), h(m, "a_x"), h(m, "b_ed"), h(m, "b_x"))
        assertEquals(s(m, "number"), num)
        assertEquals(s(m, "number_swapped"), Safety.number(h(m, "b_ed"), h(m, "b_x"), h(m, "a_ed"), h(m, "a_x")))
        assertEquals(6, num.split(' ').size)
        // Differs when any key differs.
        assertNotEquals(num, Safety.number(h(m, "a_ed"), h(m, "a_x"), h(m, "a_ed"), h(m, "b_x")))
    }

    @Test
    fun identityKeysMatchVectors() {
        val seal = obj(v, "seal")
        assertEquals(s(seal, "sender_x_pk"), Hex.encode(Crypto.x25519Public(h(seal, "sender_x_sk"))))
        assertEquals(s(seal, "recipient_x_pk"), Hex.encode(Crypto.x25519Public(h(seal, "recipient_x_sk"))))
        val g = obj(v, "group")
        assertEquals(s(g, "sender_ed_pk"), Hex.encode(Crypto.ed25519Public(h(g, "sender_ed_sk"))))
    }

    @Test
    fun padding() {
        val rows = list(v, "padding")
        assertEquals(9, rows.size)
        for (r in rows) {
            if (r.containsKey("frame_len")) {
                val len = n(r, "frame_len").toInt()
                val frame = ByteArray(len) { i -> ((i % 251) + 1).toByte() }
                val p = Pad.pad(frame)
                assertEquals(n(r, "padded_len").toInt(), p.size)
                assertEquals(s(r, "padded_sha256"), Hex.encode(Crypto.sha256(p)))
                assertArrayEquals(frame, Pad.unpad(p))
            } else {
                val p = Pad.pad(h(r, "frame"))
                assertEquals(s(r, "padded"), Hex.encode(p))
                assertEquals(n(r, "padded_len").toInt(), p.size)
                assertArrayEquals(h(r, "frame"), Pad.unpad(p))
            }
        }
        assertEquals(16384, Pad.pad(ByteArray(16380)).size)
    }

    @Test
    fun paddingRejections() {
        try { Pad.pad(ByteArray(16381)); fail() } catch (_: AegisException.FrameTooLarge) {}
        val ok = Pad.pad(ByteArray(10) { 1 })
        val notBucket = ok.copyOf(255)
        val dirty = ok.copyOf().also { it[200] = 1 }
        val oversize = ok.copyOf().also { Bytes.putBe32(it, 0, 300) }
        val tooBig = Pad.pad(ByteArray(300)).also { Bytes.putBe32(it, 0, 10) } // non-minimal bucket
        val huge = ok.copyOf().also { Bytes.putBe32(it, 0, 0xFFFFFFFFL) }
        for (bad in listOf(notBucket, dirty, oversize, tooBig, huge, ByteArray(0))) {
            try { Pad.unpad(bad); fail("accepted bad padding") } catch (_: AegisException.BadPadding) {}
        }
    }

    @Test
    fun envelopes() {
        val rows = list(v, "envelopes")
        assertEquals(3, rows.size)
        rows.forEach { assertEnvelopeVector(it) }
    }

    @Test
    fun sealCases() {
        val m = obj(v, "seal")
        val cases = list(m, "cases")
        assertEquals(2, cases.size)
        assertEquals(s(m, "recipient_inbox_queue"), Hex.encode(QueueIds.inbox(h(m, "recipient_x_pk"))))
        for (c in cases) {
            val envJson = obj(c, "envelope")
            assertEnvelopeVector(envJson)
            val env = envFrom(envJson)
            assertEquals(s(c, "e_pk"), Hex.encode(Crypto.x25519Public(h(c, "e_sk"))))
            val frame = Seal.sealDmWith(h(c, "e_sk"), h(m, "sender_x_sk"), h(m, "recipient_x_pk"), env)
            assertEquals(s(c, "frame"), Hex.encode(frame))
            val opened = Seal.openDm(h(m, "recipient_x_sk"), Hex.decode(s(c, "frame")))
            assertEquals(s(m, "sender_x_pk"), Hex.encode(opened.senderXPk))
            assertArrayEquals(env.encode(), opened.envelope.encode())
        }
    }

    @Test
    fun sealNegatives() {
        val m = obj(v, "seal")
        val c = list(m, "cases")[0]
        val frame = h(c, "frame")
        val rsk = h(m, "recipient_x_sk")
        for (i in frame.indices) {
            val t = frame.copyOf()
            t[i] = (t[i].toInt() xor 1).toByte()
            try { Seal.openDm(rsk, t); fail("accepted tampered byte $i") } catch (_: AegisException) {}
        }
        try { Seal.openDm(rsk, frame.copyOf(frame.size - 1)); fail() } catch (_: AegisException) {}
        try { Seal.openDm(rsk, frame.copyOf(10)); fail() } catch (_: AegisException) {}
        try { Seal.openDm(h(m, "sender_x_sk"), frame); fail("wrong key accepted") } catch (_: AegisException) {}
        try { Seal.openDm(rsk, byteArrayOf(2) + frame.copyOfRange(1, frame.size)); fail() } catch (_: AegisException.BadFrameType) {}
        // Degenerate ephemeral key must not crash the receiver.
        val zeroE = frame.copyOf().also { for (i in 1..32) it[i] = 0 }
        try { Seal.openDm(rsk, zeroE); fail() } catch (_: AegisException) {}
        // gmsg envelopes cannot be sealed as 0x01.
        val gm = envFrom(obj(list(v, "envelopes").let { mapOf("x" to it[2]) }, "x"))
        try { Seal.sealDm(h(m, "sender_x_sk"), h(m, "recipient_x_pk"), gm); fail() } catch (_: AegisException.BadFrameType) {}
        // All-zero recipient key is refused.
        try { Seal.sealDm(h(m, "sender_x_sk"), ByteArray(32), envFrom(obj(list(m, "cases")[0], "envelope"))); fail() } catch (_: AegisException.ZeroSharedSecret) {}
    }

    @Test
    fun sealRandomRoundTrip() {
        val a = Identity.generate()
        val b = Identity.generate()
        val env = envFrom(obj(list(obj(v, "seal"), "cases")[0], "envelope"))
        val f1 = Seal.sealDm(a.xSecret, b.xPublic, env)
        val f2 = Seal.sealDm(a.xSecret, b.xPublic, env)
        assertFalse(f1.contentEquals(f2))
        val o = Seal.openDm(b.xSecret, f1)
        assertArrayEquals(a.xPublic, o.senderXPk)
    }

    @Test
    fun groupVector() {
        val m = obj(v, "group")
        val g = h(m, "g")
        assertEquals(s(m, "group_id"), Group.groupId(g))
        assertEquals(s(m, "queue"), Hex.encode(QueueIds.group(g)))
        assertEquals(s(obj(v, "queues"), "group_queue"), Hex.encode(QueueIds.group(g)))
        val envJson = obj(m, "envelope")
        assertEnvelopeVector(envJson)
        val env = envFrom(envJson)
        val frame = Group.encryptWith(h(m, "nonce"), g, h(m, "sender_ed_sk"), env)
        assertEquals(s(m, "frame"), Hex.encode(frame))
        val back = Group.decrypt(g, Hex.decode(s(m, "frame")))
        assertArrayEquals(env.encode(), back.encode())
    }

    @Test
    fun groupNegatives() {
        val m = obj(v, "group")
        val g = h(m, "g")
        val frame = h(m, "frame")
        for (i in frame.indices) {
            val t = frame.copyOf()
            t[i] = (t[i].toInt() xor 1).toByte()
            try { Group.decrypt(g, t); fail("accepted tampered byte $i") } catch (_: AegisException) {}
        }
        val other = g.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        try { Group.decrypt(other, frame); fail("wrong key accepted") } catch (_: AegisException) {}
        try { Group.decrypt(g, frame.copyOf(40)); fail() } catch (_: AegisException) {}

        // Valid ciphertext whose signature comes from a different key than sender_ed.
        val env = envFrom(obj(m, "envelope"))
        val bytes = env.encode()
        val wrongSig = Crypto.ed25519Sign(ByteArray(32) { 9 }, Text.utf8("aegis-v2 gmsg\n").plus(bytes))
        val k = Crypto.hkdf32(g, ByteArray(0), Text.utf8("aegis-v2 group-msg"))
        val ct = Crypto.aeadSeal(k, h(m, "nonce"), byteArrayOf(2), bytes + wrongSig)
        try { Group.decrypt(g, byteArrayOf(2) + h(m, "nonce") + ct); fail("bad signature accepted") } catch (_: AegisException.BadSignature) {}

        // Frame for another group id.
        val g2 = ByteArray(32) { 7 }
        try { Group.encryptWith(h(m, "nonce"), g2, h(m, "sender_ed_sk"), env); fail() } catch (_: AegisException.GroupMismatch) {}
        // Signing key must match sender_ed.
        try { Group.encryptWith(h(m, "nonce"), g, ByteArray(32) { 3 }, env); fail() } catch (_: AegisException.SenderMismatch) {}
        // DM-kind envelopes are not group messages.
        val dm = envFrom(list(v, "envelopes")[0])
        try { Group.encryptWith(h(m, "nonce"), g, h(m, "sender_ed_sk"), dm); fail() } catch (_: AegisException.BadFrameType) {}
    }

    @Test
    fun vaultVector() {
        val m = obj(v, "vault")
        val params = Vault.Params(n(m, "m_kib").toInt(), n(m, "t").toInt(), n(m, "p").toInt())
        val pw = s(m, "password_text")
        val file = Vault.encryptWith(pw, params, h(m, "salt"), h(m, "nonce"), h(m, "data"))
        assertEquals(s(m, "file"), Hex.encode(file))
        val opened = Vault.decrypt(pw, Hex.decode(s(m, "file")))
        assertArrayEquals(h(m, "data"), opened.data)
        assertEquals(s(m, "file_name_for_alice"), Vault.fileName("alice"))
        // Re-sealing with the cached key gives a different file that still opens.
        val again = opened.keyed.seal(opened.data)
        assertFalse(again.contentEquals(Hex.decode(s(m, "file"))))
        assertArrayEquals(opened.data, Vault.decrypt(pw, again).data)
    }

    @Test
    fun vaultNegatives() {
        val fast = Vault.Params(256, 1, 1)
        val f = Vault.encryptWith("pw-pw-pw-pw", fast, ByteArray(16) { 1 }, ByteArray(12) { 2 }, "x".toByteArray())
        assertEquals("AGV2", String(f.copyOfRange(0, 4), Charsets.US_ASCII))
        assertEquals(44 + 1 + 16, f.size)
        for (i in f.indices) {
            val t = f.copyOf()
            t[i] = (t[i].toInt() xor 1).toByte()
            try { Vault.decrypt("pw-pw-pw-pw", t); fail("accepted flipped byte $i") } catch (_: AegisException) {}
        }
        try { Vault.decrypt("wrong-pw-pw", f); fail() } catch (_: AegisException.VaultDecrypt) {}
        try { Vault.decrypt("pw-pw-pw-pw", f.copyOf(f.size - 1)); fail() } catch (_: AegisException) {}
        try { Vault.decrypt("pw-pw-pw-pw", "short".toByteArray()); fail() } catch (_: AegisException.VaultFormat) {}
        // Hostile parameters are refused before any key derivation.
        for (off in intArrayOf(4, 8, 12)) {
            for (value in longArrayOf(0xFFFFFFFFL, 0x80000000L, 0L, 17L, (1L shl 18) + 1)) {
                if (off != 4 && value == (1L shl 18) + 1) continue
                if (off == 4 && value == 17L) continue
                val t = f.copyOf()
                Bytes.putBe32(t, off, value)
                try { Vault.decrypt("pw-pw-pw-pw", t); fail("accepted header $off=$value") } catch (_: AegisException.VaultParams) {}
            }
        }
        val low = f.copyOf().also { Bytes.putBe32(it, 4, 7) } // m < 8p
        try { Vault.decrypt("pw-pw-pw-pw", low); fail() } catch (_: AegisException.VaultParams) {}
        try { Vault.encrypt("pw", Vault.Params(1, 1, 1), ByteArray(0)); fail() } catch (_: AegisException.VaultParams) {}
    }

    @Test
    fun vaultAndroidParamsRoundTrip() {
        val data = ByteArray(5000) { it.toByte() }
        val f = Vault.encrypt("some long password", Vault.ANDROID, data)
        assertEquals(19456L, Bytes.be32(f, 4))
        assertEquals(2L, Bytes.be32(f, 8))
        assertEquals(1L, Bytes.be32(f, 12))
        assertArrayEquals(data, Vault.decrypt("some long password", f).data)
    }

    @Test
    fun powVector() {
        val m = obj(v, "pow")
        val scope = s(m, "scope_text")
        val ts = n(m, "ts")
        val bits = n(m, "bits").toInt()
        assertEquals(s(m, "body_hash"), Pow.bodyHashHex(h(m, "body")))
        val found = Pow.mine(scope, ts, s(m, "body_hash"), bits)
        assertEquals(n(m, "pow").toULong(), found)
        assertEquals(s(m, "hash"), Hex.encode(Pow.hash(scope, ts, s(m, "body_hash"), found)))
        assertTrue(Pow.verify(scope, ts, s(m, "body_hash"), found, bits))
        assertFalse(Pow.verify(scope, ts, s(m, "body_hash"), found + 1UL, 24))
        assertFalse(Pow.verify(scope + "x", ts, s(m, "body_hash"), found, 24))
    }

    @Test
    fun directoryVector() {
        val m = obj(v, "directory")
        val id = Identity(ByteArray(32) { (0x10 + it).toByte() }, h(m, "ed_sk"))
        assertEquals(s(m, "ed"), Hex.encode(id.edPublic))
        assertEquals(s(m, "x"), Hex.encode(id.xPublic))
        val reg = Registration.sign(id, s(m, "u"), s(m, "title_text"), n(m, "ts"))
        assertEquals(s(m, "signed_message"), Hex.encode(reg.message()))
        assertEquals(s(m, "sig"), Hex.encode(reg.sig))
        assertEquals(s(m, "pow_body_hash"), reg.bodyHash())
        reg.mine(n(m, "pow_bits").toInt())
        assertEquals(n(m, "pow").toULong(), reg.pow)
        assertEquals(s(m, "form"), reg.toForm())
        assertTrue(reg.signatureOk())
        assertTrue(reg.powOk(8))
        val forged = Registration(reg.u, "Mallory", reg.x, reg.ed, reg.ts, reg.sig, reg.pow)
        assertFalse(forged.signatureOk())
        try { Registration.sign(id, "AL", "t", 1); fail() } catch (_: AegisException.InvalidUsername) {}
        try { Registration.sign(id, "alice", "a\nb", 1); fail() } catch (_: AegisException.InvalidText) {}
        assertTrue(Registration.isValidTitle("x".repeat(64)))
        assertFalse(Registration.isValidTitle("x".repeat(65)))
    }

    @Test
    fun queueVectors() {
        val m = obj(v, "queues")
        assertEquals(s(m, "inbox"), Hex.encode(QueueIds.inbox(h(m, "x_pk"))))
        assertEquals(s(m, "group_queue"), Hex.encode(QueueIds.group(h(m, "g"))))
        assertEquals(s(obj(v, "group"), "group_id"), Group.groupId(h(m, "g")))
        assertNotEquals(Hex.encode(QueueIds.inbox(h(m, "g"))), Hex.encode(QueueIds.group(h(m, "g"))))
    }

    @Test
    fun envelopeRejections() {
        val enc = String(envFrom(list(v, "envelopes")[0]).encode(), Charsets.UTF_8)
        val msgId = s(list(v, "envelopes")[0], "msg_id")
        val bad = listOf(
            enc.replaceFirst("AEGIS2", "AEGIS1"),
            "$enc\nextra",
            enc.replaceFirst("\n", ""),
            enc.replaceFirst("dm", "xx"),
            enc.replaceFirst(msgId, msgId.dropLast(1) + msgId.last().uppercaseChar().let { if (it == msgId.last()) 'G' else it }),
            enc.replaceFirst("alice", "Alice"),
            enc.replaceFirst("1700000000123", "01700000000123"),
            enc.replaceFirst("1700000000123", "+1700000000123"),
            enc.replaceFirst("1700000000123", "99999999999999999999"),
            enc.replaceFirst("alice", "al ice"),
            enc.replaceFirst("%20", "%2G"),
            enc.replaceFirst("%20", "%2f"),
            enc.replaceFirst("%20", "%2"),
            enc.replaceFirst("hi", "h i"),
            enc.replaceFirst("hi", "hé"),
        )
        for (b in bad) {
            try { Envelope.decode(Text.utf8(b)); fail("accepted: $b") } catch (_: AegisException) {}
        }
        try { Envelope.decode(byteArrayOf(0xFF.toByte(), 0xFE.toByte())); fail() } catch (_: AegisException) {}
        // Lone UTF-8 continuation inside a percent escape must not become U+FFFD.
        try { Envelope.decode(Text.utf8(enc.replaceFirst("%20", "%FF"))); fail() } catch (_: AegisException) {}

        val dm = envFrom(list(v, "envelopes")[0])
        fun withGroup(id: String) = Envelope(Kind.Dm, dm.msgId, dm.sender, dm.senderName, dm.senderEd, dm.tsMs, dm.ttlS, id, dm.body)
        try { withGroup("ab".repeat(32)).encode(); fail() } catch (_: AegisException) {}
        val inv = envFrom(list(v, "envelopes")[1])
        val tooMany = Envelope(
            Kind.Ginv, inv.msgId, inv.sender, inv.senderName, inv.senderEd, inv.tsMs, inv.ttlS,
            inv.groupId, inv.body, inv.groupKey, (0 until 21).map { "user%02d".format(it) },
        )
        try { tooMany.encode(); fail() } catch (_: AegisException) {}
        val wrongId = Envelope(Kind.Ginv, inv.msgId, inv.sender, inv.senderName, inv.senderEd, inv.tsMs, inv.ttlS, "ab".repeat(32), inv.body, inv.groupKey, inv.members)
        try { wrongId.encode(); fail() } catch (_: AegisException) {}
    }

    @Test
    fun replayedMessageIdIsDropped() {
        val ids = SeenIds(2)
        assertTrue(ids.insert("a"))
        assertFalse(ids.insert("a"))
        assertTrue(ids.insert("b"))
        assertTrue(ids.insert("c"))
        assertTrue(ids.insert("a")) // evicted earlier
        assertEquals(listOf("c", "a"), ids.toList())
    }

    @Test
    fun keyMismatchIsRejected() {
        val m = obj(v, "seal")
        val c = list(m, "cases")[0]
        val env = envFrom(obj(c, "envelope"))
        val sx = h(m, "sender_x_pk")
        val pinned = PinnedKeys(sx, env.senderEd)
        Pinning.checkDm(env, sx, pinned)
        Pinning.checkGroup(env, pinned)
        val other = ByteArray(32) { 1 }
        try { Pinning.checkDm(env, other, pinned); fail() } catch (_: AegisException.SenderMismatch) {}
        try { Pinning.checkDm(env, sx, PinnedKeys(sx, other)); fail() } catch (_: AegisException.SenderMismatch) {}
        try { Pinning.checkGroup(env, PinnedKeys(sx, other)); fail() } catch (_: AegisException.SenderMismatch) {}
    }

    @Test
    fun expiry() {
        assertFalse(Expiry.isExpired(1000, 0, Long.MAX_VALUE))
        assertFalse(Expiry.isExpired(1000, 10, 10_999))
        assertTrue(Expiry.isExpired(1000, 10, 11_000))
        assertFalse(Expiry.isExpired(Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE - 1))
    }

    @Test
    fun usernamesAndText() {
        assertEquals("alice_01", Names.normalizeUsername("Alice_01"))
        for (bad in listOf("ab", "a b", "alice!", "a".repeat(25), "алиса", "", "aliceK", "aliİce")) {
            try { Names.normalizeUsername(bad); fail(bad) } catch (_: AegisException.InvalidUsername) {}
        }
        assertEquals("abcd", Text.sanitizeDisplay("a‮b​c\u0007d\n﻿"))
        assertEquals("ab", Text.sanitizeDisplay("a⁪b  ￹￻" + String(Character.toChars(0xE0041))))
        assertEquals(64, Text.sanitizeDisplay("я".repeat(100)).length)
        assertEquals("a%20b%0A%25%C3%A9", Text.pctEncode("a b\n%é"))
        assertEquals("a b\n%é", Text.pctDecodeStrict("a%20b%0A%25%C3%A9"))
    }
}
