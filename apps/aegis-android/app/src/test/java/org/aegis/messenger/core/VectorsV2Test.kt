package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/** Vectors for attachments, channels, the official channel, avatars, profile cards and the MP4 sanitizer. */
class VectorsV2Test {
    companion object {
        lateinit var v: Map<String, Any?>

        @BeforeClass
        @JvmStatic
        fun load() {
            val path = System.getProperty("aegis.vectors") ?: error("aegis.vectors not set")
            v = Json.parseObject(File(path).readText(Charsets.UTF_8))
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

    private fun assertEnv(e: Map<String, Any?>) {
        val env = envFrom(e)
        val enc = env.encode()
        assertEquals(s(e, "encoded"), Hex.encode(enc))
        assertEquals(s(e, "encoded_text"), String(enc, Charsets.UTF_8))
        assertArrayEquals(enc, Envelope.decode(Hex.decode(s(e, "encoded"))).encode())
    }

    private fun payload(len: Int): ByteArray {
        val m = ByteArray(len) { (it % 251).toByte() }
        m[0] = 0xff.toByte(); m[1] = 0xd8.toByte(); m[2] = 0xff.toByte()
        return m
    }

    private fun meta(d: Map<String, Any?>, caption: String): AttachmentMeta {
        val p = AttachmentDescriptor.parse(d["descriptor_body_text"] as String)
        return AttachmentMeta(p.kind, p.width, p.height, p.durationMs, caption)
    }

    @Test
    fun attachmentCases() {
        for (c in list(obj(v, "attachment"), "cases")) {
            val len = n(c, "m_len").toInt()
            val m = payload(len)
            assertEquals(s(c, "m_sha256"), Hex.encode(Crypto.sha256(m)))
            assertEquals(n(c, "padded_len").toInt(), Attach.paddedLen(len.toLong()))
            assertEquals(n(c, "n").toInt(), Attach.chunkCount(len.toLong()))
            val body = s(c, "descriptor_body_text")
            val parsed = AttachmentDescriptor.parse(body)
            assertEquals(body, parsed.encode())
            val ids = (c["ids"] as List<*>).map { Hex.decode(it as String) }
            val sealed = Attach.sealWith(meta(c, parsed.caption), m, h(c, "key"), ids)
            assertEquals(body, sealed.descriptor.encode())
            val lens = (c["chunk_lens"] as List<*>).map { it as Long }
            val shas = (c["chunk_sha256"] as List<*>).map { it as String }
            assertEquals(lens.size, sealed.chunks.size)
            for (i in lens.indices) {
                assertEquals(lens[i].toInt(), sealed.chunks[i].size)
                assertEquals(shas[i], Hex.encode(Crypto.sha256(sealed.chunks[i])))
            }
            (c["chunks"] as List<*>?)?.forEachIndexed { i, hx -> assertEquals(hx, Hex.encode(sealed.chunks[i])) }
            assertArrayEquals(m, Attach.open(parsed, sealed.chunks))
            assertEnv(obj(c, "dmf_envelope"))
            assertEquals(body, envFrom(obj(c, "dmf_envelope")).body)
        }
    }

    @Test
    fun attachmentFailsClosed() {
        val c = list(obj(v, "attachment"), "cases")[0]
        val m = payload(100)
        val sealed = Attach.sealWith(
            meta(c, ""), m, h(c, "key"), listOf(ByteArray(32) { 1 }),
        )
        val d = sealed.descriptor
        val bad = sealed.chunks[0].copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        try {
            Attach.open(d, listOf(bad))
            fail()
        } catch (_: AegisException) {
        }
        try {
            Attach.open(d, emptyList())
            fail()
        } catch (_: AegisException) {
        }
        try {
            Attach.sealWith(meta(c, ""), ByteArray(10), ByteArray(32), listOf(ByteArray(32)))
            fail("magic")
        } catch (_: AegisException) {
        }
        for (b in listOf("", "AT2\nimage", d.encode().replace("AT1", "AT2"), d.encode() + "\nx")) {
            try {
                AttachmentDescriptor.parse(b)
                fail(b)
            } catch (_: AegisException) {
            }
        }
        assertEquals(null, Attach.paddedLen(Attach.MAX_SIZE + 1L))
        assertEquals(65536, Attach.paddedLen(65528))
        assertEquals(131072, Attach.paddedLen(65529))
        assertEquals(1, Attach.chunkCount(1_048_568))
        assertEquals(2, Attach.chunkCount(1_048_569))
    }

    @Test
    fun channelVector() {
        val c = obj(v, "channel")
        val g = h(c, "g")
        assertEquals(s(c, "channel_id"), Channel.channelId(g))
        assertEquals(s(c, "queue"), Hex.encode(Channel.queue(g)))
        assertEquals(s(c, "key"), Hex.encode(Channel.msgKey(g)))
        assertEquals(s(c, "owner_ed_pk"), Hex.encode(Crypto.ed25519Public(h(c, "owner_ed_sk"))))
        assertEnv(obj(c, "cinv_envelope"))
        assertEnv(obj(c, "post_envelope"))
        val post = envFrom(obj(c, "post_envelope"))
        val frame = Channel.sealPostWith(h(c, "nonce"), g, h(c, "owner_ed_sk"), post)
        assertEquals(s(c, "frame"), Hex.encode(frame))
        val pk = h(c, "owner_ed_pk")
        val opened = Channel.openPost(g, s(c, "owner"), pk, frame)
        assertEquals(post.body, opened.body)
        for (bad in listOf(
            { Channel.openPost(g, "bob", pk, frame) },
            { Channel.openPost(g, s(c, "owner"), ByteArray(32) { 1 }, frame) },
            { Channel.openPost(ByteArray(32) { 7 }, s(c, "owner"), pk, frame) },
            { Group.decrypt(g, frame) },
        )) {
            try {
                bad()
                fail()
            } catch (_: AegisException) {
            }
        }
        for (i in frame.indices) {
            val t = frame.copyOf()
            t[i] = (t[i].toInt() xor 0x40).toByte()
            try {
                Channel.openPost(g, s(c, "owner"), pk, t)
                fail("byte $i")
            } catch (_: AegisException) {
            }
        }
        // A group frame never opens as a channel post.
        val gm = Envelope(
            Kind.Gmsg, post.msgId, post.sender, post.senderName, post.senderEd, post.tsMs, 0,
            Group.groupId(g), "x",
        )
        val gf = Group.encrypt(g, h(c, "owner_ed_sk"), gm)
        try {
            Channel.openPost(g, s(c, "owner"), pk, gf)
            fail()
        } catch (_: AegisException) {
        }
        try {
            Channel.sealPost(g, h(c, "owner_ed_sk"), gm)
            fail()
        } catch (_: AegisException) {
        }
    }

    @Test
    fun subscriberCannotForge() {
        val c = obj(v, "channel")
        val g = h(c, "g")
        val ownerPk = h(c, "owner_ed_pk")
        val mine = ByteArray(32) { 0x99.toByte() }
        val post = envFrom(obj(c, "post_envelope"))
        // Own key in sender_ed: the sender check rejects it.
        val own = Envelope(
            Kind.Cmsg, post.msgId, post.sender, post.senderName, Crypto.ed25519Public(mine), post.tsMs, 0,
            post.groupId, "x",
        )
        val f = Channel.sealPost(g, mine, own)
        try {
            Channel.openPost(g, s(c, "owner"), ownerPk, f)
            fail()
        } catch (_: AegisException.SenderMismatch) {
        }
        // Owner key claimed, signed with the wrong key: bad signature.
        val claim = Envelope(Kind.Cmsg, post.msgId, post.sender, post.senderName, ownerPk, post.tsMs, 0, post.groupId, "x")
        val bytes = claim.encode()
        val sig = Crypto.ed25519Sign(mine, Bytes.concat(Text.utf8("aegis-v2 gmsg\n"), bytes))
        val key = Channel.msgKey(g)
        val nonce = ByteArray(12) { 3 }
        val ct = Crypto.aeadSeal(key, nonce, byteArrayOf(2), Bytes.concat(bytes, sig))
        val forged = Bytes.concat(byteArrayOf(2), nonce, ct)
        try {
            Channel.openPost(g, s(c, "owner"), ownerPk, forged)
            fail()
        } catch (_: AegisException.BadSignature) {
        }
    }

    @Test
    fun officialVector() {
        val o = obj(v, "official")
        assertEquals(s(o, "g"), Hex.encode(Official.g()))
        assertEquals(s(o, "channel_id"), Official.channelId())
        assertEquals(s(o, "queue"), Hex.encode(Official.queue()))
        assertEquals(s(o, "key"), Hex.encode(Channel.msgKey(Official.g())))
        assertEquals("owner", s(o, "owner"))
        assertEnv(obj(o, "post_envelope"))
        val post = envFrom(obj(o, "post_envelope"))
        val frame = Channel.sealPostWith(h(o, "nonce"), Official.g(), h(o, "owner_ed_sk"), post)
        assertEquals(s(o, "frame"), Hex.encode(frame))
        assertEquals("welcome", Official.openPost(h(o, "owner_ed_pk"), frame).body)
        try {
            Official.openPost(ByteArray(32) { 1 }, frame)
            fail()
        } catch (_: AegisException) {
        }
    }

    @Test
    fun avatarVectors() {
        @Suppress("UNCHECKED_CAST")
        val list = v["avatar"] as List<Map<String, Any?>>
        for (a in list) {
            val av = Avatar.fromEdPk(h(a, "ed_pk"))
            assertEquals(s(a, "mask"), av.maskString())
            assertEquals(n(a, "bg").toInt(), av.bg)
            assertEquals(n(a, "fg").toInt(), av.fg)
        }
        for (i in 0..255) {
            val a = Avatar.fromEdPk(ByteArray(32) { i.toByte() })
            for (r in a.cells) {
                assertEquals(r[0], r[4])
                assertEquals(r[1], r[3])
            }
            assertTrue(a.bg in 0x1c until 0x1c + 0x18)
            assertTrue(a.fg in 0xa0 until 0xa0 + 0x50)
        }
    }

    @Test
    fun profVector() {
        val p = obj(v, "prof")
        assertEnv(obj(p, "envelope"))
        val body = s(p, "body_text")
        val prof = Profile(s(p, "name"), s(p, "about"), Particles.parse(s(p, "particles")))
        assertEquals(body, prof.encode())
        val back = Profile.parse(body)
        assertEquals(prof.name, back.name)
        assertEquals(prof.about, back.about)
        assertEquals(prof.particles, back.particles)
        @Suppress("UNCHECKED_CAST")
        val invalid = p["invalid_bodies"] as List<String>
        val extra = listOf("", "PF1\nn\nx\r\nnone", "PF1\nn\nx\u0085\nnone", "PF1\nn\nx\nSnow",
            "PF1\n" + "n".repeat(65) + "\nx\nnone", "PF1\nn\n" + "a".repeat(141) + "\nnone")
        for (b in invalid + extra) {
            try {
                Profile.parse(b)
                fail(b)
            } catch (_: AegisException) {
            }
        }
        Profile.parse("PF1\nn\n" + "a".repeat(140) + "\nnone")
    }

    @Test
    fun mp4Vector() {
        val m = obj(v, "mp4")
        val out = Mp4Clean.sanitize(h(m, "input"))
        assertEquals(s(m, "output"), Hex.encode(out.bytes))
        assertEquals(s(m, "output_sha256"), Hex.encode(Crypto.sha256(out.bytes)))
        assertEquals(n(m, "width"), out.width)
        assertEquals(n(m, "height"), out.height)
        assertEquals(n(m, "duration_ms"), out.durationMs)
        // The shared fixture builder reproduces the vector input.
        assertEquals(s(m, "input"), Hex.encode(Mp4Fixture.build().bytes))
    }

    @Test
    fun groupGmfAndHundredMembers() {
        val g = Group.newSecret()
        val sk = ByteArray(32) { 5 }
        val pk = Crypto.ed25519Public(sk)
        val members = List(100) { "user${it}x" }
        val inv = Envelope(
            Kind.Ginv, "00".repeat(16), "alice", "A", pk, 1, 0, Group.groupId(g), "G", g, members,
        )
        assertEquals(inv.members, Envelope.decode(inv.encode()).members)
        try {
            Envelope(Kind.Ginv, "00".repeat(16), "alice", "A", pk, 1, 0, Group.groupId(g), "G", g, members + "extra").encode()
            fail()
        } catch (_: AegisException) {
        }
        val gmf = Envelope(Kind.Gmf, "11".repeat(16), "alice", "A", pk, 1, 0, Group.groupId(g), "AT1")
        assertEquals(Kind.Gmf, Group.decrypt(g, Group.encrypt(g, sk, gmf)).kind)
    }

    @Test
    fun strictEd25519() {
        val sk = ByteArray(32) { 9 }
        val pk = Crypto.ed25519Public(sk)
        val msg = Text.utf8("strict")
        val sig = Crypto.ed25519Sign(sk, msg)
        assertTrue(Crypto.ed25519Verify(pk, msg, sig))
        // S + L is the same point equation but not canonical.
        val l = java.math.BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")
        val sBig = java.math.BigInteger(1, sig.copyOfRange(32, 64).reversedArray()).add(l)
        val enc = sBig.toByteArray().reversedArray()
        val s2 = ByteArray(32)
        enc.copyInto(s2, 0, 0, minOf(32, enc.size))
        if (sBig.bitLength() <= 256) {
            val bad = sig.copyOf()
            s2.copyInto(bad, 32)
            assertFalse(Crypto.ed25519Verify(pk, msg, bad))
        }
        // Small-order public keys and R values are refused.
        val identity = ByteArray(32).also { it[0] = 1 }
        val zeroPk = ByteArray(32)
        val minusOne = Hex.decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        val order8 = Hex.decode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
        val order8b = Hex.decode("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
        for (small in listOf(identity, zeroPk, minusOne, order8, order8b)) {
            assertTrue(Crypto.isSmallOrder(small))
            assertFalse(Crypto.ed25519Verify(small, msg, sig))
            val badR = sig.copyOf()
            small.copyInto(badR, 0)
            assertFalse(Crypto.ed25519Verify(pk, msg, badR))
            // Identity key with the identity signature (R = identity, S = 0) would pass a lax verifier.
            val lax = ByteArray(64)
            small.copyInto(lax, 0)
            assertFalse(Crypto.ed25519Verify(small, msg, lax))
        }
        assertFalse(Crypto.isSmallOrder(pk))
        assertFalse(Crypto.isSmallOrder(sig, 0))
    }

    @Test
    fun pinVector() {
        val p = obj(v, "pin")
        val params = PinParams(n(p, "m_kib").toInt(), n(p, "t").toInt(), n(p, "p").toInt())
        val pin = s(p, "pin_text")
        val key = Pin.PinKey.derive(pin, h(p, "salt"), h(p, "slot"), params)
        assertArrayEquals(h(p, "t_key"), key.t)
        assertArrayEquals(h(p, "verifier"), key.verifier())
        assertArrayEquals(h(p, "wrap"), key.wrapKey(h(p, "s")))
        val st = Pin.setupWith(pin, h(p, "vault_key"), params, h(p, "salt"), h(p, "slot"), h(p, "s"), h(p, "nonce"))
        assertArrayEquals(h(p, "file"), st.file.encode())
        assertArrayEquals(h(p, "verifier"), st.verifier)
        val f = Pin.PinFile.parse(h(p, "file"))
        assertArrayEquals(h(p, "vault_key"), f.unwrap(key, h(p, "s")))
        try { f.unwrap(key, ByteArray(32)); fail() } catch (_: AegisException) {}
        val slotHex = s(p, "slot")
        val vHex = s(p, "verifier")
        assertEquals(s(p, "create_hash_input_text"), Pin.createHashInput(slotHex, vHex, s(p, "s")))
        assertEquals(s(p, "open_hash_input_text"), Pin.openHashInput(slotHex, vHex))
        assertEquals(s(p, "pow_scope_text"), Pin.powScope(slotHex))
        val d = Pin.DuressRecord.parse(h(p, "duress_file"))
        assertArrayEquals(h(p, "duress_file"), d.encode())
        assertTrue(d.matches(s(p, "duress_pin_text"), params))
        assertFalse(d.matches(pin, params))
        assertFalse(Pin.isValidPin("12345"))
        assertFalse(Pin.isValidPin("12a4"))
        assertTrue(Pin.isValidPin("0000"))
        try { Pin.PinFile.parse(ByteArray(Pin.PIN_FILE_LEN)); fail() } catch (_: AegisException) {}
    }
}
