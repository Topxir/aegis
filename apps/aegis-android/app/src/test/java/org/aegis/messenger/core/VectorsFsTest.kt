package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/** Vectors for X3DH, the Double Ratchet, sessions and sender keys (spec sections 27 and 28). */
class VectorsFsTest {
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

    private fun seq(start: Int, len: Int = 32) = ByteArray(len) { (start + it).toByte() }

    private fun envFrom(e: Map<String, Any?>): Envelope = Envelope(
        Kind.parse(s(e, "kind")), s(e, "msg_id"), s(e, "sender"), s(e, "sender_name_text"),
        h(e, "sender_ed"), n(e, "ts_ms"), n(e, "ttl_s"), s(e, "group_id"), s(e, "body_text"),
        s(e, "group_key").let { if (it.isEmpty()) null else Hex.decode(it) },
        s(e, "members").let { if (it.isEmpty()) emptyList() else it.split(',') },
    )

    private fun hx(b: ByteArray) = Hex.encode(b)

    @Test
    fun x3dh() {
        val x = obj(v, "x3dh")
        val aSk = h(x, "a_x_sk")
        val bId = Identity(seq(0x30), seq(0x40))
        val aId = Identity(seq(0x10), seq(0x20))
        assertEquals(s(x, "b_ed_pk"), hx(bId.edPublic))
        val spk = X3dh.SignedPrekey.fromSecret(bId, h(x, "spk_sk"), n(x, "spk_ts"))
        assertEquals(s(x, "spk_pk"), hx(spk.pk))
        assertEquals(s(x, "spk_sig"), hx(spk.sig))
        val ek = h(x, "ek_sk")
        assertEquals(s(x, "ek_pk"), hx(Crypto.x25519Public(ek)))
        val opkSk = h(x, "opk_sk")
        assertEquals(s(x, "opk_pk"), hx(Crypto.x25519Public(opkSk)))
        val parties = X3dh.Parties(aId.edPublic, aId.xPublic, bId.edPublic, bId.xPublic)
        assertEquals(s(x, "ad"), hx(parties.ad()))
        for (c in list(x, "cases")) {
            val withOpk = c["with_opk"] as Boolean
            val bundle = X3dh.Bundle(spk.pk, spk.ts, spk.sig, if (withOpk) Crypto.x25519Public(opkSk) else null)
            bundle.check(bId.edPublic, spk.ts + 100)
            val a = X3dh.initiateWith(ek, aSk, bId.xPublic, bundle)
            assertEquals(s(c, "sk"), hx(a))
            val b = X3dh.respond(bId.xSecret, spk.sk, if (withOpk) opkSk else null, aId.xPublic, Crypto.x25519Public(ek))
            assertEquals(s(c, "sk"), hx(b))
        }
    }

    @Test
    fun bundleChecks() {
        val b = Identity(seq(0x30), seq(0x40))
        val sp = X3dh.SignedPrekey.fromSecret(b, seq(0xc0), 10_000_000)
        val bundle = X3dh.Bundle(sp.pk, sp.ts, sp.sig, null)
        bundle.check(b.edPublic, 10_000_000)
        bundle.check(b.edPublic, 10_000_000 + X3dh.SPK_MAX_AGE_SECS)
        try { bundle.check(b.edPublic, 10_000_000 + X3dh.SPK_MAX_AGE_SECS + 1); fail() } catch (_: AegisException) {}
        try { bundle.check(b.edPublic, 10_000_000 - 601); fail() } catch (_: AegisException) {}
        try { bundle.check(ByteArray(32) { 9 }, 10_000_000); fail() } catch (_: AegisException) {}
    }

    @Test
    fun ratchet() {
        val r = obj(v, "ratchet")
        val sk = h(r, "sk")
        val ad = h(r, "ad")
        val spkSk = h(r, "spk_sk")
        val now = n(r, "now")
        val a = Ratchet.initInitiatorWith(h(r, "a_dhs_sk"), sk, ad, Crypto.x25519Public(spkSk))
        val b = Ratchet.initResponder(sk, ad, spkSk)
        val msgs = list(r, "a_to_b")
        for (m in msgs) {
            val enc = a.encrypt(Text.utf8(s(m, "plain_text")))
            assertEquals(s(m, "msg"), hx(enc))
        }
        @Suppress("UNCHECKED_CAST")
        val order = (r["delivery_order"] as List<Long>).map { it.toInt() }
        for ((k, i) in order.withIndex()) {
            val plain = b.decryptWith(h(r, "b_new_dhs_sk"), Hex.decode(s(msgs[i], "msg")), now)
            assertEquals(s(msgs[i], "plain_text"), String(plain, Charsets.UTF_8))
            if (k == 0) assertEquals(if (i == 0) 0 else i, b.skippedLen)
        }
        assertEquals(0, b.skippedLen)
        val reply = obj(r, "b_to_a")
        val enc = b.encrypt(Text.utf8(s(reply, "plain_text")))
        assertEquals(s(reply, "msg"), hx(enc))
        val got = a.decryptWith(h(r, "a_new_dhs_sk"), enc, now)
        assertEquals("reply", String(got, Charsets.UTF_8))
        // A replayed message is refused and a state round trip keeps working.
        try { b.decryptWith(seq(1), Hex.decode(s(msgs[0], "msg")), now); fail() } catch (_: AegisException) {}
        val b2 = Ratchet.decode(b.encode())
        assertArrayEquals(b.encode(), b2.encode())
    }

    @Test
    fun session() {
        val s0 = obj(v, "session")
        val alice = Identity(seq(0x10), seq(0x20))
        val bob = Identity(seq(0x30), seq(0x40))
        val dm = envFrom(list(v, "envelopes")[0])
        val spk = X3dh.SignedPrekey.fromSecret(bob, h(s0, "spk_sk"), n(s0, "spk_ts"))
        val opkSk = h(s0, "opk_sk")
        val bundle = X3dh.Bundle(spk.pk, spk.ts, spk.sig, Crypto.x25519Public(opkSk))
        val now = n(s0, "now")
        val store = SessionStore()
        store.addContact("bob", bob.edPublic, bob.xPublic)
        assertTrue(store.encrypt(alice, "bob", dm, now) is Encrypted.NeedsPrekeys)
        store.startSessionWith(h(s0, "ek_sk"), h(s0, "dhs_sk"), alice, "bob", bundle, now)
        val start = (store.encryptWith(h(s0, "start_e_sk"), alice, "bob", dm, now) as Encrypted.Frame).bytes
        assertEquals(s(s0, "start_frame"), hx(start))
        assertEquals("hi %41\nline2 <img src=x onerror=alert(1)>", s(s0, "start_body_text"))

        // Bob side as a store with the same prekey secrets is not constructible by seed; use the raw pieces.
        val ad = X3dh.Parties(alice.edPublic, alice.xPublic, bob.edPublic, bob.xPublic).ad()
        val sk = X3dh.respond(bob.xSecret, spk.sk, opkSk, alice.xPublic, Crypto.x25519Public(h(s0, "ek_sk")))
        val bobRatchet = Ratchet.initResponder(sk, ad, spk.sk)
        val inner = Seal.openRaw(0x03, bob.xSecret, start).plain
        assertEquals(0, inner[0].toInt())
        bobRatchet.decryptWith(seq(0x77), inner.copyOfRange(97, inner.size), now)
        val pong = Envelope(
            Kind.Dm, hx(seq(0x61).copyOf(16)), "bob", dm.senderName, bob.edPublic, dm.tsMs, 0, "", "pong",
        )
        val replyMsg = bobRatchet.encrypt(pong.encode())
        val replyFrame = Seal.sealRaw(0x03, seq(0xa3), bob.xSecret, alice.xPublic, Bytes.concat(byteArrayOf(1), replyMsg))
        assertEquals(s(s0, "reply_frame"), hx(replyFrame))

        store.addContact("bob", bob.edPublic, bob.xPublic)
        val got = store.decryptWith(h(s0, "a_new_dhs_sk"), alice, replyFrame, now + 2)
        assertEquals("pong", got.envelope!!.body)
        val next = Envelope(Kind.Dm, s(s0, "message_msg_id"), dm.sender, dm.senderName, dm.senderEd, dm.tsMs, 0, "", "second")
        val second = (store.encryptWith(h(s0, "message_e_sk"), alice, "bob", next, now + 3) as Encrypted.Frame).bytes
        assertEquals(s(s0, "message_frame"), hx(second))

        // State survives an encode and decode and the replayed reply is dropped.
        val again = SessionStore.decode(store.encode())
        assertArrayEquals(store.encode(), again.encode())
        assertNull(again.decryptWith(seq(0x99), alice, replyFrame, now + 4).envelope)
    }

    @Test
    fun fullConversationBetweenStores() {
        val t0 = 1_700_000_000L
        val a = Identity(seq(1), seq(2))
        val b = Identity(seq(3), seq(4))
        val sa = SessionStore()
        val sb = SessionStore()
        sa.addContact("bob", b.edPublic, b.xPublic)
        sb.addContact("alice", a.edPublic, a.xPublic)
        fun env(from: String, ed: ByteArray, body: String) =
            Envelope(Kind.Dm, hx(Crypto.randomBytes(16)), from, "N", ed, 1, 0, "", body)
        val put = sb.preparePrekeys(b, t0, 0)
        assertEquals(50, put.opks.size)
        val bundle = X3dh.Bundle(put.spk.pk, put.spk.ts, put.spk.sig, put.opks.first())
        sa.startSession(a, "bob", bundle, t0)
        val f1 = (sa.encrypt(a, "bob", env("alice", a.edPublic, "one"), t0) as Encrypted.Frame).bytes
        val f2 = (sa.encrypt(a, "bob", env("alice", a.edPublic, "two"), t0) as Encrypted.Frame).bytes
        assertEquals("one", sb.decrypt(b, f1, t0).envelope!!.body)
        assertEquals("two", sb.decrypt(b, f2, t0).envelope!!.body)
        val r1 = (sb.encrypt(b, "alice", env("bob", b.edPublic, "hey"), t0) as Encrypted.Frame).bytes
        assertEquals("hey", sa.decrypt(a, r1, t0).envelope!!.body)
        val f3 = (sa.encrypt(a, "bob", env("alice", a.edPublic, "three"), t0) as Encrypted.Frame).bytes
        assertEquals("three", sb.decrypt(b, f3, t0).envelope!!.body)
        // The one-time prekey is spent: a second start with the same bundle is not accepted.
        val sa2 = SessionStore()
        sa2.addContact("bob", b.edPublic, b.xPublic)
        sa2.startSession(a, "bob", bundle, t0)
        val g = (sa2.encrypt(a, "bob", env("alice", a.edPublic, "again"), t0) as Encrypted.Frame).bytes
        assertNull(sb.decrypt(b, g, t0).envelope)
    }

    @Test
    fun senderKey() {
        val k = obj(v, "senderkey")
        val g = h(k, "g")
        val alice = Identity(seq(0x10), seq(0x20))
        val dm = envFrom(list(v, "envelopes")[0])
        val chain = SendChain.createWith(h(k, "chain_id"), h(k, "ck"), 1_700_000_000)
        val skeyJ = obj(k, "skey_envelope")
        val skey = chain.skeyEnvelopeWith(s(skeyJ, "msg_id"), "alice", dm.senderName, alice.edPublic, s(k, "group_id"), dm.tsMs)
        assertEquals(s(skeyJ, "encoded"), hx(skey.encode()))
        val gmJ = obj(k, "gmsg_envelope")
        val gmsg = envFrom(gmJ)
        val frame = chain.encryptWith(h(k, "hnonce"), SkScope.Group, g, h(k, "ed_sk"), gmsg)
        assertEquals(s(k, "frame"), hx(frame))
        val set = RecvSet(SkScope.Group, g, null)
        val now = n(k, "now")
        set.addFromSkey(skey, now)
        val out = set.decrypt(frame, now)
        assertEquals("hello chain", out.body)
        try { set.decrypt(frame, now); fail() } catch (_: AegisException) {}
        val set2 = RecvSet.decode(set.encode())
        assertArrayEquals(set.encode(), set2.encode())
        assertTrue(chain.needsRotation(now, true))
        assertTrue(!chain.needsRotation(now + 1, false))
        assertTrue(chain.needsRotation(now + SenderKey.ROTATE_AFTER_SECS, false))
    }
}
