package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Replays of pairwise frames and channel posts, and the replay state formats. */
class ReplayTest {
    private val t0 = 1_700_000_000L
    private val a = Identity(seq(1), seq(2))
    private val b = Identity(seq(3), seq(4))

    private fun seq(start: Int, len: Int = 32) = ByteArray(len) { (start + it).toByte() }

    private fun env(from: String, ed: ByteArray, body: String) =
        Envelope(Kind.Dm, Hex.encode(Crypto.randomBytes(16)), from, "N", ed, 1, 0, "", body)

    private inner class Chat {
        val sa = SessionStore().apply { addContact("bob", b.edPublic, b.xPublic) }
        val sb = SessionStore().apply { addContact("alice", a.edPublic, a.xPublic) }

        init {
            val put = sb.preparePrekeys(b, t0, 0)
            sa.startSession(a, "bob", X3dh.Bundle(put.spk.pk, put.spk.ts, put.spk.sig, put.opks.first()), t0)
        }

        fun toBob(body: String) = (sa.encrypt(a, "bob", env("alice", a.edPublic, body), t0) as Encrypted.Frame).bytes
        fun toAlice(body: String) = (sb.encrypt(b, "alice", env("bob", b.edPublic, body), t0) as Encrypted.Frame).bytes
    }

    private fun assertIgnored(r: Received) {
        assertNull(r.envelope)
        assertTrue(r.actions.none { it is SessionAction.StartNewSession || it is SessionAction.UndecryptableNotice })
    }

    @Test
    fun replayedStartFramesAreIgnoredAfterSeenSetRollsOver() {
        val p = Chat()
        val frames = (0 until 1100).map { p.toBob("m$it") }
        for (f in frames) assertNotNull(p.sb.decrypt(b, f, t0).envelope)
        for (f in frames.take(3) + frames[0] + frames[0]) assertIgnored(p.sb.decrypt(b, f, t0 + 10))
        assertTrue(p.sb.encrypt(b, "alice", env("bob", b.edPublic, "x"), t0 + 10) is Encrypted.Frame)
        assertNotNull(p.sb.decrypt(b, p.toBob("live"), t0 + 11).envelope)
    }

    @Test
    fun replayedFramesFromPastChainsAreIgnored() {
        val p = Chat()
        val old = arrayListOf(p.toBob("hello"))
        assertNotNull(p.sb.decrypt(b, old[0], t0).envelope)
        assertNotNull(p.sa.decrypt(a, p.toAlice("reply"), t0).envelope)
        repeat(3) { round ->
            repeat(2) {
                val f = p.toBob("r$round-$it")
                assertNotNull(p.sb.decrypt(b, f, t0).envelope)
                old.add(f)
            }
            assertNotNull(p.sa.decrypt(a, p.toAlice("ack"), t0).envelope)
        }
        repeat(1100) { assertNotNull(p.sb.decrypt(b, p.toBob("m$it"), t0).envelope) }
        repeat(5) { for (f in old) assertIgnored(p.sb.decrypt(b, f, t0 + 10)) }
        assertTrue(p.sb.encrypt(b, "alice", env("bob", b.edPublic, "x"), t0 + 10) is Encrypted.Frame)
        assertNotNull(p.sb.decrypt(b, p.toBob("live"), t0 + 11).envelope)
    }

    @Test
    fun v1SessionStateStillDecodes() {
        val st = SessionStore()
        st.addContact("alice", ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val v2 = st.encode()
        val n = v2.size
        assertArrayEquals(ByteArray(5), v2.copyOfRange(n - 5, n))
        val v1 = Bytes.concat(Text.utf8("AGS1"), v2.copyOfRange(4, n - 5), v2.copyOfRange(n - 1, n))
        assertArrayEquals(v2, SessionStore.decode(v1).encode())
    }

    @Test
    fun overlongStringsAreRefusedNotTruncated() {
        try { StateWriter().str("a".repeat(256)); fail() } catch (_: AegisException) {}
        assertEquals(256, StateWriter().str("a".repeat(255)).finish().size)
    }

    private val g = ByteArray(32) { 0x55 }
    private val ownerSk = ByteArray(32) { 0x66 }
    private val ownerEd = Crypto.ed25519Public(ownerSk)

    private fun post(body: String) = Envelope(
        Kind.Cmsg, Hex.encode(Crypto.randomBytes(16)), "owner", "Owner", ownerEd, 1, 0, Channel.channelId(g), body,
    )

    private fun chainKey(ck0: ByteArray, n: Int): ByteArray {
        var ck = ck0
        repeat(n) { ck = Kdf.ck(ck).second }
        return ck
    }

    private fun openPlain(ck0: ByteArray, cid: ByteArray, n: Int, frame: ByteArray): ByteArray {
        val (k, nonce) = Kdf.msgKey(Kdf.ck(chainKey(ck0, n)).first, "aegis-v2 group-key")
        return Crypto.aeadOpen(k, nonce, SenderKey.chainAad(cid, n.toLong()), frame.copyOfRange(1 + SenderKey.HDR_LEN, frame.size))
    }

    private fun forge(ck0: ByteArray, cid: ByteArray, n: Int, plain: ByteArray): ByteArray {
        val (k, nonce) = Kdf.msgKey(Kdf.ck(chainKey(ck0, n)).first, "aegis-v2 group-key")
        val aad = SenderKey.chainAad(cid, n.toLong())
        val hnonce = ByteArray(12) { 9 }
        val hdr = Crypto.aeadSeal(SenderKey.headerKey(g), hnonce, byteArrayOf(SenderKey.FRAME), aad.copyOfRange(1, aad.size))
        return Bytes.concat(byteArrayOf(SenderKey.FRAME), hnonce, hdr, Crypto.aeadSeal(k, nonce, aad, plain))
    }

    @Test
    fun replayedChannelPostDoesNotBurnTheRealKey() {
        val cid = ByteArray(16) { 1 }
        val ck0 = ByteArray(32) { 2 }
        val owner = SendChain.createWith(cid, ck0, 100)
        val victim = RecvSet(SkScope.Channel, g, ownerEd)
        victim.addChain("owner", ownerEd, cid, 0, ck0, 100)
        val f0 = owner.encryptWith(seq(7, 12), SkScope.Channel, g, ownerSk, post("post 0"))
        assertEquals("post 0", victim.decrypt(f0, 101).body)
        val before = victim.encode()
        try { victim.decrypt(forge(ck0, cid, 1, openPlain(ck0, cid, 0, f0)), 102); fail() } catch (_: AegisException) {}
        assertArrayEquals(before, victim.encode())
        val f1 = owner.encryptWith(seq(8, 12), SkScope.Channel, g, ownerSk, post("post 1"))
        assertEquals("post 1", victim.decrypt(f1, 103).body)

        val cid2 = ByteArray(16) { 3 }
        val ck2 = ByteArray(32) { 4 }
        val next = SendChain.createWith(cid2, ck2, 200)
        victim.addChain("owner", ownerEd, cid2, 0, ck2, 200)
        val again = victim.encode()
        try { victim.decrypt(forge(ck2, cid2, 0, openPlain(ck0, cid, 0, f0)), 201); fail() } catch (_: AegisException) {}
        assertArrayEquals(again, victim.encode())
        assertEquals("new", victim.decrypt(next.encryptWith(seq(9, 12), SkScope.Channel, g, ownerSk, post("new")), 202).body)
    }

    private fun setBytes(magic: String, owner: ByteArray?, count: Int, v2Chain: Boolean?): ByteArray {
        val w = StateWriter().raw(Text.utf8(magic)).flag(false).raw(g).opt32(owner).u16(count)
        if (v2Chain != null) {
            w.raw(ByteArray(16) { 1 }).str("alice").raw(ownerEd).u32(0).raw(ByteArray(32) { 2 }).optU64(null).u16(0)
            if (v2Chain) w.u16(0)
        }
        return w.finish()
    }

    @Test
    fun groupSetRefusesOwnerKeyAndCapsChains() {
        try { RecvSet(SkScope.Group, g, ownerEd); fail() } catch (_: AegisException) {}
        try { RecvSet.decode(setBytes("AGK2", ownerEd, 1, true)); fail() } catch (_: AegisException) {}
        try { RecvSet.decode(setBytes("AGK2", null, 0xFFFF, null)); fail() } catch (_: AegisException) {}
        val v2 = setBytes("AGK2", null, 1, true)
        assertArrayEquals(v2, RecvSet.decode(v2).encode())
        assertArrayEquals(v2, RecvSet.decode(setBytes("AGK1", null, 1, false)).encode())
    }
}
