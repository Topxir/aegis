package org.aegis.messenger.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Invite links (spec section 30). The vectors are shared with crates/aegis-core/tests/invite.rs. */
class InviteTest {
    private val s = ByteArray(32) { 0x11 }
    private val alice = Identity(ByteArray(32) { 1 }, ByteArray(32) { 2 })
    private val bob = Identity(ByteArray(32) { 3 }, ByteArray(32) { 4 })

    private val id = "1a86791297c6f73dc95d866dd901c213c1d10cb112e5d85f4906291ba4ecc030"
    private val box = "764bcc5e512e703c9c11bdf08bf54db1d89b40176a2bb5053ffd460e258f58c3f4fbd42e7c8b77cd41e769c4c26c1ec53c0837ae8de8f02715b051e582ac81b30d35fd352509605c24750e7c7d12fd8fd7d6499634de8499362c76c0ccb878fe4d59d29c77e2c6a0dff0cca56d588f31cf09e7addd0be86ba723a4c59d9ebe9a493937d6a131c518fbe17cabca3db88d471bdab54a8c7436aff76edd953ceaac0d19f106e73666c9943301ac4afd36d5"
    private val tag = "04abbf161426f4d264813bc5d84417ec4c1c0f3598b3674605009d84043ea5b8"
    private val body = "04abbf161426f4d264813bc5d84417ec4c1c0f3598b3674605009d84043ea5b87947973b5aa61ee565e1f5e95b363792a58224f7ae2bb265cf68b6e24874fa3b085b80d7078f6c10bbb2c725842c0d3df4972c07313e1399eede224bbd0a8202"

    private fun aliceBundle() = Invite.Bundle("alice", alice.xPublic, alice.edPublic)

    @Test
    fun vectors() {
        assertEquals(id, Hex.encode(Invite.id(s)))
        assertEquals(box, Hex.encode(Invite.seal(s, aliceBundle())))
        assertEquals(tag, Hex.encode(Invite.acceptTag(s, "bob", bob.xPublic, bob.edPublic)))
        assertEquals(body, Invite.acceptBody(bob, s, "bob"))
    }

    @Test
    fun bundleOpensOnlyWithItsSecret() {
        val sealed = Hex.decode(box)
        val b = Invite.open(s, sealed)
        assertEquals("alice", b.u)
        assertArrayEquals(alice.xPublic, b.x)
        assertArrayEquals(alice.edPublic, b.ed)
        val bad = sealed.copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        for (attempt in listOf<() -> Unit>(
            { Invite.open(ByteArray(32) { 0x12 }, sealed) },
            { Invite.open(s, bad) },
            { Invite.open(s, sealed.copyOf(Invite.BOX_LEN - 1)) },
        )) {
            try { attempt(); fail("opened") } catch (_: AegisException) {}
        }
        val long = Invite.Bundle("a".repeat(24), alice.xPublic, alice.edPublic)
        assertEquals(Invite.BOX_LEN, Invite.seal(s, long).size)
    }

    @Test
    fun linksRoundTripAndRejectJunk() {
        val l = Invite.link(s)
        assertEquals("aegis://invite/" + Hex.encode(s), l)
        assertArrayEquals(s, Invite.parseLink(l))
        assertArrayEquals(s, Invite.parseLink("  ${l.uppercase()}\n"))
        for (bad in listOf("", "aegis://invite/", "aegis://invite/zz", "https://invite/1111", l.dropLast(1), l + "0", "$l?x")) {
            try { Invite.parseLink(bad); fail(bad) } catch (_: AegisException) {}
        }
    }

    @Test
    fun acceptProvesTheSecretAndTheKey() {
        val x = bob.xPublic
        val ed = bob.edPublic
        assertTrue(Invite.checkAccept(s, "bob", x, ed, body))
        assertFalse(Invite.checkAccept(ByteArray(32) { 0x12 }, "bob", x, ed, body))
        assertFalse(Invite.checkAccept(s, "carol", x, ed, body))
        assertFalse(Invite.checkAccept(s, "bob", alice.xPublic, ed, body))
        assertFalse(Invite.checkAccept(s, "bob", x, alice.edPublic, body))
        val forged = tag + Hex.encode(alice.sign(Text.utf8("anything")))
        assertFalse(Invite.checkAccept(s, "bob", x, ed, forged))
        assertFalse(Invite.checkAccept(s, "bob", x, ed, body.substring(0, 64)))
        assertFalse(Invite.checkAccept(s, "bob", x, ed, ""))
    }

    @Test
    fun iaccEnvelopeCarriesOnlyTheProof() {
        val env = Envelope(Kind.Iacc, "00112233445566778899aabbccddeeff", "bob", "", bob.edPublic, 1_700_000_000_000, 0, "", body)
        val back = Envelope.decode(env.encode())
        assertEquals(Kind.Iacc, back.kind)
        assertEquals(body, back.body)
        assertEquals(0x01.toByte(), Kind.Iacc.frameType)
        try {
            Envelope(Kind.Iacc, env.msgId, "bob", "", bob.edPublic, 1, 0, "", tag).encode(); fail()
        } catch (_: AegisException.InvalidEnvelope) {}
        try {
            Envelope(Kind.Iacc, env.msgId, "bob", "", bob.edPublic, 1, 0, "", body, members = listOf("alice")).encode(); fail()
        } catch (_: AegisException.InvalidEnvelope) {}
    }

    @Test
    fun signedFormsMatchTheServer() {
        val f = Invite.createForm(alice, "alice", s, 1_700_000_000)
        val p = f.split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
        assertEquals(listOf("u", "id", "box", "ts", "sig"), p.keys.toList())
        assertEquals(id, p["id"])
        val msg = Invite.createMessage("alice", id, p["box"]!!, 1_700_000_000)
        assertTrue(Crypto.ed25519Verify(alice.edPublic, msg, Hex.decode(p["sig"]!!)))
        val h = Invite.hideForm(alice, "alice", true, 5)
        assertTrue(h.startsWith("u=alice&hidden=1&ts=5&sig="))
        val sig = Hex.decode(h.substringAfter("sig="))
        assertTrue(Crypto.ed25519Verify(alice.edPublic, Invite.hideMessage("alice", true, 5), sig))
        assertFalse(Crypto.ed25519Verify(alice.edPublic, Invite.hideMessage("alice", false, 5), sig))
        assertEquals("id=$id", Invite.idForm(s))
        assertEquals("u=bob&ts=1&pow=2&ed=" + Hex.encode(bob.edPublic), Prekeys.takeForm("bob", 1, 2UL, bob.edPublic))
        assertEquals("u=bob&ts=1&pow=2", Prekeys.takeForm("bob", 1, 2UL))
    }
}
