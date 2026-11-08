package org.aegis.messenger.data

import org.aegis.messenger.core.Envelope
import org.aegis.messenger.core.Identity
import org.aegis.messenger.core.Invite
import org.aegis.messenger.core.Kind
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Vault side of invite links (spec section 29). */
class InvitesTest {
    private val alice = Identity(ByteArray(32) { 1 }, ByteArray(32) { 2 })
    private val bob = Identity(ByteArray(32) { 3 }, ByteArray(32) { 4 })
    private val carol = Identity(ByteArray(32) { 5 }, ByteArray(32) { 6 })
    private val s = ByteArray(32) { 0x11 }
    private val now = 1_700_000_000L

    private fun vault(u: String, id: Identity) = VaultData(u, id.xSecret, id.edSecret)

    private fun iacc(from: Identity, u: String, secret: ByteArray, msgId: String = "00112233445566778899aabbccddeeff") =
        Envelope(Kind.Iacc, msgId, u, "Bob", from.edPublic, now * 1000, 0, "", Invite.acceptBody(from, secret, u))

    @Test
    fun openRespectsTheCapAndExpiry() {
        var d = vault("alice", alice)
        repeat(Invite.MAX_OPEN) { i -> d = Invites.open(d, ByteArray(32) { i.toByte() }, now)!! }
        assertNull(Invites.open(d, ByteArray(32) { 99 }, now))
        val later = now + Invite.TTL_SECS + 3600
        assertEquals(0, Invites.purge(d, later).invites.size)
        assertNotNull(Invites.open(d, ByteArray(32) { 99 }, later))
        assertEquals(Invite.MAX_OPEN - 1, Invites.drop(d, ByteArray(32) { 0 }).invites.size)
        assertTrue(Invites.isOwn(d, ByteArray(32) { 3 }))
        assertFalse(Invites.isOwn(d, ByteArray(32) { 42 }))
    }

    @Test
    fun invitesSurviveTheVaultCodec() {
        val d = Invites.open(vault("alice", alice), s, now)!!
        val back = VaultCodec.decode(VaultCodec.encode(d.copy(settings = d.settings.copy(hidden = true))))
        assertEquals(1, back.invites.size)
        assertArrayEquals(s, back.invites[0].secret)
        assertEquals(now + Invite.TTL_SECS, back.invites[0].expS)
        assertTrue(back.settings.hidden)
        assertFalse(VaultCodec.decode(VaultCodec.encode(vault("bob", bob))).settings.hidden)
    }

    @Test
    fun redeemedBundleNeverReplacesAContact() {
        val d = vault("bob", bob)
        val b = Invite.Bundle("alice", alice.xPublic, alice.edPublic)
        assertEquals(Invites.Pin.New, Invites.pin(d, b, bob.xPublic, bob.edPublic))
        val known = d.withContact(Contact("alice", "", alice.xPublic, alice.edPublic))
        assertEquals(Invites.Pin.Known, Invites.pin(known, b, bob.xPublic, bob.edPublic))
        val other = d.withContact(Contact("alice", "", carol.xPublic, carol.edPublic))
        assertEquals(Invites.Pin.Conflict, Invites.pin(other, b, bob.xPublic, bob.edPublic))
        val sameKeys = d.withContact(Contact("mallory", "", alice.xPublic, carol.edPublic))
        assertEquals(Invites.Pin.Conflict, Invites.pin(sameKeys, b, bob.xPublic, bob.edPublic))
        assertEquals(Invites.Pin.Self, Invites.pin(d, Invite.Bundle("bob", alice.xPublic, alice.edPublic), bob.xPublic, bob.edPublic))
        assertEquals(Invites.Pin.Self, Invites.pin(d, Invite.Bundle("eve", bob.xPublic, alice.edPublic), bob.xPublic, bob.edPublic))
    }

    @Test
    fun acceptPinsTheRedeemerOnceAndUsesTheSecret() {
        val d = Invites.open(vault("alice", alice), s, now)!!
        val r = Invites.accept(d, iacc(bob, "bob", s), bob.xPublic, false)!!
        assertEquals("bob", r.second.username)
        assertEquals("Bob", r.second.title)
        assertArrayEquals(bob.xPublic, r.first.contact("bob")!!.x)
        assertEquals(0, r.first.invites.size)
        // The same secret is gone, and a known contact is never re-pinned.
        assertNull(Invites.accept(r.first, iacc(bob, "bob", s, "ffeeddccbbaa99887766554433221100"), bob.xPublic, false))
    }

    @Test
    fun acceptDropsEverythingElse() {
        val d = Invites.open(vault("alice", alice), s, now)!!
        val good = iacc(bob, "bob", s)
        assertNull(Invites.accept(d, good, bob.xPublic, true))
        assertNull(Invites.accept(d, good, carol.xPublic, false))
        assertNull(Invites.accept(d, iacc(bob, "bob", ByteArray(32) { 0x12 }), bob.xPublic, false))
        assertNull(Invites.accept(d, iacc(alice, "alice", s), alice.xPublic, false))
        val withCarol = d.withContact(Contact("carol", "", bob.xPublic, carol.edPublic))
        assertNull(Invites.accept(withCarol, good, bob.xPublic, false))
        val dm = Envelope(Kind.Dm, good.msgId, "bob", "", bob.edPublic, now * 1000, 0, "", "hi")
        assertNull(Invites.accept(d, dm, bob.xPublic, false))
        assertEquals(1, d.invites.size)
    }
}
