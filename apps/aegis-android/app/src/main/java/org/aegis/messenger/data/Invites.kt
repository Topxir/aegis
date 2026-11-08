package org.aegis.messenger.data

import org.aegis.messenger.core.Bytes
import org.aegis.messenger.core.Envelope
import org.aegis.messenger.core.Invite
import org.aegis.messenger.core.Kind
import org.aegis.messenger.core.Text

/** An invite secret this user handed out, kept until it is used or expires. */
class OpenInvite(val secret: ByteArray, val expS: Long) {
    override fun toString(): String = "OpenInvite($expS)"
}

/** Vault rules for one-time invites (spec section 29). */
object Invites {
    enum class Pin { New, Known, Self, Conflict }

    /** Drops invites the server has dropped anyway; it rounds expiry up to the hour. */
    fun purge(d: VaultData, nowS: Long): VaultData {
        val keep = d.invites.filter { it.expS + 3600 > nowS }
        return if (keep.size == d.invites.size) d else d.copy(invites = keep)
    }

    /** Adds [secret] as an open invite, or null when too many are open. */
    fun open(d: VaultData, secret: ByteArray, nowS: Long): VaultData? {
        val p = purge(d, nowS)
        if (p.invites.size >= Invite.MAX_OPEN) return null
        return p.copy(invites = p.invites + OpenInvite(secret.copyOf(), nowS + Invite.TTL_SECS))
    }

    fun drop(d: VaultData, secret: ByteArray): VaultData =
        d.copy(invites = d.invites.filter { !Bytes.eq(it.secret, secret) })

    fun isOwn(d: VaultData, secret: ByteArray): Boolean = d.invites.any { Bytes.eq(it.secret, secret) }

    /** What a redeemed bundle means: a contact with other keys is never replaced. */
    fun pin(d: VaultData, b: Invite.Bundle, ownX: ByteArray, ownEd: ByteArray): Pin {
        if (b.u == d.username || Bytes.eq(b.x, ownX) || Bytes.eq(b.ed, ownEd)) return Pin.Self
        val c = d.contact(b.u)
        if (c != null) return if (Bytes.eq(c.x, b.x) && Bytes.eq(c.ed, b.ed)) Pin.Known else Pin.Conflict
        if (d.contacts.any { Bytes.eq(it.x, b.x) || Bytes.eq(it.ed, b.ed) }) return Pin.Conflict
        return Pin.New
    }

    /**
     * Applies an `iacc` opened with the sealed sender key [senderX]. Only a stranger proving one of
     * the open secrets is taken; that secret is used up. Returns the new vault and contact, or null.
     */
    fun accept(d: VaultData, env: Envelope, senderX: ByteArray, blocked: Boolean): Pair<VaultData, Contact>? {
        if (env.kind != Kind.Iacc || blocked || env.sender == d.username || d.contact(env.sender) != null) return null
        if (d.contacts.any { Bytes.eq(it.x, senderX) || Bytes.eq(it.ed, env.senderEd) }) return null
        val hit = d.invites.firstOrNull { Invite.checkAccept(it.secret, env.sender, senderX, env.senderEd, env.body) }
            ?: return null
        val c = Contact(env.sender, Text.sanitizeDisplay(env.senderName), senderX.copyOf(), env.senderEd.copyOf())
        return d.copy(invites = d.invites.filter { it !== hit }).withContact(c) to c
    }
}
