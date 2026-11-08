package org.aegis.messenger.core

/**
 * One-time invites and the hidden-profile switch (spec section 29).
 *
 * The server keeps only `id = SHA256("aegis-v2 invite-id" || s)` and a box it cannot open; the
 * link carries the 32-byte secret `s`.
 */
object Invite {
    const val TTL_SECS = 7L * 24 * 3600
    const val MAX_OPEN = 10
    const val PLAIN_LEN = 160
    const val BOX_LEN = PLAIN_LEN + 16
    const val LINK_PREFIX = "aegis://invite/"
    private const val MAGIC = "AIV1"

    /** What an invite hands out: the inviter's name and keys. */
    class Bundle(val u: String, val x: ByteArray, val ed: ByteArray) {
        override fun toString(): String = "Bundle($u)"
    }

    fun id(s: ByteArray): ByteArray = Crypto.sha256(Text.utf8("aegis-v2 invite-id"), s)

    private fun boxKey(s: ByteArray) = Crypto.hkdf32(s, ByteArray(0), Text.utf8("aegis-v2 invite-key"))

    fun seal(s: ByteArray, b: Bundle): ByteArray {
        if (!Names.isValidUsername(b.u)) throw AegisException.InvalidUsername()
        val text = Text.utf8("$MAGIC\n${b.u}\n${Hex.encode(b.x)}\n${Hex.encode(b.ed)}")
        val plain = ByteArray(PLAIN_LEN)
        text.copyInto(plain)
        val key = boxKey(s)
        // One message per key, so the fixed nonce is safe.
        return try {
            Crypto.aeadSeal(key, ByteArray(12), id(s), plain)
        } finally {
            key.fill(0)
            plain.fill(0)
        }
    }

    fun open(s: ByteArray, sealed: ByteArray): Bundle {
        if (sealed.size != BOX_LEN) throw AegisException.Length()
        val key = boxKey(s)
        val plain = try {
            Crypto.aeadOpen(key, ByteArray(12), id(s), sealed)
        } finally {
            key.fill(0)
        }
        try {
            var end = plain.indexOfFirst { it.toInt() == 0 }
            if (end < 0) end = plain.size
            for (i in end until plain.size) if (plain[i].toInt() != 0) throw AegisException.InvalidText()
            val f = Text.utf8Strict(plain.copyOf(end)).split('\n')
            if (f.size != 4 || f[0] != MAGIC || !Names.isValidUsername(f[1])) throw AegisException.InvalidText()
            if (!Hex.isHexLen(f[2], 32) || !Hex.isHexLen(f[3], 32)) throw AegisException.InvalidHex()
            return Bundle(f[1], Hex.decode(f[2]), Hex.decode(f[3]))
        } finally {
            plain.fill(0)
        }
    }

    /** `HKDF(s, info = "aegis-v2 invite-accept\n" u "\n" x "\n" ed)`. */
    fun acceptTag(s: ByteArray, u: String, x: ByteArray, ed: ByteArray): ByteArray =
        Crypto.hkdf32(s, ByteArray(0), Text.utf8("aegis-v2 invite-accept\n$u\n${Hex.encode(x)}\n${Hex.encode(ed)}"))

    private fun acceptMessage(u: String, x: ByteArray, tag: ByteArray) =
        Text.utf8("aegis-v2 invite-accept-sig\n$u\n${Hex.encode(x)}\n${Hex.encode(tag)}")

    /** Body of an `iacc` envelope: hex of tag || Ed25519 signature. */
    fun acceptBody(id: Identity, s: ByteArray, u: String): String {
        val tag = acceptTag(s, u, id.xPublic, id.edPublic)
        return Hex.encode(tag + id.sign(acceptMessage(u, id.xPublic, tag)))
    }

    fun checkAccept(s: ByteArray, u: String, x: ByteArray, ed: ByteArray, body: String): Boolean {
        if (!Hex.isHexLen(body, 96)) return false
        val raw = Hex.decode(body)
        val tag = acceptTag(s, u, x, ed)
        val tagOk = java.security.MessageDigest.isEqual(raw.copyOf(32), tag)
        return tagOk and Crypto.ed25519Verify(ed, acceptMessage(u, x, tag), raw.copyOfRange(32, 96))
    }

    fun link(s: ByteArray): String = LINK_PREFIX + Hex.encode(s)

    /** Reads a pasted or opened link; white space around it and letter case are ignored. */
    fun parseLink(text: String): ByteArray {
        val t = text.trim()
        val n = LINK_PREFIX.length
        if (t.length != n + 64 || !t.substring(0, n).equals(LINK_PREFIX, ignoreCase = true)) {
            throw AegisException.InvalidText()
        }
        val h = t.substring(n)
        if (!h.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw AegisException.InvalidHex()
        return Hex.decode(h.lowercase())
    }

    fun createMessage(u: String, idHex: String, boxHex: String, ts: Long): ByteArray =
        Text.utf8("aegis-v2 invite\n$u\n$idHex\n$boxHex\n$ts")

    /** Form body of `invite/create`. */
    fun createForm(identity: Identity, u: String, s: ByteArray, ts: Long): String {
        val idHex = Hex.encode(id(s))
        val boxHex = Hex.encode(seal(s, Bundle(u, identity.xPublic, identity.edPublic)))
        val sig = identity.sign(createMessage(u, idHex, boxHex, ts))
        return "u=${Text.pctEncode(u)}&id=$idHex&box=$boxHex&ts=$ts&sig=${Hex.encode(sig)}"
    }

    /** Body of `invite/redeem` and `invite/revoke`. */
    fun idForm(s: ByteArray): String = "id=" + Hex.encode(id(s))

    fun hideMessage(u: String, hidden: Boolean, ts: Long): ByteArray =
        Text.utf8("aegis-v2 hide\n$u\n${if (hidden) 1 else 0}\n$ts")

    /** Form body of `dir/hide`. */
    fun hideForm(identity: Identity, u: String, hidden: Boolean, ts: Long): String {
        if (!Names.isValidUsername(u)) throw AegisException.InvalidUsername()
        val sig = identity.sign(hideMessage(u, hidden, ts))
        return "u=${Text.pctEncode(u)}&hidden=${if (hidden) 1 else 0}&ts=$ts&sig=${Hex.encode(sig)}"
    }
}
