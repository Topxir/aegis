package org.aegis.messenger.core

/** Directory registration (spec section 3). */
class Registration(
    val u: String,
    val title: String,
    val x: ByteArray,
    val ed: ByteArray,
    val ts: Long,
    val sig: ByteArray,
    var pow: ULong = 0UL,
) {
    fun message(): ByteArray = signedMessage(u, title, Hex.encode(x), Hex.encode(ed), ts)

    fun bodyHash(): String = Pow.bodyHashHex(message())

    fun mine(bits: Int) {
        pow = Pow.mine(powScope(u), ts, bodyHash(), bits)
    }

    fun powOk(bits: Int): Boolean = Pow.verify(powScope(u), ts, bodyHash(), pow, bits)

    fun signatureOk(): Boolean = Crypto.ed25519Verify(ed, message(), sig)

    fun toForm(): String =
        "u=${Text.pctEncode(u)}&title=${Text.pctEncode(title)}&x=${Hex.encode(x)}&ed=${Hex.encode(ed)}" +
            "&ts=$ts&sig=${Hex.encode(sig)}&pow=$pow"

    companion object {
        const val MAX_TITLE_CHARS = 64

        fun isValidTitle(t: String): Boolean =
            t.codePointCount(0, t.length) <= MAX_TITLE_CHARS &&
                t.none { Character.getType(it) == Character.CONTROL.toInt() }

        fun signedMessage(u: String, title: String, xHex: String, edHex: String, ts: Long): ByteArray =
            Text.utf8("aegis-v2 dir\n$u\n$title\n$xHex\n$edHex\n$ts")

        fun powScope(u: String): String = "dir:$u"

        /** Signs a registration for [id]; pow stays zero until mined. */
        fun sign(id: Identity, u: String, title: String, ts: Long): Registration {
            if (!Names.isValidUsername(u)) throw AegisException.InvalidUsername()
            if (!isValidTitle(title)) throw AegisException.InvalidText()
            val msg = signedMessage(u, title, Hex.encode(id.xPublic), Hex.encode(id.edPublic), ts)
            return Registration(u, title, id.xPublic, id.edPublic, ts, id.sign(msg))
        }
    }
}
