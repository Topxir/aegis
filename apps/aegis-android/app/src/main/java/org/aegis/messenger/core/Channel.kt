package org.aegis.messenger.core

/** Channels: broadcast groups where only the owner posts (spec section 15). */
object Channel {
    const val MAX_SUBSCRIBERS = 200

    fun newSecret(): ByteArray = Crypto.randomBytes(32)

    fun channelId(g: ByteArray): String = Hex.encode(Crypto.sha256(Text.utf8("aegis-v2 channel-id"), g))

    fun queue(g: ByteArray): ByteArray = QueueIds.channel(g)

    fun msgKey(g: ByteArray): ByteArray = Crypto.hkdf32(g, ByteArray(0), Text.utf8("aegis-v2 channel-msg"))

    fun sealPost(g: ByteArray, ownerEdSk: ByteArray, env: Envelope): ByteArray =
        sealPostWith(Crypto.randomBytes(12), g, ownerEdSk, env)

    fun sealPostWith(nonce: ByteArray, g: ByteArray, ownerEdSk: ByteArray, env: Envelope): ByteArray {
        if (env.kind != Kind.Cmsg && env.kind != Kind.Cmf) throw AegisException.BadFrameType()
        val k = msgKey(g)
        try {
            return SignedFrame.seal(k, channelId(g), nonce, ownerEdSk, env)
        } finally {
            k.fill(0)
        }
    }

    /**
     * Accepts a frame only if it is a cmsg or cmf of this channel whose sender is [owner], whose
     * sender_ed equals the pinned [ownerEdPk], and whose signature verifies.
     */
    fun openPost(g: ByteArray, owner: String, ownerEdPk: ByteArray, frame: ByteArray): Envelope {
        val k = msgKey(g)
        val env = try {
            SignedFrame.open(k, frame)
        } finally {
            k.fill(0)
        }
        if (env.kind != Kind.Cmsg && env.kind != Kind.Cmf) throw AegisException.BadFrameType()
        if (env.groupId != channelId(g)) throw AegisException.GroupMismatch()
        if (env.sender != owner || !Bytes.eq(env.senderEd, ownerEdPk)) throw AegisException.SenderMismatch()
        return env
    }
}

/** The built-in official channel (spec section 19): channel framing with a public secret. */
object Official {
    const val OWNER = "owner"
    /** Owner key compiled into the build; never taken from the directory or the server (spec section 19). */
    val OWNER_ED_PK: ByteArray? = Hex.decode("9b714d3e9f6b7d248a15c7302d3b1ff391ca416c98ccc935bb4349f00eec5884")

    val available: Boolean get() = OWNER_ED_PK != null

    /** Opens a post against the compiled-in key only; fails while none is compiled in. */
    fun verify(frame: ByteArray): Envelope =
        openPost(OWNER_ED_PK ?: throw AegisException.InvalidEnvelope("no official owner key"), frame)

    fun g(): ByteArray = Crypto.sha256(Text.utf8("aegis-v2 official-channel"))
    fun channelId(): String = Channel.channelId(g())
    fun queue(): ByteArray = Channel.queue(g())
    fun openPost(ownerEdPk: ByteArray, frame: ByteArray): Envelope = Channel.openPost(g(), OWNER, ownerEdPk, frame)
}

/** Default avatars generated from the identity key (spec section 17). */
class Avatar(val cells: Array<BooleanArray>, val bg: Int, val fg: Int) {
    fun maskString(): String = buildString { for (r in cells) for (c in r) append(if (c) '1' else '0') }

    companion object {
        fun fromEdPk(edPk: ByteArray): Avatar {
            val h = Crypto.sha256(Text.utf8("aegis-v2 avatar"), edPk)
            val cells = Array(5) { BooleanArray(5) }
            for (r in 0 until 5) for (c in 0 until 3) {
                val k = r * 3 + c
                val on = ((h[k / 8].toInt() and 0xFF) shr (k % 8)) and 1 == 1
                cells[r][c] = on
                cells[r][4 - c] = on
            }
            return Avatar(cells, 0x1c + (h[2].toInt() and 0xFF) % 0x18, 0xa0 + (h[3].toInt() and 0xFF) % 0x50)
        }
    }
}

enum class Particles(val wire: String) {
    None("none"), Dust("dust"), Snow("snow"), Embers("embers"), Orbit("orbit"), Rain("rain");

    companion object {
        fun parse(s: String): Particles = values().firstOrNull { it.wire == s }
            ?: throw AegisException.InvalidEnvelope("particles")
    }
}

/** Profile card body, PF1 (spec section 22). */
class Profile(val name: String, val about: String, val particles: Particles) {
    private fun check(s: String, max: Int, what: String) {
        if (s.codePointCount(0, s.length) > max || s.codePoints().anyMatch { Character.isISOControl(it) || Text.isSpoofing(it) }) {
            throw AegisException.InvalidEnvelope(what)
        }
    }

    private fun validate() {
        check(name, MAX_NAME, "profile name")
        check(about, MAX_ABOUT, "profile about")
    }

    fun encode(): String {
        validate()
        return "PF1\n$name\n$about\n${particles.wire}"
    }

    companion object {
        const val MAX_NAME = 64
        const val MAX_ABOUT = 140

        fun parse(body: String): Profile {
            val l = body.split('\n')
            if (l.size != 4) throw AegisException.InvalidEnvelope("profile lines")
            if (l[0] != "PF1") throw AegisException.InvalidEnvelope("profile header")
            val p = Profile(l[1], l[2], Particles.parse(l[3]))
            p.validate()
            return p
        }
    }
}
