package org.aegis.messenger.core

/** Direct messages and group invites: frame type 0x01 (spec section 6). */
object Seal {
    const val FRAME_SEAL: Byte = 0x01
    private const val C1_LEN = 32 + 16
    private const val MIN_LEN = 1 + 32 + C1_LEN + 16
    private val ZERO_NONCE = ByteArray(12)
    private val INFO1 = Text.utf8("aegis-v2 seal-1")
    private val INFO2 = Text.utf8("aegis-v2 seal-2")

    class Opened(val senderXPk: ByteArray, val envelope: Envelope)

    fun sealDm(senderXSk: ByteArray, recipientXPk: ByteArray, env: Envelope): ByteArray =
        sealDmWith(Crypto.randomBytes(32), senderXSk, recipientXPk, env)

    /** Deterministic variant of [sealDm] with an injected ephemeral secret. */
    fun sealDmWith(eSk: ByteArray, senderXSk: ByteArray, recipientXPk: ByteArray, env: Envelope): ByteArray {
        if (env.kind == Kind.Gmsg) throw AegisException.BadFrameType()
        val plain = env.encode()
        val ePk = Crypto.x25519Public(eSk)
        val sPk = Crypto.x25519Public(senderXSk)
        val dh1 = Crypto.dh(eSk, recipientXPk)
        val dh2 = Crypto.dh(senderXSk, recipientXPk)
        val salt = Bytes.concat(ePk, recipientXPk)
        val k1 = Crypto.hkdf32(dh1, salt, INFO1)
        val aad1 = Bytes.concat(byteArrayOf(FRAME_SEAL), ePk)
        val c1 = Crypto.aeadSeal(k1, ZERO_NONCE, aad1, sPk)
        val k2 = Crypto.hkdf32(Bytes.concat(dh1, dh2), salt, INFO2)
        val aad2 = Bytes.concat(aad1, c1)
        val c2 = Crypto.aeadSeal(k2, ZERO_NONCE, aad2, plain)
        listOf(dh1, dh2, k1, k2, plain).forEach { it.fill(0) }
        return Bytes.concat(aad2, c2)
    }

    /** Opens a type 0x01 frame addressed to the owner of [recipientXSk]. */
    fun openDm(recipientXSk: ByteArray, frame: ByteArray): Opened {
        if (frame.size < MIN_LEN) throw AegisException.Length()
        if (frame[0] != FRAME_SEAL) throw AegisException.BadFrameType()
        val ePk = frame.copyOfRange(1, 33)
        val c1 = frame.copyOfRange(33, 33 + C1_LEN)
        val c2 = frame.copyOfRange(33 + C1_LEN, frame.size)
        val rPk = Crypto.x25519Public(recipientXSk)
        val salt = Bytes.concat(ePk, rPk)
        val dh1 = Crypto.dh(recipientXSk, ePk)
        val k1 = Crypto.hkdf32(dh1, salt, INFO1)
        val aad1 = Bytes.concat(byteArrayOf(FRAME_SEAL), ePk)
        val sPk = Crypto.aeadOpen(k1, ZERO_NONCE, aad1, c1)
        if (sPk.size != 32) throw AegisException.Length()
        val dh2 = Crypto.dh(recipientXSk, sPk)
        val k2 = Crypto.hkdf32(Bytes.concat(dh1, dh2), salt, INFO2)
        val plain = Crypto.aeadOpen(k2, ZERO_NONCE, Bytes.concat(aad1, c1), c2)
        listOf(dh1, dh2, k1, k2).forEach { it.fill(0) }
        try {
            val env = Envelope.decode(plain)
            if (env.kind == Kind.Gmsg) throw AegisException.BadFrameType()
            return Opened(sPk, env)
        } finally {
            plain.fill(0)
        }
    }
}

/** Queue id derivations. */
object QueueIds {
    fun inbox(xPk: ByteArray): ByteArray = Crypto.sha256(Text.utf8("aegis-v2 inbox"), xPk)
    fun group(g: ByteArray): ByteArray = Crypto.hkdf32(g, ByteArray(0), Text.utf8("aegis-v2 group-queue"))
}

/** Group messages: frame type 0x02 (spec section 7). */
object Group {
    const val FRAME_GROUP: Byte = 0x02

    fun newSecret(): ByteArray = Crypto.randomBytes(32)

    fun groupId(g: ByteArray): String = Hex.encode(Crypto.sha256(Text.utf8("aegis-v2 group-id"), g))

    private fun msgKey(g: ByteArray): ByteArray = Crypto.hkdf32(g, ByteArray(0), Text.utf8("aegis-v2 group-msg"))

    private fun sigInput(envelope: ByteArray): ByteArray = Bytes.concat(Text.utf8("aegis-v2 gmsg\n"), envelope)

    fun encrypt(g: ByteArray, edSk: ByteArray, env: Envelope): ByteArray =
        encryptWith(Crypto.randomBytes(12), g, edSk, env)

    /** Deterministic variant of [encrypt] with an injected nonce. */
    fun encryptWith(nonce: ByteArray, g: ByteArray, edSk: ByteArray, env: Envelope): ByteArray {
        if (env.kind != Kind.Gmsg) throw AegisException.BadFrameType()
        if (env.groupId != groupId(g)) throw AegisException.GroupMismatch()
        if (!Bytes.eq(env.senderEd, Crypto.ed25519Public(edSk))) throw AegisException.SenderMismatch()
        val bytes = env.encode()
        val sig = Crypto.ed25519Sign(edSk, sigInput(bytes))
        val plain = Bytes.concat(bytes, sig)
        val k = msgKey(g)
        val ct = Crypto.aeadSeal(k, nonce, byteArrayOf(FRAME_GROUP), plain)
        k.fill(0)
        plain.fill(0)
        return Bytes.concat(byteArrayOf(FRAME_GROUP), nonce, ct)
    }

    /** Decrypts a type 0x02 frame from the queue of group [g] and verifies the envelope signature. */
    fun decrypt(g: ByteArray, frame: ByteArray): Envelope {
        if (frame.size < 1 + 12 + 16 + 64) throw AegisException.Length()
        if (frame[0] != FRAME_GROUP) throw AegisException.BadFrameType()
        val nonce = frame.copyOfRange(1, 13)
        val k = msgKey(g)
        val plain = try {
            Crypto.aeadOpen(k, nonce, byteArrayOf(FRAME_GROUP), frame.copyOfRange(13, frame.size))
        } finally {
            k.fill(0)
        }
        try {
            if (plain.size < 64) throw AegisException.Length()
            val body = plain.copyOfRange(0, plain.size - 64)
            val sig = plain.copyOfRange(plain.size - 64, plain.size)
            val env = Envelope.decode(body)
            if (env.kind != Kind.Gmsg) throw AegisException.BadFrameType()
            if (env.groupId != groupId(g)) throw AegisException.GroupMismatch()
            if (!Crypto.ed25519Verify(env.senderEd, sigInput(body), sig)) throw AegisException.BadSignature()
            return env
        } finally {
            plain.fill(0)
        }
    }
}
