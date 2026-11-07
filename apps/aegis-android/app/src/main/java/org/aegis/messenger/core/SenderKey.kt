package org.aegis.messenger.core

enum class SkScope {
    Group, Channel;

    fun id(g: ByteArray): String = if (this == Group) org.aegis.messenger.core.Group.groupId(g) else org.aegis.messenger.core.Channel.channelId(g)
    fun allows(k: Kind): Boolean = when (this) {
        Group -> k == Kind.Gmsg || k == Kind.Gmf
        Channel -> k == Kind.Cmsg || k == Kind.Cmf
    }
}

/** Sender keys for groups and channels: frame type 0x05 (spec section 28). */
object SenderKey {
    const val FRAME: Byte = 0x05
    const val ROTATE_AFTER_SECS = 7L * 24 * 3600
    const val ROTATE_AFTER_MESSAGES = 1000L
    const val MAX_SKIPPED = 2000
    const val SKIPPED_TTL_SECS = 30L * 24 * 3600
    const val OLD_CHAIN_KEEP_SECS = 30L * 24 * 3600
    const val HDR_LEN = 12 + 16 + 4 + 16
    const val MAX_CHAINS_PER_SENDER = 8
    const val MAX_CHAINS = 1000
    const val MAX_SEEN_PER_CHAIN = 2 * ROTATE_AFTER_MESSAGES.toInt()

    internal fun headerKey(g: ByteArray) = Crypto.hkdf32(g, ByteArray(0), Text.utf8("aegis-v2 group-hdr"))
    internal fun sigInput(envelope: ByteArray) = Bytes.concat(Text.utf8("aegis-v2 gmsg\n"), envelope)
    internal fun chainAad(chainId: ByteArray, n: Long): ByteArray {
        val nb = ByteArray(4)
        Bytes.putBe32(nb, 0, n)
        return Bytes.concat(byteArrayOf(FRAME), chainId, nb)
    }
}

/** Our own sending chain for one group or channel. */
class SendChain(val chainId: ByteArray, var n: Long, private var ck: ByteArray, val createdAt: Long) {
    companion object {
        fun create(now: Long) = createWith(Crypto.randomBytes(16), Crypto.randomBytes(32), now)
        fun createWith(chainId: ByteArray, ck: ByteArray, now: Long) = SendChain(chainId.copyOf(), 0, ck.copyOf(), now)

        fun decode(bytes: ByteArray): SendChain {
            val r = StateReader(bytes)
            r.magic("AGC1")
            val s = SendChain(r.take(16), r.u32(), r.take(32), r.u64())
            r.end()
            return s
        }
    }

    /** True after 7 days or 1000 messages, or when a member was removed. */
    fun needsRotation(now: Long, memberRemoved: Boolean): Boolean =
        memberRemoved || n >= SenderKey.ROTATE_AFTER_MESSAGES || now >= createdAt + SenderKey.ROTATE_AFTER_SECS

    /** The skey envelope that gives the current state of this chain to one recipient. */
    fun skeyEnvelopeWith(msgId: String, sender: String, senderName: String, senderEd: ByteArray, groupId: String, tsMs: Long) =
        Envelope(Kind.Skey, msgId, sender, senderName, senderEd, tsMs, 0, groupId, Hex.encode(chainId) + ":" + n, ck.copyOf())

    fun skeyEnvelope(sender: String, senderName: String, senderEd: ByteArray, groupId: String, tsMs: Long) =
        skeyEnvelopeWith(Hex.encode(Crypto.randomBytes(16)), sender, senderName, senderEd, groupId, tsMs)

    fun encrypt(scope: SkScope, g: ByteArray, edSk: ByteArray, env: Envelope): ByteArray =
        encryptWith(Crypto.randomBytes(12), scope, g, edSk, env)

    /** Encrypts [env] as a type 0x05 frame and advances the chain. On error the chain is unchanged. */
    fun encryptWith(hnonce: ByteArray, scope: SkScope, g: ByteArray, edSk: ByteArray, env: Envelope): ByteArray {
        if (!scope.allows(env.kind)) throw AegisException.BadFrameType()
        if (env.groupId != scope.id(g)) throw AegisException.GroupMismatch()
        if (!Bytes.eq(env.senderEd, Crypto.ed25519Public(edSk))) throw AegisException.SenderMismatch()
        if (n >= 0xFFFFFFFFL) throw AegisException.Session("chain exhausted")
        val (mk, nextCk) = Kdf.ck(ck)
        val (key, nonce) = Kdf.msgKey(mk, "aegis-v2 group-key")
        val bytes = env.encode()
        val sig = Crypto.ed25519Sign(edSk, SenderKey.sigInput(bytes))
        val plain = Bytes.concat(bytes, sig)
        val aad = SenderKey.chainAad(chainId, n)
        val hdr = Crypto.aeadSeal(SenderKey.headerKey(g), hnonce, byteArrayOf(SenderKey.FRAME), aad.copyOfRange(1, aad.size))
        val ct = Crypto.aeadSeal(key, nonce, aad, plain)
        n++
        ck = nextCk
        return Bytes.concat(byteArrayOf(SenderKey.FRAME), hnonce, hdr, ct)
    }

    fun encode(): ByteArray = StateWriter().raw(Text.utf8("AGC1")).raw(chainId).u32(n).raw(ck).u64(createdAt).finish()
}

private class RecvChain(
    val chainId: ByteArray,
    val sender: String,
    val senderEd: ByteArray,
    var nextN: Long,
    var ck: ByteArray,
    val skipped: MutableList<Triple<Long, ByteArray, Long>>,
    var supersededAt: Long?,
    val seen: ArrayDeque<String> = ArrayDeque(),
) {
    fun copy() = RecvChain(chainId, sender, senderEd, nextN, ck, skipped.toMutableList(), supersededAt, ArrayDeque(seen))

    /** Key and nonce for message n, advancing the chain and storing skipped keys. */
    fun takeKey(n: Long, now: Long): Pair<ByteArray, ByteArray> {
        if (n < nextN) {
            val i = skipped.indexOfFirst { it.first == n }
            if (i < 0) throw AegisException.Session("message key already used")
            val mk = skipped.removeAt(i).second
            return Kdf.msgKey(mk, "aegis-v2 group-key")
        }
        if (skipped.size + (n - nextN) > SenderKey.MAX_SKIPPED) throw AegisException.Session("too many skipped messages")
        while (nextN < n) {
            val (mk, next) = Kdf.ck(ck)
            skipped.add(Triple(nextN, mk, now))
            ck = next
            nextN++
        }
        val (mk, next) = Kdf.ck(ck)
        ck = next
        nextN = n + 1
        return Kdf.msgKey(mk, "aegis-v2 group-key")
    }
}

/** The receive side for one group or channel: every sender's chain. */
class RecvSet(val scope: SkScope, g: ByteArray, private val ownerEd: ByteArray?) {
    private val g = g.copyOf()
    private val hk = SenderKey.headerKey(g)
    private val chains = ArrayList<RecvChain>()

    init {
        if (scope == SkScope.Channel && ownerEd == null) throw AegisException.Session("channel needs an owner key")
        if (scope == SkScope.Group && ownerEd != null) throw AegisException.Session("group has no owner key")
    }

    val chainCount: Int get() = chains.size

    /** Registers the chain of an skey envelope that arrived through the pairwise session of env.sender. */
    fun addFromSkey(env: Envelope, now: Long) {
        if (env.kind != Kind.Skey || env.groupId != scope.id(g)) throw AegisException.GroupMismatch()
        val (chainId, n) = parseSkeyBody(env.body)
        val ck = env.groupKey ?: throw AegisException.InvalidEnvelope("skey key")
        addChain(env.sender, env.senderEd, chainId, n, ck, now)
    }

    fun addChain(sender: String, senderEd: ByteArray, chainId: ByteArray, n: Long, ck: ByteArray, now: Long) {
        if (Text.utf8(sender).size > 255) throw AegisException.Session("name too long")
        if (scope == SkScope.Channel && !Bytes.eq(ownerEd!!, senderEd)) throw AegisException.SenderMismatch()
        val old = chains.firstOrNull { Bytes.eq(it.chainId, chainId) && Bytes.eq(it.senderEd, senderEd) }
        if (old != null) {
            // A repeated distribution never rewinds a chain or renames its sender.
            if (old.sender == sender) return
            throw AegisException.SenderMismatch()
        }
        if (chains.size >= SenderKey.MAX_CHAINS) throw AegisException.Session("too many chains")
        for (c in chains) if (Bytes.eq(c.senderEd, senderEd) && c.supersededAt == null) c.supersededAt = now
        chains.add(RecvChain(chainId.copyOf(), sender, senderEd.copyOf(), n, ck.copyOf(), ArrayList(), null))
        val mine = chains.indices.filter { Bytes.eq(chains[it].senderEd, senderEd) }
        if (mine.size > SenderKey.MAX_CHAINS_PER_SENDER) chains.removeAt(mine[0])
    }

    /** Decrypts a type 0x05 frame. State changes only if every check passes. */
    fun decrypt(frame: ByteArray, now: Long): Envelope {
        purge(now)
        if (frame.size < 1 + SenderKey.HDR_LEN + 16 + 64) throw AegisException.Length()
        if (frame[0] != SenderKey.FRAME) throw AegisException.BadFrameType()
        val hnonce = frame.copyOfRange(1, 13)
        val h = Crypto.aeadOpen(hk, hnonce, byteArrayOf(SenderKey.FRAME), frame.copyOfRange(13, 1 + SenderKey.HDR_LEN))
        if (h.size != 20) throw AegisException.Length()
        val chainId = h.copyOfRange(0, 16)
        val n = Bytes.be32(h, 16)
        // Chain ids are only unique per sender, so every chain with this id gets a try.
        var last: AegisException = AegisException.Session("unknown chain")
        for (i in chains.indices.filter { Bytes.eq(chains[it].chainId, chainId) }) {
            try {
                return decryptWithChain(i, frame, chainId, n, now)
            } catch (e: AegisException) {
                last = e
            }
        }
        throw last
    }

    private fun decryptWithChain(i: Int, frame: ByteArray, chainId: ByteArray, n: Long, now: Long): Envelope {
        val chain = chains[i].copy()
        val (key, nonce) = chain.takeKey(n, now)
        val plain = Crypto.aeadOpen(key, nonce, SenderKey.chainAad(chainId, n), frame.copyOfRange(1 + SenderKey.HDR_LEN, frame.size))
        if (plain.size < 64) throw AegisException.Length()
        val body = plain.copyOfRange(0, plain.size - 64)
        val sig = plain.copyOfRange(plain.size - 64, plain.size)
        val env = Envelope.decode(body)
        if (!scope.allows(env.kind)) throw AegisException.BadFrameType()
        if (env.groupId != scope.id(g)) throw AegisException.GroupMismatch()
        if (!Bytes.eq(env.senderEd, chain.senderEd) || env.sender != chain.sender) throw AegisException.SenderMismatch()
        if (!Crypto.ed25519Verify(env.senderEd, SenderKey.sigInput(body), sig)) throw AegisException.BadSignature()
        // A signed post re-encrypted at another position must not use up that position's key.
        val digest = Hex.encode(Crypto.sha256(Bytes.concat(body, sig)).copyOfRange(0, 16))
        if (chains.any { Bytes.eq(it.senderEd, chain.senderEd) && it.seen.contains(digest) }) {
            throw AegisException.Session("replayed post")
        }
        chain.seen.addLast(digest)
        while (chain.seen.size > SenderKey.MAX_SEEN_PER_CHAIN) chain.seen.removeFirst()
        chains[i] = chain
        return env
    }

    fun purge(now: Long) {
        for (c in chains) c.skipped.removeAll { now >= it.third + SenderKey.SKIPPED_TTL_SECS }
        chains.removeAll { c -> c.supersededAt?.let { now >= it + SenderKey.OLD_CHAIN_KEEP_SECS } ?: false }
    }

    fun encode(): ByteArray {
        val w = StateWriter().raw(Text.utf8("AGK2")).flag(scope == SkScope.Channel).raw(g).opt32(ownerEd)
        w.u16(minOf(chains.size, 0xFFFF))
        for (c in chains) {
            w.raw(c.chainId).str(c.sender).raw(c.senderEd).u32(c.nextN).raw(c.ck).optU64(c.supersededAt)
            w.u16(minOf(c.skipped.size, 0xFFFF))
            for ((n, k, ts) in c.skipped) w.u32(n).raw(k).u64(ts)
            w.u16(minOf(c.seen.size, 0xFFFF))
            for (d in c.seen) w.raw(Hex.decode(d))
        }
        return w.finish()
    }

    companion object {
        /** Reads AGK2 and the older AGK1, which has no seen-post digests. */
        fun decode(bytes: ByteArray): RecvSet {
            val r = StateReader(bytes)
            val v2 = bytes.size >= 4 && Bytes.eq(bytes.copyOfRange(0, 4), Text.utf8("AGK2"))
            r.magic(if (v2) "AGK2" else "AGK1")
            val scope = if (r.flag()) SkScope.Channel else SkScope.Group
            val g = r.take(32)
            val set = RecvSet(scope, g, r.opt32())
            val chains = r.u16()
            if (chains > SenderKey.MAX_CHAINS) throw AegisException.Session("state")
            repeat(chains) {
                val chainId = r.take(16)
                val sender = r.str()
                val ed = r.take(32)
                val next = r.u32()
                val ck = r.take(32)
                val sup = r.optU64()
                val count = r.u16()
                if (count > SenderKey.MAX_SKIPPED) throw AegisException.Session("state")
                val sk = ArrayList<Triple<Long, ByteArray, Long>>(count)
                repeat(count) { sk.add(Triple(r.u32(), r.take(32), r.u64())) }
                val seen = ArrayDeque<String>()
                if (v2) {
                    val m = r.u16()
                    if (m > SenderKey.MAX_SEEN_PER_CHAIN) throw AegisException.Session("state")
                    repeat(m) { seen.addLast(Hex.encode(r.take(16))) }
                }
                val dup = set.chains.any { Bytes.eq(it.senderEd, ed) && Bytes.eq(it.chainId, chainId) }
                val perSender = set.chains.count { Bytes.eq(it.senderEd, ed) }
                val foreign = scope == SkScope.Channel && set.ownerEd?.let { Bytes.eq(it, ed) } != true
                if (dup || foreign || perSender >= SenderKey.MAX_CHAINS_PER_SENDER) throw AegisException.Session("state")
                set.chains.add(RecvChain(chainId, sender, ed, next, ck, sk, sup, seen))
            }
            r.end()
            return set
        }
    }
}
