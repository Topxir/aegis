package org.aegis.messenger.core

/** What the client has to do next. */
sealed class SessionAction {
    class NeedsPrekeysFetch(val contact: String) : SessionAction()
    class StartNewSession(val contact: String) : SessionAction()
    class UndecryptableNotice(val contact: String) : SessionAction()
    class LookupSender(val xPk: ByteArray) : SessionAction()
}

sealed class Encrypted {
    class Frame(val bytes: ByteArray) : Encrypted()
    object NeedsPrekeys : Encrypted()
}

class Received(
    val contact: String? = null,
    val envelope: Envelope? = null,
    val actions: List<SessionAction> = emptyList(),
)

/** Pairwise sessions with forward secrecy: frame type 0x03 (spec sections 27.4 and 27.5). Pure logic, no clock. */
class SessionStore {
    companion object {
        const val FRAME_SESSION: Byte = 0x03
        const val SEEN_EK_CAP = 1000
        const val SESSION_IDLE_SECS = 180L * 24 * 3600
        const val SUPERSEDED_KEEP_SECS = 30L * 24 * 3600
        const val RECOVERY_AFTER_FAILURES = 3
        const val RECOVERY_MIN_GAP_SECS = 24L * 3600
        private const val SEEN_FRAME_CAP = 256
        private const val MAX_SESSIONS_PER_CONTACT = 8
        private const val MAX_OPKS_HELD = 200
        private const val START_LEN = 1 + 96
        private const val HEADER_LEN = Ratchet.HEADER_LEN

        fun decode(bytes: ByteArray): SessionStore {
            val r = StateReader(bytes)
            r.magic("AGS1")
            val st = SessionStore()
            repeat(r.u16()) { st.spks.add(SpkEntry(r.take(32), r.u64(), r.optU64())) }
            repeat(r.u16()) { st.opks.add(r.take(32)) }
            repeat(r.u16()) { st.seenEk.addLast(Hex.encode(r.take(32))) }
            repeat(r.u16()) { st.seenFrames.addLast(Hex.encode(r.take(32))) }
            if (st.seenEk.size > SEEN_EK_CAP || st.seenFrames.size > SEEN_FRAME_CAP || st.opks.size > MAX_OPKS_HELD) {
                throw AegisException.Session("state")
            }
            repeat(r.u16()) {
                val u = r.str()
                val ed = r.take(32)
                val x = r.take(32)
                val c = ContactSessions(u, ed, x)
                c.sendEk = r.opt32()
                c.needStart = r.flag()
                c.failCount = r.u32()
                c.lastRecovery = r.optU64()
                repeat(r.u8()) {
                    val ek = r.take(32)
                    val f = r.u8()
                    if (f > 7) throw AegisException.Session("state")
                    val start = if (f and 4 != 0) StartHeader(r.take(32), r.take(32)) else null
                    val lastActive = r.u64()
                    val sup = r.optU64()
                    val n = r.u32()
                    if (n > Int.MAX_VALUE) throw AegisException.Session("state")
                    val ratchet = Ratchet.decode(r.take(n.toInt()))
                    c.sessions.add(Session(ratchet, ek, f and 1 != 0, f and 2 != 0, start, lastActive, sup))
                }
                if (c.sessions.size > MAX_SESSIONS_PER_CONTACT) throw AegisException.Session("state")
                st.contacts.add(c)
            }
            r.end()
            return st
        }
    }

    private class SpkEntry(val sk: ByteArray, val ts: Long, var retiredAt: Long?)
    private class StartHeader(val spk: ByteArray, val opk: ByteArray)

    private class Session(
        val ratchet: Ratchet,
        val ekPk: ByteArray,
        val weInitiated: Boolean,
        var receivedAny: Boolean,
        var start: StartHeader?,
        var lastActive: Long,
        var supersededAt: Long?,
    ) {
        fun tryDecrypt(newDhsSk: ByteArray, msg: ByteArray, now: Long): ByteArray? {
            val plain = try {
                ratchet.decryptWith(newDhsSk, msg, now)
            } catch (_: AegisException) {
                return null
            }
            receivedAny = true
            start = null
            lastActive = now
            return plain
        }
    }

    private class ContactSessions(val u: String, val ed: ByteArray, val x: ByteArray) {
        val sessions = ArrayList<Session>()
        var sendEk: ByteArray? = null
        var needStart = false
        var failCount = 0L
        var lastRecovery: Long? = null

        fun sendIndex(): Int? {
            if (needStart) return null
            val ek = sendEk ?: return null
            val i = sessions.indexOfFirst { Bytes.eq(it.ekPk, ek) }
            if (i < 0) return null
            return if (sessions[i].ratchet.canSend()) i else null
        }

        fun install(session: Session, initiated: Boolean, now: Long) {
            val newEk = session.ekPk
            val cur = sendEk?.let { ek -> sessions.firstOrNull { Bytes.eq(it.ekPk, ek) } }
            val simultaneous = !initiated && cur != null && cur.weInitiated && !cur.receivedAny
            val old = sendEk
            val chosen = if (simultaneous && old != null) minEk(old, newEk) else newEk
            sessions.add(0, session)
            sendEk = chosen
            for (s in sessions) {
                if (!Bytes.eq(s.ekPk, chosen)) {
                    if (s.supersededAt == null) s.supersededAt = now
                } else {
                    s.supersededAt = null
                }
            }
            while (sessions.size > MAX_SESSIONS_PER_CONTACT) {
                val i = sessions.indexOfLast { !Bytes.eq(it.ekPk, chosen) }
                if (i >= 0) sessions.removeAt(i) else break
            }
        }

        fun failed(now: Long): Received {
            failCount++
            val actions = ArrayList<SessionAction>()
            val allowed = lastRecovery?.let { now >= it + RECOVERY_MIN_GAP_SECS } ?: true
            if (failCount >= RECOVERY_AFTER_FAILURES && allowed) {
                failCount = 0
                lastRecovery = now
                needStart = true
                actions.add(SessionAction.StartNewSession(u))
                actions.add(SessionAction.UndecryptableNotice(u))
            }
            return Received(contact = u, actions = actions)
        }
    }

    private val spks = ArrayList<SpkEntry>()
    private val opks = ArrayList<ByteArray>()
    private val seenEk = ArrayDeque<String>()
    private val seenFrames = ArrayDeque<String>()
    private val contacts = ArrayList<ContactSessions>()

    private fun pushCapped(q: ArrayDeque<String>, v: String, cap: Int) {
        q.addLast(v)
        while (q.size > cap) q.removeFirst()
    }

    /** Registers a pinned contact. Different keys for a known name are an error. */
    fun addContact(u: String, ed: ByteArray, x: ByteArray) {
        val c = contacts.firstOrNull { it.u == u }
        if (c != null) {
            if (Bytes.eq(c.ed, ed) && Bytes.eq(c.x, x)) return
            throw AegisException.Session("contact keys changed")
        }
        contacts.add(ContactSessions(u, ed.copyOf(), x.copyOf()))
    }

    fun removeContact(u: String) {
        contacts.removeAll { it.u == u }
    }

    fun hasSession(u: String): Boolean = contacts.any { it.u == u && it.sessions.isNotEmpty() }
    fun hasContact(u: String): Boolean = contacts.any { it.u == u }
    fun hasPrekeys(): Boolean = spks.any { it.retiredAt == null }

    class PrekeyBatch(val spk: X3dh.SignedPrekey, val opks: List<ByteArray>)

    /**
     * Rotates the signed prekey when due and creates one-time prekeys. [serverOpks] is the count from the last
     * put answer; null means unknown and no one-time prekeys are added.
     */
    fun preparePrekeys(me: Identity, now: Long, serverOpks: Int?): PrekeyBatch {
        purge(now)
        val cur0 = spks.lastOrNull { it.retiredAt == null }
        if (cur0 == null || now >= cur0.ts + X3dh.SPK_ROTATE_SECS) {
            val fresh = X3dh.SignedPrekey.generate(me, now)
            for (s in spks) if (s.retiredAt == null) s.retiredAt = now
            spks.add(SpkEntry(fresh.sk, now, null))
        }
        val cur = spks.last { it.retiredAt == null }
        val sp = X3dh.SignedPrekey.fromSecret(me, cur.sk, cur.ts)
        val pks = ArrayList<ByteArray>()
        val need = if (serverOpks == null) 0 else X3dh.opksNeeded(serverOpks)
        repeat(minOf(need, Prekeys.MAX_OPKS)) {
            val sk = Crypto.randomBytes(32)
            pks.add(Crypto.x25519Public(sk))
            opks.add(sk)
        }
        while (opks.size > MAX_OPKS_HELD) opks.removeAt(0)
        return PrekeyBatch(sp, pks)
    }

    fun startSession(me: Identity, contact: String, bundle: X3dh.Bundle, now: Long) =
        startSessionWith(Crypto.randomBytes(32), Crypto.randomBytes(32), me, contact, bundle, now)

    fun startSessionWith(ekSk: ByteArray, dhsSk: ByteArray, me: Identity, contact: String, bundle: X3dh.Bundle, now: Long) {
        val c = contactOf(contact)
        bundle.check(c.ed, now)
        val sk = X3dh.initiateWith(ekSk, me.xSecret, c.x, bundle)
        val ad = X3dh.Parties(me.edPublic, me.xPublic, c.ed, c.x).ad()
        val ratchet = Ratchet.initInitiatorWith(dhsSk, sk, ad, bundle.spk)
        val s = Session(
            ratchet, Crypto.x25519Public(ekSk), true, false,
            StartHeader(bundle.spk, bundle.opk ?: ByteArray(32)), now, null,
        )
        c.install(s, true, now)
        c.needStart = false
    }

    fun encrypt(me: Identity, contact: String, env: Envelope, now: Long): Encrypted =
        encryptWith(Crypto.randomBytes(32), me, contact, env, now)

    /** Wraps [env] in a type 0x03 frame (unpadded; the caller pads as in section 4). */
    fun encryptWith(eSk: ByteArray, me: Identity, contact: String, env: Envelope, now: Long): Encrypted {
        if (env.kind.frameType != 0x01.toByte()) throw AegisException.BadFrameType()
        purge(now)
        val c = contactOf(contact)
        val i = c.sendIndex() ?: return Encrypted.NeedsPrekeys
        val plain = env.encode()
        val s = c.sessions[i]
        val msg = s.ratchet.encrypt(plain)
        plain.fill(0)
        val h = s.start
        val inner = if (h != null) Bytes.concat(byteArrayOf(0), s.ekPk, h.spk, h.opk, msg) else Bytes.concat(byteArrayOf(1), msg)
        s.lastActive = now
        return Encrypted.Frame(Seal.sealRaw(FRAME_SESSION, eSk, me.xSecret, c.x, inner))
    }

    fun decrypt(me: Identity, frame: ByteArray, now: Long): Received =
        decryptWith(Crypto.randomBytes(32), me, frame, now)

    fun decryptWith(newDhsSk: ByteArray, me: Identity, frame: ByteArray, now: Long): Received {
        purge(now)
        val opened = Seal.openRaw(FRAME_SESSION, me.xSecret, frame)
        val sPk = opened.senderXPk
        val inner = opened.plain
        val ci = contacts.indexOfFirst { Bytes.eq(it.x, sPk) }
        if (ci < 0) return Received(actions = listOf(SessionAction.LookupSender(sPk)))
        val fh = Hex.encode(Crypto.sha256(frame))
        if (seenFrames.contains(fh)) return Received()
        pushCapped(seenFrames, fh, SEEN_FRAME_CAP)

        if (inner.isEmpty()) throw AegisException.Length()
        val msg: ByteArray
        var start: Triple<ByteArray, ByteArray, ByteArray>? = null
        when (inner[0].toInt()) {
            0 -> {
                if (inner.size < START_LEN + HEADER_LEN + 16) throw AegisException.Length()
                start = Triple(inner.copyOfRange(1, 33), inner.copyOfRange(33, 65), inner.copyOfRange(65, 97))
                msg = inner.copyOfRange(97, inner.size)
            }
            1 -> msg = inner.copyOfRange(1, inner.size)
            else -> throw AegisException.Session("unknown inner kind")
        }
        if (msg.size < HEADER_LEN + 16) throw AegisException.Length()

        var created = false
        val plain: ByteArray?
        if (start != null) {
            val r = openStart(ci, me, newDhsSk, start.first, start.second, start.third, msg, now) ?: return Received()
            plain = r.first
            created = r.second
        } else {
            plain = contacts[ci].sessions.firstNotNullOfOrNull { it.tryDecrypt(newDhsSk, msg, now) }
        }
        val c = contacts[ci]
        if (plain == null) return c.failed(now)
        if (created) c.needStart = false
        c.failCount = 0
        val env = Envelope.decode(plain)
        if (env.kind.frameType != 0x01.toByte()) throw AegisException.BadFrameType()
        if (!Bytes.eq(env.senderEd, c.ed) || env.sender != c.u) throw AegisException.SenderMismatch()
        return Received(contact = c.u, envelope = env)
    }

    /** Null: dropped. First of the pair null: did not decrypt. */
    private fun openStart(
        ci: Int, me: Identity, newDhsSk: ByteArray, ek: ByteArray, spk: ByteArray, opk: ByteArray, msg: ByteArray, now: Long,
    ): Pair<ByteArray?, Boolean>? {
        val c = contacts[ci]
        val known = c.sessions.firstOrNull { Bytes.eq(it.ekPk, ek) }
        if (known != null) return known.tryDecrypt(newDhsSk, msg, now) to false
        val ekHex = Hex.encode(ek)
        if (seenEk.contains(ekHex)) return null
        val sp = spks.firstOrNull { Bytes.eq(Crypto.x25519Public(it.sk), spk) } ?: return null
        var opkIdx = -1
        if (!Bytes.eq(opk, ByteArray(32))) {
            opkIdx = opks.indexOfFirst { Bytes.eq(Crypto.x25519Public(it), opk) }
            if (opkIdx < 0) return null
        }
        val sk = X3dh.respond(me.xSecret, sp.sk, if (opkIdx >= 0) opks[opkIdx] else null, c.x, ek)
        val ad = X3dh.Parties(c.ed, c.x, me.edPublic, me.xPublic).ad()
        val session = Session(Ratchet.initResponder(sk, ad, sp.sk), ek.copyOf(), false, false, null, now, null)
        val plain = session.tryDecrypt(newDhsSk, msg, now) ?: return null to false
        pushCapped(seenEk, ekHex, SEEN_EK_CAP)
        if (opkIdx >= 0) opks.removeAt(opkIdx)
        c.install(session, false, now)
        return plain to true
    }

    /** Deletes expired sessions, superseded sessions and old signed prekey secrets. */
    fun purge(now: Long) {
        spks.removeAll { s -> s.retiredAt?.let { now >= it + X3dh.SPK_KEEP_SECS } ?: false }
        for (c in contacts) {
            for (s in c.sessions) s.ratchet.expire(now)
            c.sessions.removeAll { s ->
                now >= s.lastActive + SESSION_IDLE_SECS || (s.supersededAt?.let { now >= it + SUPERSEDED_KEEP_SECS } ?: false)
            }
            val ek = c.sendEk
            if (ek != null && c.sessions.none { Bytes.eq(it.ekPk, ek) }) c.sendEk = null
        }
    }

    private fun contactOf(u: String): ContactSessions =
        contacts.firstOrNull { it.u == u } ?: throw AegisException.Session("unknown contact")

    private fun len16(n: Int) = minOf(n, 0xFFFF)

    fun encode(): ByteArray {
        val w = StateWriter().raw(Text.utf8("AGS1"))
        w.u16(len16(spks.size))
        for (s in spks) w.raw(s.sk).u64(s.ts).optU64(s.retiredAt)
        w.u16(len16(opks.size))
        for (o in opks) w.raw(o)
        w.u16(len16(seenEk.size))
        for (e in seenEk) w.raw(Hex.decode(e))
        w.u16(len16(seenFrames.size))
        for (h in seenFrames) w.raw(Hex.decode(h))
        w.u16(len16(contacts.size))
        for (c in contacts) {
            w.str(c.u).raw(c.ed).raw(c.x).opt32(c.sendEk).flag(c.needStart).u32(c.failCount).optU64(c.lastRecovery)
            w.u8(minOf(c.sessions.size, 255))
            for (s in c.sessions) {
                val f = (if (s.weInitiated) 1 else 0) or (if (s.receivedAny) 2 else 0) or (if (s.start != null) 4 else 0)
                w.raw(s.ekPk).u8(f)
                s.start?.let { w.raw(it.spk).raw(it.opk) }
                w.u64(s.lastActive).optU64(s.supersededAt)
                val r = s.ratchet.encode()
                w.u32(r.size.toLong()).raw(r)
            }
        }
        return w.finish()
    }
}

private fun minEk(a: ByteArray, b: ByteArray): ByteArray {
    for (i in a.indices) {
        val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
        if (d != 0) return if (d < 0) a else b
    }
    return a
}
