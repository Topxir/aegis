package org.aegis.messenger.core

enum class Kind(val wire: String) {
    Dm("dm"), Ginv("ginv"), Gmsg("gmsg"), Dmf("dmf"), Gmf("gmf"),
    Cinv("cinv"), Cmsg("cmsg"), Cmf("cmf"), Prof("prof"), Skey("skey"),
    Ttl("ttl"), Gttl("gttl");

    /** Frame type that carries this kind: 0x01 sealed, 0x02 group or channel queue. */
    val frameType: Byte
        get() = when (this) {
            Dm, Ginv, Dmf, Cinv, Prof, Skey, Ttl -> 0x01
            Gmsg, Gmf, Cmsg, Cmf, Gttl -> 0x02
        }

    companion object {
        fun parse(s: String): Kind = values().firstOrNull { it.wire == s }
            ?: throw AegisException.InvalidEnvelope("type")
    }
}

/** Parses the skey body hex(chain_id) ":" n (spec section 28). */
fun parseSkeyBody(body: String): Pair<ByteArray, Long> {
    val i = body.indexOf(':')
    if (i < 0) throw AegisException.InvalidEnvelope("skey body")
    val id = body.substring(0, i)
    val n = body.substring(i + 1)
    if (!Hex.isHexLen(id, 16) || n.isEmpty() || n.length > 10 || (n.length > 1 && n[0] == '0') || !n.all { it in '0'..'9' }) {
        throw AegisException.InvalidEnvelope("skey body")
    }
    val v = n.toLong()
    if (v > 0xFFFFFFFFL) throw AegisException.InvalidEnvelope("skey body")
    return Hex.decode(id) to v
}

/** The plaintext inside every frame (spec section 5). */
class Envelope(
    val kind: Kind,
    val msgId: String,
    val sender: String,
    val senderName: String,
    val senderEd: ByteArray,
    val tsMs: Long,
    val ttlS: Long,
    val groupId: String,
    val body: String,
    val groupKey: ByteArray? = null,
    val members: List<String> = emptyList(),
) {
    override fun toString(): String = "Envelope($kind)"

    private fun validate() {
        if (!Hex.isHexLen(msgId, 16)) throw AegisException.InvalidEnvelope("msg_id")
        if (!Names.isValidUsername(sender)) throw AegisException.InvalidEnvelope("sender")
        if (senderEd.size != 32) throw AegisException.InvalidEnvelope("sender_ed")
        if (tsMs < 0 || ttlS < 0) throw AegisException.InvalidEnvelope("number")
        when (kind) {
            Kind.Dm, Kind.Dmf, Kind.Prof -> if (groupId.isNotEmpty() || groupKey != null || members.isNotEmpty()) {
                throw AegisException.InvalidEnvelope("dm carries group fields")
            }
            Kind.Gmsg, Kind.Gmf, Kind.Cmsg, Kind.Cmf -> {
                if (!Hex.isHexLen(groupId, 32)) throw AegisException.InvalidEnvelope("group_id")
                if (groupKey != null || members.isNotEmpty()) {
                    throw AegisException.InvalidEnvelope("gmsg carries invite fields")
                }
            }
            Kind.Skey -> {
                if (!Hex.isHexLen(groupId, 32) || groupKey?.size != 32 || members.isNotEmpty()) {
                    throw AegisException.InvalidEnvelope("skey fields")
                }
                parseSkeyBody(body)
            }
            Kind.Ttl, Kind.Gttl -> {
                val idOk = if (kind == Kind.Gttl) Hex.isHexLen(groupId, 32) else groupId.isEmpty()
                if (!idOk || groupKey != null || members.isNotEmpty() || body.isNotEmpty()) {
                    throw AegisException.InvalidEnvelope("ttl fields")
                }
            }
            Kind.Cinv -> {
                val key = groupKey ?: throw AegisException.InvalidEnvelope("group_key")
                if (key.size != 32 || groupId != Channel.channelId(key)) {
                    throw AegisException.InvalidEnvelope("group_id does not match group_key")
                }
                if (members.isNotEmpty()) throw AegisException.InvalidEnvelope("cinv carries members")
            }
            Kind.Ginv -> {
                val key = groupKey ?: throw AegisException.InvalidEnvelope("group_key")
                if (key.size != 32 || groupId != Group.groupId(key)) {
                    throw AegisException.InvalidEnvelope("group_id does not match group_key")
                }
                if (members.isEmpty() || members.size > MAX_MEMBERS ||
                    !members.all { Names.isValidUsername(it) }
                ) {
                    throw AegisException.InvalidEnvelope("members")
                }
            }
        }
    }

    fun encode(): ByteArray {
        validate()
        val fields = listOf(
            "AEGIS2", kind.wire, msgId, sender, senderName, Hex.encode(senderEd),
            tsMs.toString(), ttlS.toString(), groupId, body,
            groupKey?.let { Hex.encode(it) } ?: "", members.joinToString(","),
        )
        return Text.utf8(fields.joinToString("\n") { Text.pctEncode(it) })
    }

    companion object {
        const val MAX_MEMBERS = 100
        private const val FIELDS = 12

        private fun dec(s: String): Long {
            val v = try {
                Text.parseU64(s)
            } catch (_: AegisException) {
                throw AegisException.InvalidEnvelope("number")
            }
            if (v > Long.MAX_VALUE.toULong()) throw AegisException.InvalidEnvelope("number")
            return v.toLong()
        }

        fun decode(bytes: ByteArray): Envelope {
            val s = try {
                Text.utf8Strict(bytes)
            } catch (_: AegisException) {
                throw AegisException.InvalidEnvelope("utf-8")
            }
            // Kotlin split keeps trailing empty fields.
            val parts = s.split('\n')
            if (parts.size != FIELDS) throw AegisException.InvalidEnvelope("field count")
            if (parts[0] != "AEGIS2") throw AegisException.InvalidEnvelope("header")
            val f = parts.map {
                try {
                    Text.pctDecodeStrict(it)
                } catch (_: AegisException) {
                    throw AegisException.InvalidEnvelope("percent-encoding")
                }
            }
            val kind = Kind.parse(f[1])
            if (!Hex.isHexLen(f[5], 32)) throw AegisException.InvalidEnvelope("sender_ed")
            val groupKey = when {
                f[10].isEmpty() -> null
                Hex.isHexLen(f[10], 32) -> Hex.decode(f[10])
                else -> throw AegisException.InvalidEnvelope("group_key")
            }
            if (f[8].isNotEmpty() && !Hex.isHexLen(f[8], 32)) throw AegisException.InvalidEnvelope("group_id")
            val members = if (f[11].isEmpty()) emptyList() else f[11].split(',')
            val env = Envelope(
                kind, f[2], f[3], f[4], Hex.decode(f[5]), dec(f[6]), dec(f[7]),
                f[8], f[9], groupKey, members,
            )
            env.validate()
            return env
        }
    }
}

/** Keys pinned for a contact on first contact. */
class PinnedKeys(val xPk: ByteArray, val edPk: ByteArray)

object Pinning {
    /** Receiver check for dm/ginv: sealed sender key and sender_ed must equal the pin. */
    fun checkDm(env: Envelope, senderXPk: ByteArray, pinned: PinnedKeys) {
        if (!Bytes.eq(pinned.xPk, senderXPk) || !Bytes.eq(pinned.edPk, env.senderEd)) {
            throw AegisException.SenderMismatch()
        }
    }

    /** Receiver check for gmsg: sender_ed must equal the pinned key. */
    fun checkGroup(env: Envelope, pinned: PinnedKeys) {
        if (!Bytes.eq(pinned.edPk, env.senderEd)) throw AegisException.SenderMismatch()
    }
}

/** Bounded set of seen msg ids, oldest evicted first. */
class SeenIds(private val cap: Int, ids: Iterable<String> = emptyList()) {
    private val set = HashSet<String>()
    private val order = ArrayDeque<String>()

    init {
        for (i in ids) insert(i)
    }

    /** True if [id] was not seen before (and records it). */
    fun insert(id: String): Boolean {
        if (!set.add(id)) return false
        order.addLast(id)
        while (order.size > cap) set.remove(order.removeFirst())
        return true
    }

    fun contains(id: String): Boolean = set.contains(id)
    fun toList(): List<String> = order.toList()
}

object Expiry {
    /** Timer values a chat can be set to, in seconds; 0 keeps messages (spec section 5.2). */
    val TTL_CHOICES = listOf(0L, 30L, 300L, 3600L, 86_400L, 604_800L)

    fun allowed(ttlS: Long): Boolean = ttlS in TTL_CHOICES

    /** True when a message kept since [tsMs] (receipt or send time) with [ttlS] should be deleted at [nowMs]. */
    fun isExpired(tsMs: Long, ttlS: Long, nowMs: Long): Boolean {
        if (ttlS == 0L) return false
        val life = if (ttlS > Long.MAX_VALUE / 1000) Long.MAX_VALUE else ttlS * 1000
        val end = if (tsMs > Long.MAX_VALUE - life) Long.MAX_VALUE else tsMs + life
        return nowMs >= end
    }
}
