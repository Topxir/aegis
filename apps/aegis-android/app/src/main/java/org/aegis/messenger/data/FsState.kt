package org.aegis.messenger.data

import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.RecvSet
import org.aegis.messenger.core.SendChain
import org.aegis.messenger.core.SessionStore

/**
 * Forward-secrecy state kept inside the vault: pairwise sessions, our sender chains and the chains
 * we received. The object is shared between copies of [VaultData]; callers lock on it.
 */
class FsState(var store: SessionStore = SessionStore()) {
    companion object {
        /** prekeys/put is limited to one per 60 s and five per hour (spec section 27.1). */
        const val PUT_MIN_GAP_SECS = 60L
        const val PUT_PER_HOUR = 5
        const val PUT_REFRESH_SECS = 1800L
        const val MAX_REQUESTS = 20
        const val MAX_REQUEST_FRAMES = 3

        @Suppress("UNCHECKED_CAST")
        fun fromJson(m: Map<String, Any?>?): FsState {
            if (m == null) return FsState()
            try {
                val fs = FsState(SessionStore.decode(Hex.decode(m["store"] as String)))
                (m["send"] as Map<String, Map<String, Any?>>?)?.forEach { (k, v) ->
                    fs.send[k] = SendChain.decode(Hex.decode(v["c"] as String))
                    fs.given[k] = ((v["to"] as List<String>?) ?: emptyList()).toMutableSet()
                }
                (m["audience"] as Map<String, List<String>>?)?.forEach { (k, v) -> fs.audience[k] = v.toMutableSet() }
                (m["recv"] as Map<String, String>?)?.forEach { (k, v) -> fs.recv[k] = RecvSet.decode(Hex.decode(v)) }
                (m["req"] as Map<String, List<String>>?)?.forEach { (k, v) -> fs.requests[k] = v.map { Hex.decode(it) }.toMutableList() }
                (m["blocked"] as List<String>?)?.let { fs.blocked.addAll(it) }
                fs.serverOpks = (m["opks"] as Long?)?.toInt()
                (m["puts"] as List<Long>?)?.let { fs.putTimes.addAll(it) }
                return fs
            } catch (e: Exception) {
                return FsState()
            }
        }
    }

    /** Chain key: "g:<id>" or "c:<id>". */
    val send = LinkedHashMap<String, SendChain>()

    /** Users who already hold our current chain. */
    val given = HashMap<String, MutableSet<String>>()

    /** Channel subscribers we invited; groups use their member list. */
    val audience = HashMap<String, MutableSet<String>>()
    val recv = LinkedHashMap<String, RecvSet>()

    /** Session frames from keys we cannot name yet, by sender key (hex). Opened when the user accepts. */
    val requests = LinkedHashMap<String, MutableList<ByteArray>>()

    /** Sender keys (hex) the user blocked. */
    val blocked = LinkedHashSet<String>()
    var serverOpks: Int? = null
    val putTimes = ArrayList<Long>()

    /** Holds a frame from an unknown sender key. False when the limits are reached or the key is blocked. */
    fun hold(xHex: String, frame: ByteArray): Boolean = synchronized(this) {
        if (xHex in blocked) return false
        val list = requests[xHex]
        if (list == null) {
            if (requests.size >= MAX_REQUESTS) return false
            requests[xHex] = mutableListOf(frame)
            return true
        }
        if (list.size >= MAX_REQUEST_FRAMES) return false
        list.add(frame)
        true
    }

    fun lastPut(): Long? = putTimes.maxOrNull()

    /** Whether a prekeys/put may go out now, and whether one is due. */
    fun putDue(now: Long): Boolean {
        putTimes.removeAll { now - it >= 3600 }
        val last = lastPut()
        if (last != null && now - last < PUT_MIN_GAP_SECS) return false
        if (putTimes.size >= PUT_PER_HOUR) return false
        return last == null || serverOpks == null || now - last >= PUT_REFRESH_SECS
    }

    fun toJson(): Map<String, Any?> = synchronized(this) {
        mapOf(
            "store" to Hex.encode(store.encode()),
            "send" to send.mapValues { (k, c) -> mapOf("c" to Hex.encode(c.encode()), "to" to (given[k]?.toList() ?: emptyList<String>())) },
            "audience" to audience.mapValues { it.value.toList() },
            "recv" to recv.mapValues { Hex.encode(it.value.encode()) },
            "req" to requests.mapValues { e -> e.value.map { Hex.encode(it) } },
            "blocked" to blocked.toList(),
            "opks" to serverOpks?.toLong(),
            "puts" to putTimes.toList(),
        )
    }
}
