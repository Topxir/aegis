package org.aegis.messenger.data

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Json
import org.aegis.messenger.core.QueueIds
import org.aegis.messenger.core.Text

/** Delivery state of an outgoing message. Incoming messages are always [SENT]. */
object Status {
    const val SENT = 0
    const val SENDING = 1
    const val FAILED = 2
}

class Message(
    val id: String,
    val outgoing: Boolean,
    val sender: String,
    val senderName: String,
    val tsMs: Long,
    /** Local clock when the message was stored; expiry never starts later than this. */
    val baseMs: Long,
    val ttlS: Long,
    val body: String,
    val status: Int = Status.SENT,
)

class Contact(
    val username: String,
    val title: String,
    val x: ByteArray,
    val ed: ByteArray,
    val verified: Boolean = false,
    /** Set when a message arrived under a different key; [pendingX]/[pendingEd] hold that key until the user decides. */
    val keyChanged: Boolean = false,
    val pendingX: ByteArray? = null,
    val pendingEd: ByteArray? = null,
    val ttlS: Long = 0,
)

class Group(
    val id: String,
    val secret: ByteArray,
    val name: String,
    val members: List<String>,
    val ttlS: Long = 0,
) {
    val queueHex: String get() = Hex.encode(QueueIds.group(secret))
}

class Chat(
    val messages: List<Message> = emptyList(),
    val unread: Int = 0,
)

class Settings(
    val endpoint: String = org.aegis.messenger.net.Endpoint.DEFAULT,
    /** "host:port" of a SOCKS5 proxy, empty for a direct connection. */
    val proxy: String = "",
    val displayName: String = "",
    val idleLockMin: Int = 5,
    val backgroundLockMin: Int = 15,
    val pollSeconds: Int = 30,
    val notifications: Boolean = true,
)

class VaultData(
    val username: String,
    val xSk: ByteArray,
    val edSk: ByteArray,
    val registered: Boolean = false,
    val contacts: List<Contact> = emptyList(),
    val groups: List<Group> = emptyList(),
    /** Keys are "dm:<username>" or "g:<group id>". */
    val chats: Map<String, Chat> = emptyMap(),
    val seen: List<String> = emptyList(),
    /** Last polled sequence per queue hex. */
    val cursors: Map<String, Long> = emptyMap(),
    val settings: Settings = Settings(),
) {
    fun contact(u: String): Contact? = contacts.firstOrNull { it.username == u }
    fun group(id: String): Group? = groups.firstOrNull { it.id == id }
    fun chat(key: String): Chat = chats[key] ?: Chat()

    fun withContact(c: Contact): VaultData =
        VaultData(username, xSk, edSk, registered, contacts.filter { it.username != c.username } + c, groups, chats, seen, cursors, settings)

    fun copy(
        registered: Boolean = this.registered,
        contacts: List<Contact> = this.contacts,
        groups: List<Group> = this.groups,
        chats: Map<String, Chat> = this.chats,
        seen: List<String> = this.seen,
        cursors: Map<String, Long> = this.cursors,
        settings: Settings = this.settings,
    ) = VaultData(username, xSk, edSk, registered, contacts, groups, chats, seen, cursors, settings)

    fun withChat(key: String, c: Chat): VaultData = copy(chats = chats + (key to c))

    fun wipe() {
        xSk.fill(0)
        edSk.fill(0)
        groups.forEach { it.secret.fill(0) }
    }
}

fun dmKey(username: String) = "dm:$username"
fun groupKey(id: String) = "g:$id"

/** JSON (de)serialisation of the vault payload. */
object VaultCodec {
    private const val SCHEMA = 1L

    fun encode(v: VaultData): ByteArray {
        val m = LinkedHashMap<String, Any?>()
        m["schema"] = SCHEMA
        m["username"] = v.username
        m["x_sk"] = Hex.encode(v.xSk)
        m["ed_sk"] = Hex.encode(v.edSk)
        m["registered"] = v.registered
        m["contacts"] = v.contacts.map { c ->
            mapOf(
                "u" to c.username, "title" to c.title, "x" to Hex.encode(c.x), "ed" to Hex.encode(c.ed),
                "verified" to c.verified, "key_changed" to c.keyChanged,
                "px" to c.pendingX?.let { Hex.encode(it) }, "ped" to c.pendingEd?.let { Hex.encode(it) },
                "ttl" to c.ttlS,
            )
        }
        m["groups"] = v.groups.map { g ->
            mapOf("id" to g.id, "key" to Hex.encode(g.secret), "name" to g.name, "members" to g.members, "ttl" to g.ttlS)
        }
        m["chats"] = v.chats.mapValues { (_, c) ->
            mapOf(
                "unread" to c.unread.toLong(),
                "msgs" to c.messages.map { x ->
                    mapOf(
                        "id" to x.id, "out" to x.outgoing, "s" to x.sender, "sn" to x.senderName, "ts" to x.tsMs,
                        "base" to x.baseMs, "ttl" to x.ttlS, "b" to x.body, "st" to x.status.toLong(),
                    )
                },
            )
        }
        m["seen"] = v.seen
        m["cursors"] = v.cursors
        val s = v.settings
        m["settings"] = mapOf(
            "endpoint" to s.endpoint, "proxy" to s.proxy, "name" to s.displayName,
            "idle" to s.idleLockMin.toLong(), "bg" to s.backgroundLockMin.toLong(),
            "poll" to s.pollSeconds.toLong(), "notify" to s.notifications,
        )
        return Text.utf8(Json.write(m))
    }

    @Suppress("UNCHECKED_CAST")
    fun decode(bytes: ByteArray): VaultData {
        try {
            val m = Json.parseObject(Text.utf8Strict(bytes))
            if (m["schema"] != SCHEMA) throw AegisException.VaultFormat()
            fun str(o: Map<String, Any?>, k: String) = o[k] as String
            fun lng(o: Map<String, Any?>, k: String) = o[k] as Long
            fun bool(o: Map<String, Any?>, k: String) = o[k] as Boolean
            fun list(o: Map<String, Any?>, k: String) = o[k] as List<Map<String, Any?>>
            val contacts = list(m, "contacts").map {
                Contact(
                    str(it, "u"), str(it, "title"), Hex.decodeFixed(str(it, "x"), 32), Hex.decodeFixed(str(it, "ed"), 32),
                    bool(it, "verified"), bool(it, "key_changed"),
                    (it["px"] as String?)?.let { h -> Hex.decodeFixed(h, 32) },
                    (it["ped"] as String?)?.let { h -> Hex.decodeFixed(h, 32) },
                    lng(it, "ttl"),
                )
            }
            val groups = list(m, "groups").map {
                Group(str(it, "id"), Hex.decodeFixed(str(it, "key"), 32), str(it, "name"), (it["members"] as List<String>), lng(it, "ttl"))
            }
            val chats = (m["chats"] as Map<String, Map<String, Any?>>).mapValues { (_, c) ->
                Chat(
                    list(c, "msgs").map {
                        Message(
                            str(it, "id"), bool(it, "out"), str(it, "s"), str(it, "sn"), lng(it, "ts"), lng(it, "base"),
                            lng(it, "ttl"), str(it, "b"), lng(it, "st").toInt(),
                        )
                    },
                    lng(c, "unread").toInt(),
                )
            }
            val st = m["settings"] as Map<String, Any?>
            val settings = Settings(
                str(st, "endpoint"), str(st, "proxy"), str(st, "name"), lng(st, "idle").toInt(), lng(st, "bg").toInt(),
                lng(st, "poll").toInt(), bool(st, "notify"),
            )
            return VaultData(
                str(m, "username"), Hex.decodeFixed(str(m, "x_sk"), 32), Hex.decodeFixed(str(m, "ed_sk"), 32),
                bool(m, "registered"), contacts, groups, chats, (m["seen"] as List<String>),
                (m["cursors"] as Map<String, Long>), settings,
            )
        } catch (e: AegisException) {
            throw e
        } catch (e: Exception) {
            throw AegisException.VaultFormat()
        }
    }
}
