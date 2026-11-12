package org.aegis.messenger.data

import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Json
import org.aegis.messenger.core.MediaKind
import org.aegis.messenger.core.Particles
import org.aegis.messenger.core.QueueIds
import org.aegis.messenger.core.Text

/** Delivery state of an outgoing message. Incoming messages are always [SENT]. */
object Status {
    const val SENT = 0
    const val SENDING = 1
    const val FAILED = 2
}

/** A stored attachment: [file] is the name under the encrypted media directory. */
class Media(val file: String, val kind: MediaKind, val width: Long, val height: Long, val durationMs: Long, val desc: String = "")

data class Message(
    val id: String,
    val outgoing: Boolean,
    val sender: String,
    val senderName: String,
    val tsMs: Long,
    /** Local clock when the message was stored or sent; expiry counts from here (spec section 5.2). */
    val baseMs: Long,
    val ttlS: Long,
    val body: String,
    val status: Int = Status.SENT,
    val media: Media? = null,
    /** Set only on the local line that records a timer change: the new timer in seconds. */
    val timer: Long? = null,
)

data class Contact(
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
    /** Profile card received from the contact (spec section 22). */
    val about: String = "",
    val particles: Particles = Particles.None,
    val cardName: String = "",
    val cardTs: Long = 0,
    /** Sender time of the last timer change applied; older changes are ignored. */
    val ttlTs: Long = 0,
)

data class Group(
    val id: String,
    val secret: ByteArray,
    val name: String,
    val members: List<String>,
    val ttlS: Long = 0,
    /** Who made the group; only this member can remove others. Empty for groups saved before this field. */
    val creator: String = "",
    val ttlTs: Long = 0,
) {
    val queueHex: String get() = Hex.encode(QueueIds.group(secret))
}

/** A channel (spec section 15). [official] marks the built-in channel of section 19. */
class Channel(
    val id: String,
    val secret: ByteArray,
    val name: String,
    val owner: String,
    val ownerEd: ByteArray,
    val official: Boolean = false,
) {
    fun mine(me: String) = !official && owner == me
    /** Own channels, plus the official one for `owner` holding the compiled-in key. */
    fun postable(me: String, edSk: ByteArray): Boolean =
        if (!official) owner == me
        else me == org.aegis.messenger.core.Official.OWNER &&
            org.aegis.messenger.core.Official.OWNER_ED_PK?.contentEquals(org.aegis.messenger.core.Crypto.ed25519Public(edSk)) == true
}

class ChatPrefs(val pinned: Boolean = false, val muted: Boolean = false)

class OwnProfile(val name: String = "", val about: String = "", val particles: Particles = Particles.None)

data class Chat(
    val messages: List<Message> = emptyList(),
    val unread: Int = 0,
)

data class Settings(
    val endpoint: String = org.aegis.messenger.net.Endpoint.DEFAULT,
    /** "host:port" of a SOCKS5 proxy, empty for a direct connection. */
    val proxy: String = "",
    val displayName: String = "",
    val idleLockMin: Int = 5,
    val backgroundLockMin: Int = 15,
    val pollSeconds: Int = 30,
    val notifications: Boolean = true,
    /** Idle and background locks; off leaves only the lock on start and the manual one. */
    val appLock: Boolean = true,
    /** Show the chat, sender and text in notifications instead of only "New message". */
    val showContent: Boolean = false,
    /** Directory lookups of this account answer "not found" (spec section 30.4). */
    val hidden: Boolean = false,
)

class VaultData(
    val username: String,
    val xSk: ByteArray,
    val edSk: ByteArray,
    val registered: Boolean = false,
    val contacts: List<Contact> = emptyList(),
    val groups: List<Group> = emptyList(),
    /** Keys are "dm:<username>", "g:<group id>" or "c:<channel id>". */
    val chats: Map<String, Chat> = emptyMap(),
    val seen: List<String> = emptyList(),
    /** Last polled sequence per queue hex. */
    val cursors: Map<String, Long> = emptyMap(),
    val settings: Settings = Settings(),
    val channels: List<Channel> = emptyList(),
    val prefs: Map<String, ChatPrefs> = emptyMap(),
    val profile: OwnProfile = OwnProfile(),
    /** Key for attachments at rest (spec section 13). */
    val mediaKey: ByteArray = org.aegis.messenger.core.Crypto.randomBytes(32),
    /** Pinned owner key of the official channel; null until first seen (spec section 19). */
    val officialOwnerEd: ByteArray? = null,
    val fs: FsState = FsState(),
    val look: Look = Look(),
    /** Invite secrets handed out and not yet used (spec section 30). */
    val invites: List<OpenInvite> = emptyList(),
) {
    fun contact(u: String): Contact? = contacts.firstOrNull { it.username == u }
    fun group(id: String): Group? = groups.firstOrNull { it.id == id }
    fun channel(id: String): Channel? = channels.firstOrNull { it.id == id }
    fun chat(key: String): Chat = chats[key] ?: Chat()
    fun pref(key: String): ChatPrefs = prefs[key] ?: ChatPrefs()

    fun withContact(c: Contact): VaultData = copy(contacts = contacts.filter { it.username != c.username } + c)

    fun copy(
        registered: Boolean = this.registered,
        contacts: List<Contact> = this.contacts,
        groups: List<Group> = this.groups,
        chats: Map<String, Chat> = this.chats,
        seen: List<String> = this.seen,
        cursors: Map<String, Long> = this.cursors,
        settings: Settings = this.settings,
        channels: List<Channel> = this.channels,
        prefs: Map<String, ChatPrefs> = this.prefs,
        profile: OwnProfile = this.profile,
        officialOwnerEd: ByteArray? = this.officialOwnerEd,
        look: Look = this.look,
        invites: List<OpenInvite> = this.invites,
    ) = VaultData(
        username, xSk, edSk, registered, contacts, groups, chats, seen, cursors, settings,
        channels, prefs, profile, mediaKey, officialOwnerEd, fs, look, invites,
    )

    fun withChat(key: String, c: Chat): VaultData = copy(chats = chats + (key to c))

    fun wipe() {
        xSk.fill(0)
        edSk.fill(0)
        mediaKey.fill(0)
        groups.forEach { it.secret.fill(0) }
        channels.forEach { it.secret.fill(0) }
        invites.forEach { it.secret.fill(0) }
    }
}

fun dmKey(username: String) = "dm:$username"
fun groupKey(id: String) = "g:$id"
fun channelKey(id: String) = "c:$id"

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
                "about" to c.about, "particles" to c.particles.wire, "card_name" to c.cardName, "card_ts" to c.cardTs,
                "ttl_ts" to c.ttlTs,
            )
        }
        m["groups"] = v.groups.map { g ->
            mapOf("id" to g.id, "key" to Hex.encode(g.secret), "name" to g.name, "members" to g.members, "ttl" to g.ttlS, "creator" to g.creator, "ttl_ts" to g.ttlTs)
        }
        m["chats"] = v.chats.mapValues { (_, c) ->
            mapOf(
                "unread" to c.unread.toLong(),
                "msgs" to c.messages.map { x ->
                    val e = mapOf(
                        "id" to x.id, "out" to x.outgoing, "s" to x.sender, "sn" to x.senderName, "ts" to x.tsMs,
                        "base" to x.baseMs, "ttl" to x.ttlS, "b" to x.body, "st" to x.status.toLong(),
                        "media" to x.media?.let { md ->
                            mapOf(
                                "file" to md.file, "kind" to md.kind.wire, "w" to md.width, "h" to md.height,
                                "dur" to md.durationMs, "desc" to md.desc,
                            )
                        },
                    )
                    if (x.timer != null) e + ("timer" to x.timer) else e
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
            "app_lock" to s.appLock, "show_content" to s.showContent, "hidden" to s.hidden,
        )
        m["channels"] = v.channels.map { c ->
            mapOf(
                "id" to c.id, "key" to Hex.encode(c.secret), "name" to c.name, "owner" to c.owner,
                "owner_ed" to Hex.encode(c.ownerEd), "official" to c.official,
            )
        }
        m["prefs"] = v.prefs.mapValues { (_, p) -> mapOf("pin" to p.pinned, "mute" to p.muted) }
        m["profile"] = mapOf("name" to v.profile.name, "about" to v.profile.about, "particles" to v.profile.particles.wire)
        m["media_key"] = Hex.encode(v.mediaKey)
        m["official_owner_ed"] = v.officialOwnerEd?.let { Hex.encode(it) }
        m["fs"] = v.fs.toJson()
        m["look"] = v.look.toJson()
        m["invites"] = v.invites.map { mapOf("s" to Hex.encode(it.secret), "exp" to it.expS) }
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
                    (it["about"] as String?) ?: "",
                    (it["particles"] as String?)?.let { p -> Particles.parse(p) } ?: Particles.None,
                    (it["card_name"] as String?) ?: "",
                    (it["card_ts"] as Long?) ?: 0,
                    (it["ttl_ts"] as Long?) ?: 0,
                )
            }
            val groups = list(m, "groups").map {
                Group(str(it, "id"), Hex.decodeFixed(str(it, "key"), 32), str(it, "name"), (it["members"] as List<String>), lng(it, "ttl"), (it["creator"] as String?) ?: "", (it["ttl_ts"] as Long?) ?: 0)
            }
            val chats = (m["chats"] as Map<String, Map<String, Any?>>).mapValues { (_, c) ->
                Chat(
                    list(c, "msgs").map {
                        Message(
                            str(it, "id"), bool(it, "out"), str(it, "s"), str(it, "sn"), lng(it, "ts"), lng(it, "base"),
                            lng(it, "ttl"), str(it, "b"), lng(it, "st").toInt(),
                            (it["media"] as Map<String, Any?>?)?.let { md ->
                                Media(
                                    str(md, "file"), MediaKind.parse(str(md, "kind")), lng(md, "w"), lng(md, "h"),
                                    lng(md, "dur"), (md["desc"] as String?) ?: "",
                                )
                            },
                            it["timer"] as Long?,
                        )
                    },
                    lng(c, "unread").toInt(),
                )
            }
            val st = m["settings"] as Map<String, Any?>
            val settings = Settings(
                str(st, "endpoint"), str(st, "proxy"), str(st, "name"), lng(st, "idle").toInt(), lng(st, "bg").toInt(),
                lng(st, "poll").toInt(), bool(st, "notify"),
                (st["app_lock"] as Boolean?) ?: true, (st["show_content"] as Boolean?) ?: false, (st["hidden"] as Boolean?) ?: false,
            )
            val channels = ((m["channels"] as List<Map<String, Any?>>?) ?: emptyList()).map {
                Channel(
                    str(it, "id"), Hex.decodeFixed(str(it, "key"), 32), str(it, "name"), str(it, "owner"),
                    Hex.decodeFixed(str(it, "owner_ed"), 32), bool(it, "official"),
                )
            }
            val prefs = ((m["prefs"] as Map<String, Map<String, Any?>>?) ?: emptyMap())
                .mapValues { (_, p) -> ChatPrefs(bool(p, "pin"), bool(p, "mute")) }
            val pr = (m["profile"] as Map<String, Any?>?)?.let {
                OwnProfile(str(it, "name"), str(it, "about"), Particles.parse(str(it, "particles")))
            } ?: OwnProfile()
            val mediaKey = (m["media_key"] as String?)?.let { Hex.decodeFixed(it, 32) }
                ?: org.aegis.messenger.core.Crypto.randomBytes(32)
            val officialEd = (m["official_owner_ed"] as String?)?.let { Hex.decodeFixed(it, 32) }
            val invites = ((m["invites"] as List<Map<String, Any?>>?) ?: emptyList()).map {
                OpenInvite(Hex.decodeFixed(str(it, "s"), 32), lng(it, "exp"))
            }
            return VaultData(
                str(m, "username"), Hex.decodeFixed(str(m, "x_sk"), 32), Hex.decodeFixed(str(m, "ed_sk"), 32),
                bool(m, "registered"), contacts, groups, chats, (m["seen"] as List<String>),
                (m["cursors"] as Map<String, Long>), settings,
                channels, prefs, pr, mediaKey, officialEd, FsState.fromJson(m["fs"] as Map<String, Any?>?),
                Look.fromJson(m["look"] as? Map<String, Any?>), invites,
            )
        } catch (e: AegisException) {
            throw e
        } catch (e: Exception) {
            throw AegisException.VaultFormat()
        }
    }
}
