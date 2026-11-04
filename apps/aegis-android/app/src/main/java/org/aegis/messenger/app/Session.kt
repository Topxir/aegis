package org.aegis.messenger.app

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.aegis.messenger.R
import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Bytes
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Envelope
import org.aegis.messenger.core.Expiry
import org.aegis.messenger.core.Group as GroupCrypto
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Identity
import org.aegis.messenger.core.Kind
import org.aegis.messenger.core.Names
import org.aegis.messenger.core.Pad
import org.aegis.messenger.core.PinnedKeys
import org.aegis.messenger.core.Pinning
import org.aegis.messenger.core.QueueIds
import org.aegis.messenger.core.Registration
import org.aegis.messenger.core.Safety
import org.aegis.messenger.core.Seal
import org.aegis.messenger.core.SeenIds
import org.aegis.messenger.core.Text
import org.aegis.messenger.core.Vault
import org.aegis.messenger.data.Chat
import org.aegis.messenger.data.Contact
import org.aegis.messenger.data.Group
import org.aegis.messenger.data.Message
import org.aegis.messenger.data.Settings
import org.aegis.messenger.data.Status
import org.aegis.messenger.data.VaultCodec
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.data.dmKey
import org.aegis.messenger.data.groupKey
import org.aegis.messenger.net.Client
import org.aegis.messenger.net.DirectTransport
import org.aegis.messenger.net.Endpoint
import org.aegis.messenger.net.ProxyAddr
import org.aegis.messenger.net.SocksTransport
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * Process-wide account state. The decrypted vault exists only while [data] is non-null;
 * locking writes it out, wipes the key material and drops every reference.
 */
class Session(private val ctx: Context) {
    companion object {
        const val MIN_PASSWORD = 10
        const val MAX_MESSAGES = 2000
        const val MAX_TEXT_CHARS = 4000
        const val SEEN_CAP = 4000
        private const val MAX_IMPORT = 64 * 1024 * 1024
        private val TTL_CHOICES = longArrayOf(0, 3600, 86400, 604800)
        fun ttlChoices(): LongArray = TTL_CHOICES
    }

    /** Non-null while unlocked. */
    var data by mutableStateOf<VaultData?>(null)
        private set

    /** Resource id of the last user-visible problem, consumed by the UI. */
    var notice by mutableStateOf<Int?>(null)

    var busy by mutableStateOf(false)
        private set

    /** Chat currently on screen; its messages do not count as unread. */
    @Volatile var openChat: String? = null

    @Volatile var foreground = false
        private set

    private val lock = Any()
    private var keyed: Vault.Keyed? = null
    private var file: File? = null
    private var saveQueued = false
    private val main = Handler(Looper.getMainLooper())
    private val saver = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "save").also { it.isDaemon = true } }
    private val net = Executors.newCachedThreadPool { r -> Thread(r, "net").also { it.isDaemon = true } }
    private var poller: Thread? = null
    private val wake = java.util.concurrent.Semaphore(0)
    private var backgroundAt = 0L
    private val idleRunnable = Runnable { lock() }
    private val bgRunnable = Runnable { lock() }

    // ---- account lifecycle -------------------------------------------------

    private fun post(f: () -> Unit) { main.post(f) }

    private fun fail(e: Throwable): Int = when (e) {
        is AegisException.InvalidUsername -> R.string.err_username_invalid
        is AegisException.VaultDecrypt, is AegisException.VaultFormat, is AegisException.VaultParams -> R.string.err_unlock
        is AegisException.Http -> if (e.code == 409) R.string.err_username_taken else R.string.err_network
        is AegisException.Network, is AegisException.BadResponse, is AegisException.InvalidEndpoint -> R.string.err_network
        else -> R.string.err_generic
    }

    private fun vaultFile(username: String) = File(ctx.filesDir, Vault.fileName(username))

    fun accountExists(username: String): Boolean =
        runCatching { vaultFile(Names.normalizeUsername(username)).exists() }.getOrDefault(false)

    /** Creates the account, registers it with the directory when reachable, and unlocks it. */
    fun create(rawUser: String, password: String, displayName: String, endpoint: String, done: (Int?) -> Unit) {
        val user = try { Names.normalizeUsername(rawUser) } catch (e: AegisException) { return done(R.string.err_username_invalid) }
        if (password.codePointCount(0, password.length) < MIN_PASSWORD) return done(R.string.err_password_short)
        val title = Text.sanitizeDisplay(displayName)
        val ep = try { Endpoint.parse(endpoint).origin } catch (e: AegisException) { return done(R.string.err_endpoint_invalid) }
        val f = vaultFile(user)
        if (f.exists()) return done(R.string.err_account_exists)
        busy = true
        net.execute {
            var result: Int? = null
            try {
                val id = Identity.generate()
                val settings = Settings(endpoint = ep, displayName = title)
                var registered = false
                try {
                    val client = clientFor(settings)
                    val existing = client.lookup(user)
                    if (existing != null) throw AegisException.Http(409)
                    client.register(Registration.sign(id, user, title, System.currentTimeMillis() / 1000))
                    registered = true
                } catch (e: AegisException.Network) {
                    // Offline: the account is created locally and registered on the next poll.
                } catch (e: AegisException.BadResponse) {
                    // Same as offline.
                }
                val d = VaultData(user, id.xSecret, id.edSecret, registered, settings = settings)
                val k = Vault.newKeyed(password, Vault.ANDROID)
                writeAtomic(f, k.seal(VaultCodec.encode(d)))
                post { open(d, k, f) }
            } catch (e: Throwable) {
                result = fail(e)
            }
            post { busy = false; done(result) }
        }
    }

    fun unlock(rawUser: String, password: String, done: (Int?) -> Unit) {
        val user = try { Names.normalizeUsername(rawUser) } catch (e: AegisException) { return done(R.string.err_unlock) }
        val f = vaultFile(user)
        busy = true
        net.execute {
            var result: Int? = null
            try {
                if (!f.isFile) throw AegisException.VaultFormat()
                val opened = Vault.decrypt(password, f.readBytes())
                val d = VaultCodec.decode(opened.data)
                opened.data.fill(0)
                if (d.username != user) {
                    opened.keyed.wipe()
                    throw AegisException.VaultFormat()
                }
                post { open(d, opened.keyed, f) }
            } catch (e: Throwable) {
                result = if (e is AegisException || e is java.io.IOException) R.string.err_unlock else fail(e)
            }
            post { busy = false; done(result) }
        }
    }

    private fun open(d: VaultData, k: Vault.Keyed, f: File) {
        synchronized(lock) {
            keyed = k
            file = f
            data = d
        }
        purgeExpired()
        startPoller()
        AegisService.start(ctx)
        touch()
    }

    /** Copies a vault file chosen by the user after proving the password opens it. */
    fun importVault(rawUser: String, password: String, uri: Uri, done: (Int?) -> Unit) {
        val user = try { Names.normalizeUsername(rawUser) } catch (e: AegisException) { return done(R.string.err_username_invalid) }
        val f = vaultFile(user)
        if (f.exists()) return done(R.string.err_account_exists)
        busy = true
        net.execute {
            var result: Int? = null
            try {
                val bytes = ctx.contentResolver.openInputStream(uri)?.use { s ->
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(65536)
                    while (true) {
                        val n = s.read(buf)
                        if (n < 0) break
                        if (out.size() + n > MAX_IMPORT) throw AegisException.VaultFormat()
                        out.write(buf, 0, n)
                    }
                    out.toByteArray()
                } ?: throw AegisException.VaultFormat()
                val opened = Vault.decrypt(password, bytes)
                val d = VaultCodec.decode(opened.data)
                opened.data.fill(0)
                opened.keyed.wipe()
                d.wipe()
                if (d.username != user) throw AegisException.VaultFormat()
                writeAtomic(f, bytes)
            } catch (e: Throwable) {
                result = R.string.err_import
            }
            post { busy = false; done(result) }
        }
    }

    /** Copies the encrypted vault file as-is; works without unlocking. */
    fun exportVault(rawUser: String, uri: Uri, done: (Int?) -> Unit) {
        val user = try { Names.normalizeUsername(rawUser) } catch (e: AegisException) { return done(R.string.err_username_invalid) }
        val f = vaultFile(user)
        busy = true
        net.execute {
            var result: Int? = null
            try {
                if (data?.username == user) flush()
                if (!f.isFile) throw AegisException.VaultFormat()
                ctx.contentResolver.openOutputStream(uri, "wt")?.use { it.write(f.readBytes()) } ?: throw java.io.IOException()
            } catch (e: Throwable) {
                result = R.string.err_export
            }
            post { busy = false; done(result) }
        }
    }

    fun lock() {
        main.removeCallbacks(idleRunnable)
        main.removeCallbacks(bgRunnable)
        stopPoller()
        flush()
        synchronized(lock) {
            data?.wipe()
            keyed?.wipe()
            data = null
            keyed = null
            file = null
        }
        openChat = null
        Notifier.cancelAll(ctx)
        AegisService.stop(ctx)
    }

    /** Removes this account's vault file from the device and locks. */
    fun deleteAccount() {
        val f = synchronized(lock) { file }
        stopPoller()
        synchronized(lock) { saveQueued = false }
        lock()
        f?.delete()
        f?.let { File(it.path + ".tmp").delete() }
    }

    // ---- auto-lock ---------------------------------------------------------

    fun onForeground() {
        foreground = true
        main.removeCallbacks(bgRunnable)
        val d = data ?: return
        val min = d.settings.backgroundLockMin
        if (min >= 0 && backgroundAt != 0L && SystemClock.elapsedRealtime() - backgroundAt >= min * 60_000L) {
            lock()
            return
        }
        backgroundAt = 0
        touch()
    }

    fun onBackground() {
        foreground = false
        main.removeCallbacks(idleRunnable)
        val d = data ?: return
        backgroundAt = SystemClock.elapsedRealtime()
        val min = d.settings.backgroundLockMin
        if (min == 0) lock() else if (min > 0) main.postDelayed(bgRunnable, min * 60_000L)
    }

    /** Called on user interaction; restarts the idle countdown. */
    fun touch() {
        main.removeCallbacks(idleRunnable)
        val min = data?.settings?.idleLockMin ?: return
        if (min > 0 && foreground) main.postDelayed(idleRunnable, min * 60_000L)
    }

    // ---- state mutation and persistence -------------------------------------

    private fun update(f: (VaultData) -> VaultData) {
        synchronized(lock) {
            val d = data ?: return
            data = f(d)
        }
        queueSave()
    }

    private fun queueSave() {
        synchronized(lock) {
            if (saveQueued) return
            saveQueued = true
        }
        saver.schedule({ flush() }, 400, TimeUnit.MILLISECONDS)
    }

    /** Writes the current state to disk now. */
    fun flush() {
        val bytes: ByteArray
        val f: File
        synchronized(lock) {
            saveQueued = false
            val d = data ?: return
            val k = keyed ?: return
            f = file ?: return
            val plain = VaultCodec.encode(d)
            bytes = k.seal(plain)
            plain.fill(0)
        }
        try { writeAtomic(f, bytes) } catch (e: java.io.IOException) { post { notice = R.string.err_save } }
    }

    private fun writeAtomic(target: File, bytes: ByteArray) {
        val tmp = File(target.path + ".tmp")
        FileOutputStream(tmp).use { o ->
            o.write(bytes)
            o.flush()
            o.fd.sync()
        }
        try {
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: java.io.IOException) {
            throw java.io.IOException("rename")
        }
    }

    private fun purgeExpired() {
        val now = System.currentTimeMillis()
        val d = data ?: return
        var changed = false
        val chats = d.chats.mapValues { (_, c) ->
            val kept = c.messages.filter { !Expiry.isExpired(it.baseMs, it.ttlS, now) }
            if (kept.size != c.messages.size) { changed = true; Chat(kept, c.unread) } else c
        }
        if (changed) update { it.copy(chats = chats) }
    }

    fun purgeNow() = purgeExpired()

    // ---- network -----------------------------------------------------------

    private fun clientFor(s: Settings): Client {
        val ep = Endpoint.parse(s.endpoint)
        val tr = if (s.proxy.isBlank()) DirectTransport() else SocksTransport(ProxyAddr.parse(s.proxy))
        return Client(ep, tr)
    }

    fun testConnection(done: (Boolean) -> Unit) {
        val s = data?.settings ?: return done(false)
        busy = true
        net.execute {
            val ok = try { clientFor(s).health() } catch (e: Throwable) { false }
            post { busy = false; done(ok) }
        }
    }

    private fun startPoller() {
        stopPoller()
        val t = Thread({
            try {
                while (!Thread.currentThread().isInterrupted) {
                    val d = data ?: break
                    try { pollOnce() } catch (e: InterruptedException) { throw e } catch (e: Exception) { /* retried next round */ }
                    val base = d.settings.pollSeconds.coerceIn(10, 600) * 1000L
                    val wait = base - base / 4 + Random.nextLong(base / 2 + 1)
                    wake.tryAcquire(wait, TimeUnit.MILLISECONDS)
                    wake.drainPermits()
                }
            } catch (e: InterruptedException) {
                // stopped
            }
        }, "poll")
        t.isDaemon = true
        poller = t
        t.start()
    }

    private fun stopPoller() {
        poller?.interrupt()
        poller = null
    }

    /** Asks the poller to run now (for example when the app returns to the foreground). */
    fun pollSoon() {
        wake.release()
    }

    private fun pollOnce() {
        purgeExpired()
        val d0 = data ?: return
        val client = clientFor(d0.settings)
        if (!d0.registered) {
            val id = Identity(d0.xSk, d0.edSk)
            val reg = Registration.sign(id, d0.username, d0.settings.displayName, System.currentTimeMillis() / 1000)
            id.wipe()
            client.register(reg)
            update { it.copy(registered = true) }
        }
        retryPending()
        var incoming = 0
        val inbox = QueueIds.inbox(Crypto.x25519Public(d0.xSk))
        incoming += drain(client, inbox, null)
        for (g in (data ?: return).groups) incoming += drain(client, Hex.decode(g.queueHex), g)
        if (incoming > 0 && !foreground && (data?.settings?.notifications == true)) Notifier.newMessage(ctx)
    }

    private fun drain(client: Client, queue: ByteArray, group: Group?): Int {
        val qHex = Hex.encode(queue)
        var count = 0
        var rounds = 0
        while (rounds++ < 10) {
            val d = data ?: return count
            val after = d.cursors[qHex] ?: 0L
            val polled = client.poll(queue, after)
            for ((seq, padded) in polled.frames) {
                count += handleFrame(client, padded, group)
                update { it.copy(cursors = it.cursors + (qHex to seq)) }
            }
            if (polled.frames.size < Client.MAX_POLL) break
        }
        return count
    }

    /** Returns the number of new incoming messages. Lookup failures propagate so the cursor stays put. */
    private fun handleFrame(client: Client, padded: ByteArray, group: Group?): Int {
        val d = data ?: return 0
        try {
            val frame = Pad.unpad(padded)
            return if (group == null) {
                val o = Seal.openDm(d.xSk, frame)
                ingest(client, o.envelope, o.senderXPk, null)
            } else {
                ingest(client, GroupCrypto.decrypt(group.secret, frame), null, group)
            }
        } catch (e: AegisException.Network) {
            throw e
        } catch (e: AegisException.Http) {
            throw e
        } catch (e: AegisException.BadResponse) {
            throw e
        } catch (e: AegisException.InvalidEndpoint) {
            throw e
        } catch (e: AegisException) {
            return 0
        }
    }

    private fun markSeen(id: String) {
        update { it.copy(seen = SeenIds(SEEN_CAP, it.seen).also { s -> s.insert(id) }.toList()) }
    }

    private fun ingest(client: Client, env: Envelope, senderX: ByteArray?, group: Group?): Int {
        val d = data ?: return 0
        if (env.sender == d.username) return 0
        if (SeenIds(SEEN_CAP, d.seen).contains(env.msgId)) return 0
        var contact = d.contact(env.sender)
        if (contact == null) {
            val e = client.lookup(env.sender)
            if (e == null || !Bytes.eq(e.ed, env.senderEd) || (senderX != null && !Bytes.eq(e.x, senderX))) {
                markSeen(env.msgId)
                return 0
            }
            contact = Contact(env.sender, e.title, e.x, e.ed)
            update { it.withContact(contact) }
        } else {
            val pinned = PinnedKeys(contact.x, contact.ed)
            try {
                if (group == null) Pinning.checkDm(env, senderX!!, pinned) else Pinning.checkGroup(env, pinned)
            } catch (e: AegisException.SenderMismatch) {
                val c = contact
                update {
                    it.withContact(
                        Contact(c.username, c.title, c.x, c.ed, false, true, senderX?.copyOf(), env.senderEd.copyOf(), c.ttlS),
                    )
                }
                markSeen(env.msgId)
                return 0
            }
        }
        val now = System.currentTimeMillis()
        markSeen(env.msgId)
        return when (env.kind) {
            Kind.Dm -> {
                if (group != null) return 0
                addIncoming(dmKey(env.sender), env, now)
            }
            Kind.Gmsg -> {
                if (group == null || env.sender !in group.members) return 0
                addIncoming(groupKey(group.id), env, now)
            }
            Kind.Ginv -> {
                if (group != null) return 0
                acceptInvite(env)
                1
            }
        }
    }

    private fun addIncoming(key: String, env: Envelope, now: Long): Int {
        val base = minOf(env.tsMs, now)
        if (Expiry.isExpired(base, env.ttlS, now)) return 0
        val m = Message(env.msgId, false, env.sender, env.senderName, env.tsMs, base, env.ttlS, env.body)
        update { d ->
            val c = d.chat(key)
            val unread = if (openChat == key && foreground) c.unread else c.unread + 1
            d.withChat(key, Chat((c.messages + m).takeLast(MAX_MESSAGES), unread))
        }
        return 1
    }

    private fun acceptInvite(env: Envelope) {
        val key = env.groupKey ?: return
        update { d ->
            if (d.group(env.groupId) != null) return@update d
            if (d.username !in env.members || env.sender !in env.members) return@update d
            val g = Group(env.groupId, key.copyOf(), Text.sanitizeDisplay(env.body), env.members, env.ttlS)
            d.copy(groups = d.groups + g)
        }
    }

    // ---- contacts ----------------------------------------------------------

    /** Exact-username lookup; pins the key it returns on first sight. */
    fun addContact(raw: String, done: (String?, Int?) -> Unit) {
        val d = data ?: return done(null, R.string.err_generic)
        val user = try { Names.normalizeUsername(raw.trim().removePrefix("@")) } catch (e: AegisException) {
            return done(null, R.string.err_username_invalid)
        }
        if (user == d.username) return done(null, R.string.err_self)
        if (d.contact(user) != null) return done(user, null)
        busy = true
        net.execute {
            var err: Int? = null
            try {
                val e = clientFor(d.settings).lookup(user)
                if (e == null) err = R.string.err_not_found else update { cur ->
                    if (cur.contact(user) != null) cur else cur.withContact(Contact(user, e.title, e.x, e.ed))
                }
            } catch (e: Throwable) {
                err = fail(e)
            }
            post { busy = false; done(if (err == null) user else null, err) }
        }
    }

    fun setVerified(user: String, v: Boolean) = update { d ->
        val c = d.contact(user) ?: return@update d
        d.withContact(Contact(c.username, c.title, c.x, c.ed, v, c.keyChanged, c.pendingX, c.pendingEd, c.ttlS))
    }

    /** Keeps the key pinned earlier and clears the warning. */
    fun keepOldKey(user: String) = update { d ->
        val c = d.contact(user) ?: return@update d
        d.withContact(Contact(c.username, c.title, c.x, c.ed, c.verified, false, null, null, c.ttlS))
    }

    /** Replaces the pinned key with the one that triggered the warning; verification is reset. */
    fun acceptNewKey(user: String, done: (Int?) -> Unit) {
        val d = data ?: return done(R.string.err_generic)
        val c = d.contact(user) ?: return done(R.string.err_generic)
        val ped = c.pendingEd ?: return done(R.string.err_generic)
        val px = c.pendingX
        if (px != null) {
            update { cur ->
                cur.withContact(Contact(user, c.title, px, ped, false, false, null, null, c.ttlS))
            }
            return done(null)
        }
        busy = true
        net.execute {
            var err: Int? = null
            try {
                val e = clientFor(d.settings).lookup(user)
                if (e == null || !Bytes.eq(e.ed, ped)) err = R.string.err_key_unconfirmed
                else update { cur -> cur.withContact(Contact(user, e.title, e.x, e.ed, false, false, null, null, c.ttlS)) }
            } catch (e: Throwable) {
                err = fail(e)
            }
            post { busy = false; done(err) }
        }
    }

    fun safetyNumber(c: Contact): String? {
        val d = data ?: return null
        val id = Identity(d.xSk, d.edSk)
        val n = Safety.number(id.edPublic, id.xPublic, c.ed, c.x)
        id.wipe()
        return n
    }

    fun setChatTtl(key: String, ttlS: Long) {
        if (ttlS !in TTL_CHOICES) return
        update { d ->
            if (key.startsWith("dm:")) {
                val c = d.contact(key.removePrefix("dm:")) ?: return@update d
                d.withContact(Contact(c.username, c.title, c.x, c.ed, c.verified, c.keyChanged, c.pendingX, c.pendingEd, ttlS))
            } else {
                val g = d.group(key.removePrefix("g:")) ?: return@update d
                d.copy(groups = d.groups.map { if (it.id == g.id) Group(g.id, g.secret, g.name, g.members, ttlS) else it })
            }
        }
    }

    fun markRead(key: String) = update { d ->
        val c = d.chats[key]
        if (c == null || c.unread == 0) d else d.withChat(key, Chat(c.messages, 0))
    }

    fun deleteChatHistory(key: String) = update { d -> d.withChat(key, Chat()) }

    // ---- sending -----------------------------------------------------------

    private fun newId(): String = Hex.encode(Crypto.randomBytes(16))

    fun sendDm(user: String, rawText: String) {
        val d = data ?: return
        val c = d.contact(user) ?: return
        if (c.keyChanged) { notice = R.string.err_key_changed_block; return }
        val text = Text.sanitizeBody(rawText).trim()
        if (text.isEmpty()) return
        if (text.length > MAX_TEXT_CHARS) { notice = R.string.err_too_large; return }
        val now = System.currentTimeMillis()
        val m = Message(newId(), true, d.username, d.settings.displayName, now, now, c.ttlS, text, Status.SENDING)
        appendOutgoing(dmKey(user), m)
        deliver(dmKey(user), m)
    }

    fun sendGroup(id: String, rawText: String) {
        val d = data ?: return
        val g = d.group(id) ?: return
        val text = Text.sanitizeBody(rawText).trim()
        if (text.isEmpty()) return
        if (text.length > MAX_TEXT_CHARS) { notice = R.string.err_too_large; return }
        val now = System.currentTimeMillis()
        val m = Message(newId(), true, d.username, d.settings.displayName, now, now, g.ttlS, text, Status.SENDING)
        appendOutgoing(groupKey(id), m)
        deliver(groupKey(id), m)
    }

    private fun appendOutgoing(key: String, m: Message) = update { d ->
        val c = d.chat(key)
        d.withChat(key, Chat((c.messages + m).takeLast(MAX_MESSAGES), c.unread))
            .copy(seen = SeenIds(SEEN_CAP, d.seen).also { it.insert(m.id) }.toList())
    }

    private fun setStatus(key: String, id: String, status: Int) = update { d ->
        val c = d.chats[key] ?: return@update d
        d.withChat(key, Chat(c.messages.map { if (it.id == id) Message(it.id, it.outgoing, it.sender, it.senderName, it.tsMs, it.baseMs, it.ttlS, it.body, status) else it }, c.unread))
    }

    fun retry(key: String, id: String) {
        val m = data?.chats?.get(key)?.messages?.firstOrNull { it.id == id && it.outgoing && it.status == Status.FAILED } ?: return
        setStatus(key, id, Status.SENDING)
        deliver(key, m)
    }

    private fun deliver(key: String, m: Message) {
        net.execute {
            val status = try {
                val d = data ?: return@execute
                val id = Identity(d.xSk, d.edSk)
                try {
                    val client = clientFor(d.settings)
                    if (key.startsWith("dm:")) {
                        val c = d.contact(key.removePrefix("dm:")) ?: throw AegisException.InvalidUsername()
                        if (c.keyChanged) throw AegisException.SenderMismatch()
                        val env = Envelope(Kind.Dm, m.id, d.username, m.senderName, id.edPublic, m.tsMs, m.ttlS, "", m.body)
                        client.send(QueueIds.inbox(c.x), Seal.sealDm(id.xSecret, c.x, env))
                    } else {
                        val g = d.group(key.removePrefix("g:")) ?: throw AegisException.GroupMismatch()
                        val env = Envelope(Kind.Gmsg, m.id, d.username, m.senderName, id.edPublic, m.tsMs, m.ttlS, g.id, m.body)
                        client.send(Hex.decode(g.queueHex), GroupCrypto.encrypt(g.secret, id.edSecret, env))
                    }
                } finally {
                    id.wipe()
                }
                Status.SENT
            } catch (e: AegisException.FrameTooLarge) {
                post { notice = R.string.err_too_large }
                Status.FAILED
            } catch (e: Exception) {
                Status.FAILED
            }
            setStatus(key, m.id, status)
        }
    }

    private fun retryPending() {
        // Failed messages are retried manually; sending ones stuck after a process death are marked failed.
        val d = data ?: return
        if (d.chats.values.none { c -> c.messages.any { it.status == Status.SENDING } }) return
        // A message being sent right now is also SENDING, so only touch ones older than a minute.
        val cutoff = System.currentTimeMillis() - 60_000
        update { cur ->
            cur.copy(
                chats = cur.chats.mapValues { (_, c) ->
                    Chat(c.messages.map { if (it.status == Status.SENDING && it.tsMs < cutoff) Message(it.id, it.outgoing, it.sender, it.senderName, it.tsMs, it.baseMs, it.ttlS, it.body, Status.FAILED) else it }, c.unread)
                },
            )
        }
    }

    // ---- groups ------------------------------------------------------------

    fun createGroup(rawName: String, members: List<String>, done: (String?, Int?) -> Unit) {
        val d = data ?: return done(null, R.string.err_generic)
        val name = Text.sanitizeDisplay(rawName).trim()
        if (name.isEmpty()) return done(null, R.string.err_group_name)
        val all = (listOf(d.username) + members.filter { it != d.username }).distinct()
        if (all.size < 2) return done(null, R.string.err_group_members)
        if (all.size > Envelope.MAX_MEMBERS) return done(null, R.string.err_group_size)
        if (members.any { m -> d.contact(m)?.keyChanged != false }) return done(null, R.string.err_key_changed_block)
        val secret = GroupCrypto.newSecret()
        val g = Group(GroupCrypto.groupId(secret), secret, name, all, 0)
        update { it.copy(groups = it.groups + g) }
        sendInvites(g.id, null)
        done(g.id, null)
    }

    fun resendInvites(groupId: String) = sendInvites(groupId, null)

    private fun sendInvites(groupId: String, onlyFor: String?) {
        net.execute {
            var failed = 0
            val d = data ?: return@execute
            val g = d.group(groupId) ?: return@execute
            val id = Identity(d.xSk, d.edSk)
            try {
                val client = clientFor(d.settings)
                for (u in g.members) {
                    if (u == d.username || (onlyFor != null && u != onlyFor)) continue
                    try {
                        val c = d.contact(u) ?: throw AegisException.InvalidUsername()
                        val env = Envelope(
                            Kind.Ginv, newId(), d.username, d.settings.displayName, id.edPublic,
                            System.currentTimeMillis(), g.ttlS, g.id, g.name, g.secret, g.members,
                        )
                        client.send(QueueIds.inbox(c.x), Seal.sealDm(id.xSecret, c.x, env))
                    } catch (e: Exception) {
                        failed++
                    }
                }
            } catch (e: Exception) {
                failed++
            } finally {
                id.wipe()
            }
            if (failed > 0) post { notice = R.string.err_invites }
        }
    }

    /** Leaving only deletes the local copy; other members are not told. */
    fun leaveGroup(id: String) = update { d ->
        val g = d.group(id) ?: return@update d
        g.secret.fill(0)
        d.copy(groups = d.groups.filter { it.id != id }, chats = d.chats - groupKey(id), cursors = d.cursors - g.queueHex)
    }

    // ---- settings ----------------------------------------------------------

    fun saveSettings(s: Settings, done: (Int?) -> Unit) {
        try { Endpoint.parse(s.endpoint) } catch (e: AegisException) { return done(R.string.err_endpoint_invalid) }
        if (s.proxy.isNotBlank()) try { ProxyAddr.parse(s.proxy) } catch (e: AegisException) { return done(R.string.err_proxy_invalid) }
        val title = Text.sanitizeDisplay(s.displayName)
        val clean = Settings(
            Endpoint.parse(s.endpoint).origin, if (s.proxy.isBlank()) "" else ProxyAddr.parse(s.proxy).toString(), title,
            s.idleLockMin, s.backgroundLockMin, s.pollSeconds.coerceIn(10, 600), s.notifications,
        )
        update { d ->
            val endpointChanged = d.settings.endpoint != clean.endpoint
            val renamed = d.settings.displayName != clean.displayName
            // A different server or display name needs a fresh directory registration; cursors belong to the old server.
            d.copy(
                settings = clean,
                registered = d.registered && !endpointChanged && !renamed,
                cursors = if (endpointChanged) emptyMap() else d.cursors,
            )
        }
        touch()
        pollSoon()
        done(null)
    }
}
