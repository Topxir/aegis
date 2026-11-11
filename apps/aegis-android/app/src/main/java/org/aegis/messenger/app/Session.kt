package org.aegis.messenger.app

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.aegis.messenger.R
import org.aegis.messenger.core.AegisException
import org.aegis.messenger.core.Attach
import org.aegis.messenger.core.AttachmentDescriptor
import org.aegis.messenger.core.AttachmentMeta
import org.aegis.messenger.core.Bytes
import org.aegis.messenger.core.Channel as ChannelCrypto
import org.aegis.messenger.core.MediaKind
import org.aegis.messenger.core.Official
import org.aegis.messenger.core.Particles
import org.aegis.messenger.core.Profile
import org.aegis.messenger.core.Crypto
import org.aegis.messenger.core.Encrypted
import org.aegis.messenger.core.Envelope
import org.aegis.messenger.core.RecvSet
import org.aegis.messenger.core.SendChain
import org.aegis.messenger.core.SessionAction
import org.aegis.messenger.core.SkScope
import org.aegis.messenger.core.Prekeys
import org.aegis.messenger.core.SenderKey
import org.aegis.messenger.core.Expiry
import org.aegis.messenger.core.Group as GroupCrypto
import org.aegis.messenger.core.Hex
import org.aegis.messenger.core.Identity
import org.aegis.messenger.core.Invite
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
import org.aegis.messenger.data.Channel
import org.aegis.messenger.data.Chat
import org.aegis.messenger.data.ChatPrefs
import org.aegis.messenger.data.Media
import org.aegis.messenger.data.OwnProfile
import org.aegis.messenger.data.channelKey
import org.aegis.messenger.core.SessionStore
import org.aegis.messenger.data.Contact
import org.aegis.messenger.data.FsState
import org.aegis.messenger.data.Invites
import org.aegis.messenger.data.Group
import org.aegis.messenger.data.Message
import org.aegis.messenger.data.Settings
import org.aegis.messenger.data.Status
import org.aegis.messenger.data.VaultCodec
import org.aegis.messenger.data.VaultData
import org.aegis.messenger.data.dmKey
import org.aegis.messenger.data.groupKey
import org.aegis.messenger.net.Client
import org.aegis.messenger.net.DirEntry
import org.aegis.messenger.net.DirectTransport
import org.aegis.messenger.net.Endpoint
import org.aegis.messenger.net.Response
import org.aegis.messenger.net.Route
import org.aegis.messenger.net.Transport
import org.aegis.messenger.core.SlotGate
import org.aegis.messenger.net.ProxyAddr
import org.aegis.messenger.net.SocksTransport
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

import java.util.concurrent.Executors
import org.aegis.messenger.core.CoverMode
import org.aegis.messenger.core.CoverScheduler
import org.aegis.messenger.core.CoverSlot
import org.aegis.messenger.core.CoverTick
import org.aegis.messenger.core.OsCoverRng
import org.aegis.messenger.core.Pin
import org.aegis.messenger.net.PinOpen
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * Process-wide account state. The decrypted vault exists only while [data] is non-null;
 * locking writes it out, wipes the key material and drops every reference.
 */
class Session(private val ctx: Context) {
    companion object {
        /** Poll interval while the app is on screen, so new messages show up within seconds. */
        private const val FG_POLL_MS = 2_500L
        const val MIN_PASSWORD = 10
        const val MAX_MESSAGES = 2000
        const val MAX_TEXT_CHARS = 4000
        const val SEEN_CAP = 4000
        const val MAX_CAPTION = Attach.MAX_CAPTION
        private const val MAX_IMPORT = 64 * 1024 * 1024
        fun ttlChoices(): List<Long> = Expiry.TTL_CHOICES
    }

    /** Non-null while unlocked. */
    var data by mutableStateOf<VaultData?>(null)
        private set

    /** Resource id of the last user-visible problem, consumed by the UI. */
    var notice by mutableStateOf<Int?>(null)

    var busy by mutableStateOf(false)
        private set

    /** Origin whose pinned server key changed; the UI shows a stop screen while this is set. */
    var keyChangedOrigin by mutableStateOf<String?>(null)
        private set

    init {
        AppPins.onKeyChanged = { o -> post { keyChangedOrigin = o } }
    }

    /** Hides the stop screen without trusting the key; the next request raises it again. */
    fun dismissKeyChanged() { keyChangedOrigin = null }

    /** The user accepted the new server key: forget the old pin so the next request pins the new one. */
    fun trustNewServerKey() {
        val o = keyChangedOrigin ?: return
        AppPins.pins.remove(o)
        keyChangedOrigin = null
    }

    /** Chat currently on screen; its messages do not count as unread. */
    @Volatile var openChat: String? = null

    @Volatile var foreground = false
        private set

    private val lock = Any()

    private fun store(): MediaStore? {
        val d = data ?: return null
        return MediaStore(File(ctx.filesDir, Vault.fileName(d.username) + ".media"))
    }

    private fun dropMedia(messages: List<Message>) {
        val st = store() ?: return
        messages.forEach { m -> m.media?.let { st.delete(it.file) } }
    }

    /** Decrypted attachment bytes for display, held in memory only. Null if unreadable. */
    fun loadMedia(m: Media): ByteArray? {
        val d = data ?: return null
        return try { store()?.load(d.mediaKey, m.file) } catch (e: Exception) { null }
    }
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
        is AegisException.NeedsUpdate -> R.string.err_contact_update
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
                    client.register(Registration.sign(id, user, "", System.currentTimeMillis() / 1000))
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
        ensureOfficial()
        syncFsContacts(d)
        purgeExpired()
        Boot.setAppLock(ctx, d.settings.appLock)
        startPoller()
        AegisService.start(ctx)
        if (Boot.backgroundPoll(ctx)) BgState.store(ctx, d.settings.endpoint, d.settings.proxy, d.xSk) else BgState.clear(ctx)
        BgState.schedule(ctx, Boot.backgroundPoll(ctx))
        touch()
    }

    private fun ensureOfficial() = update { d ->
        if (d.channels.any { it.official }) d
        else d.copy(channels = d.channels + Channel(Official.channelId(), Official.g(), "Aegis", Official.OWNER, d.officialOwnerEd ?: ByteArray(32), true))
    }

    /** Copies a vault file chosen by the user after proving the password opens it. */
    fun importVault(rawUser: String, password: String, uri: Uri, done: (Int?) -> Unit) {
        // A blank username takes the one inside the vault.
        val named = if (rawUser.isBlank()) null else try { Names.normalizeUsername(rawUser) } catch (e: AegisException) { return done(R.string.err_username_invalid) }
        if (named != null && vaultFile(named).exists()) return done(R.string.err_account_exists)
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
                val vu = d.username
                opened.keyed.wipe()
                d.wipe()
                if (named != null && vu != named) throw AegisException.VaultFormat()
                val f = vaultFile(vu)
                if (f.exists()) result = R.string.err_account_exists else writeAtomic(f, bytes)
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
        gate.reset()
        post { refreshPin() }
        openChat = null
        inviteLink = null
        synchronized(accepts) { accepts.clear() }
        Notifier.cancelAll(ctx)
        AegisService.stop(ctx)
    }

    // ---- PIN and duress (spec section 20) ----------------------------------

    /** Result of a PIN attempt: a message, and the tries left when the server counted a wrong PIN. */
    class PinOutcome(val msg: Int?, val left: Int? = null)

    var pinSet by mutableStateOf(false)
        private set
    var duressSet by mutableStateOf(false)
        private set

    init { refreshPin() }

    private fun pinFile(user: String) = File(ctx.filesDir, Vault.fileName(user) + ".pin")
    private fun duressFile() = File(ctx.filesDir, "duress.rec")

    private fun refreshPin() {
        val u = Boot.pinUser(ctx)
        pinSet = u.isNotEmpty() && pinFile(u).isFile
        duressSet = pinSet && duressFile().isFile
    }

    val pinDigits: Int get() = if (pinGhost) ghostDigits else Boot.pinDigits(ctx)

    /** Forgets the PIN on this device. The password still opens the vault. */
    private fun clearPinLocal() {
        val u = Boot.pinUser(ctx)
        if (u.isNotEmpty()) pinFile(u).delete()
        duressFile().delete()
        Boot.clearPin(ctx)
        post { refreshPin() }
    }

    /** Sets a PIN for the unlocked account; the vault key is wrapped with it and S goes to the server. */
    fun pinSetup(pin: String, done: (Int?) -> Unit) {
        val d = data ?: return done(R.string.err_generic)
        if (pinSet || !Pin.isValidPin(pin)) return done(R.string.err_generic)
        val k = synchronized(lock) { keyed?.exportKey() } ?: return done(R.string.err_generic)
        val user = d.username
        val st = d.settings
        busy = true
        net.execute {
            var result: Int? = null
            try {
                val setup = Pin.setup(pin, k)
                try {
                    clientFor(st).pinCreate(setup.file.slot, setup.verifier, setup.s)
                    writeAtomic(pinFile(user), setup.file.encode())
                    Boot.setPin(ctx, user, st.endpoint, st.proxy, pin.length)
                } finally {
                    setup.s.fill(0)
                }
            } catch (e: Throwable) {
                result = fail(e)
            } finally {
                k.fill(0)
            }
            post { refreshPin(); busy = false; done(result) }
        }
    }

    /** Removes the PIN: the server slot is deleted with the current PIN, then the local files go. */
    fun pinRemove(pin: String, done: (Int?) -> Unit) {
        val user = Boot.pinUser(ctx)
        if (user.isEmpty() || !Pin.isValidPin(pin)) return done(R.string.err_pin_wrong)
        busy = true
        net.execute {
            var result: Int? = null
            try {
                val pf = Pin.PinFile.parse(pinFile(user).readBytes())
                val key = pf.derive(pin)
                try {
                    val c = clientFor(Boot.pinEndpoint(ctx), Boot.pinProxy(ctx))
                    c.pinDelete(pf.slot, key.verifier())
                } finally {
                    key.wipe()
                }
                clearPinLocal()
            } catch (e: AegisException.Http) {
                result = R.string.err_pin_wrong
            } catch (e: Throwable) {
                result = fail(e)
            }
            post { busy = false; done(result) }
        }
    }

    /** Sets the duress PIN: the real PIN is checked with pin_open first, the duress PIN must differ. Stored only on this device. */
    fun duressSetup(realPin: String, pin: String, done: (Int?) -> Unit) {
        val user = Boot.pinUser(ctx)
        if (!pinSet || user.isEmpty() || !Pin.isValidPin(pin) || !Pin.isValidPin(realPin)) return done(R.string.err_generic)
        if (pin == realPin) return done(R.string.duress_same)
        busy = true
        net.execute {
            var result: Int? = null
            try {
                val pf = Pin.PinFile.parse(pinFile(user).readBytes())
                val key = pf.derive(realPin)
                try {
                    val c = clientFor(Boot.pinEndpoint(ctx), Boot.pinProxy(ctx))
                    when (val r = c.pinOpen(pf.slot, key.verifier())) {
                        is PinOpen.Ok -> {
                            r.s.fill(0)
                            writeAtomic(duressFile(), Pin.DuressRecord.create(pin).encode())
                        }
                        is PinOpen.Wrong -> {
                            if (r.left == 0) { clearPinLocal(); result = R.string.err_pin_gone } else result = R.string.err_pin_wrong
                        }
                        PinOpen.Gone -> { clearPinLocal(); result = R.string.err_pin_gone }
                        PinOpen.Throttled -> result = R.string.err_pin_throttled
                    }
                } finally {
                    key.wipe()
                }
            } catch (e: Throwable) {
                result = if (e is AegisException && e !is AegisException.Network && e !is AegisException.Http && e !is AegisException.BadResponse) R.string.err_save else fail(e)
            }
            post { refreshPin(); busy = false; done(result) }
        }
    }

    fun duressRemove() {
        duressFile().delete()
        refreshPin()
    }

    /** Last tries-left value the server reported; the duress wipe shows it back. */
    @Volatile private var lastLeft: Int? = null

    /** Set after a duress wipe: the lock screen keeps acting like a real PIN screen with a counter. */
    var pinGhost by mutableStateOf(false)
        private set
    private var ghostLeft = 4
    private var ghostDigits = 4

    /** Deletes the vault, the PIN files and the media folder of [user] from this device (spec section 25). */
    private fun duressWipe(user: String) {
        val name = Vault.fileName(user)
        val vf = vaultFile(user)
        MediaStore(File(ctx.filesDir, "$name.media")).deleteAll()
        File(ctx.filesDir, "$name.media").deleteRecursively()
        vf.delete()
        File(vf.path + ".tmp").delete()
        pinFile(user).delete()
        duressFile().delete()
        Boot.clearPin(ctx)
        BgState.clear(ctx)
        BgState.schedule(ctx, false)
    }

    /** Unlocks with the PIN. A duress PIN is checked first, on this device: it wipes the vault and shows the wrong-PIN result. */
    fun pinUnlock(pin: String, done: (PinOutcome) -> Unit) {
        if (pinGhost) {
            if (pin.length != ghostDigits) return done(PinOutcome(R.string.err_pin_wrong))
            busy = true
            net.execute {
                // Same key derivation as a real attempt, so the delay looks alike.
                try { Pin.DuressRecord.create(pin).matches(pin) } catch (e: Exception) { /* timing only */ }
                try { Thread.sleep(400) } catch (e: InterruptedException) { /* ignore */ }
                ghostLeft--
                val out = if (ghostLeft > 0) PinOutcome(R.string.err_pin_wrong, ghostLeft) else PinOutcome(R.string.err_pin_gone)
                post { if (ghostLeft <= 0) pinGhost = false; busy = false; done(out) }
            }
            return
        }
        val user = Boot.pinUser(ctx)
        if (user.isEmpty() || !Pin.isValidPin(pin)) return done(PinOutcome(R.string.err_pin_wrong))
        busy = true
        net.execute {
            var out = PinOutcome(null)
            try {
                val dur = try { Pin.DuressRecord.parse(duressFile().readBytes()) } catch (e: Exception) { null }
                if (dur != null && dur.matches(pin)) {
                    ghostDigits = Boot.pinDigits(ctx)
                    duressWipe(user)
                    ghostLeft = lastLeft ?: 4
                    out = PinOutcome(R.string.err_pin_wrong, ghostLeft)
                    post { pinGhost = true; refreshPin() }
                } else {
                    val pf = Pin.PinFile.parse(pinFile(user).readBytes())
                    val key = pf.derive(pin)
                    try {
                        val c = clientFor(Boot.pinEndpoint(ctx), Boot.pinProxy(ctx))
                        when (val r = c.pinOpen(pf.slot, key.verifier())) {
                            is PinOpen.Ok -> {
                                lastLeft = null
                                val vk = pf.unwrap(key, r.s)
                                r.s.fill(0)
                                val f = vaultFile(user)
                                val opened = try { Vault.decryptWithKey(vk, f.readBytes()) } finally { vk.fill(0) }
                                val d = VaultCodec.decode(opened.data)
                                opened.data.fill(0)
                                if (d.username != user) {
                                    opened.keyed.wipe()
                                    throw AegisException.VaultFormat()
                                }
                                post { open(d, opened.keyed, f) }
                            }
                            is PinOpen.Wrong -> {
                                lastLeft = r.left
                                if (r.left == 0) {
                                    clearPinLocal()
                                    out = PinOutcome(R.string.err_pin_gone)
                                } else {
                                    out = PinOutcome(R.string.err_pin_wrong, r.left)
                                }
                            }
                            PinOpen.Gone -> {
                                clearPinLocal()
                                out = PinOutcome(R.string.err_pin_gone)
                            }
                            PinOpen.Throttled -> out = PinOutcome(R.string.err_pin_throttled)
                        }
                    } finally {
                        key.wipe()
                    }
                }
            } catch (e: Throwable) {
                out = PinOutcome(if (e is AegisException && e !is AegisException.Network && e !is AegisException.Http && e !is AegisException.BadResponse) R.string.err_unlock else fail(e))
            }
            post { busy = false; done(out) }
        }
    }

    // ---- cover traffic (spec section 26) ------------------------------------

    @Volatile private var pollNow = false
    @Volatile private var early = false
    @Volatile private var sched: CoverScheduler? = null
    @Volatile private var pollRunning = false
    private val gate = SlotGate({ coverMode() != CoverMode.Off && foreground }, { early = true; wake.release() })
    private val coverRng = OsCoverRng()

    /**
     * Runs [task] on a worker. With cover traffic on and the app in the foreground every request the
     * task makes waits for its own slot (see [gate]), so a task with several requests spreads them
     * over several slots instead of sending them back to back.
     */
    private fun realRequest(task: Runnable) {
        net.execute(task)
    }

    /** A client whose requests take one cover slot each. */
    private fun gatedClient(endpoint: String, proxy: String): Client =
        clientFor(endpoint, proxy) { t ->
            object : Transport {
                override fun request(ep: Endpoint, method: String, pathQuery: String, body: ByteArray?, contentType: String?): Response =
                    gate.pass { t.request(ep, method, pathQuery, body, contentType) }
            }
        }

    private fun sendDummy(d: VaultData, reqLen: Int, respLen: Int) {
        try {
            val got = clientFor(d.settings.endpoint, d.settings.proxy).nop(reqLen, respLen)
            sched?.let { sc -> synchronized(sc) { sc.recordResponse(got) } }
        } catch (e: InterruptedException) {
            throw e
        } catch (e: Exception) {
            // A failed dummy is not retried.
        }
    }

    private fun startPollCycle() {
        pollRunning = true
        net.execute {
            try {
                gate.asPoll { pollOnce() }
            } catch (e: Exception) {
                // retried next round
            } finally {
                pollRunning = false
                lastPollAt = SystemClock.elapsedRealtime()
                // A slot that was given to this cycle but not used still carries one request.
                if (gate.takeCredit()) data?.let { sendDummy(it, 64, 1024) }
            }
        }
    }

    @Volatile private var lastPollAt = 0L

    private fun coverMode(): CoverMode = when (Boot.coverMode(ctx)) {
        0 -> CoverMode.Off
        2 -> CoverMode.High
        else -> CoverMode.Standard
    }

    /** Tells the runner that the cover setting changed. */
    fun coverChanged() { wake.release() }

    private fun runLoop() {
        val sched = CoverScheduler(coverMode(), SystemClock.elapsedRealtime(), coverRng)
        this.sched = sched
        var lastPoll = 0L
        while (!Thread.currentThread().isInterrupted) {
            val d = data ?: break
            val mode = coverMode()
            val now = SystemClock.elapsedRealtime()
            val pollMs = if (foreground) FG_POLL_MS else d.settings.pollSeconds.coerceIn(10, 600) * 1000L
            if (mode != sched.mode) sched.setMode(mode, now, coverRng)
            if (early) {
                early = false
                sched.earlySlot(now)
            }
            if (mode == CoverMode.Off || !foreground) {
                if (pollNow || now - lastPoll >= pollMs - pollMs / 4) {
                    pollNow = false
                    try { pollOnce() } catch (e: InterruptedException) { throw e } catch (e: Exception) { /* retried next round */ }
                    lastPoll = SystemClock.elapsedRealtime()
                }
                val wait = pollMs - pollMs / 4 + Random.nextLong(pollMs / 2 + 1)
                wake.tryAcquire(wait, TimeUnit.MILLISECONDS)
                wake.drainPermits()
                continue
            }
            if (lastPollAt > lastPoll) lastPoll = lastPollAt
            val pollDue = !pollRunning && (pollNow || now - lastPoll >= pollMs)
            if (pollDue) pollNow = false
            when (val t = synchronized(sched) { sched.tick(now, gate.queued(), pollDue, coverRng) }) {
                CoverTick.Off -> {}
                is CoverTick.Wait -> {
                    wake.tryAcquire(maxOf(t.untilMs - now, 1L), TimeUnit.MILLISECONDS)
                    wake.drainPermits()
                    if (gate.queued() > 0) sched.queueGrew(SystemClock.elapsedRealtime(), gate.queued())
                }
                is CoverTick.Slot -> when (val s = t.slot) {
                    CoverSlot.Real -> if (!gate.grantReal()) sendDummy(d, 64, 1024)
                    CoverSlot.Poll -> {
                        gate.grantPollStart()
                        lastPoll = SystemClock.elapsedRealtime()
                        startPollCycle()
                    }
                    is CoverSlot.Dummy -> sendDummy(d, s.reqLen, s.respLen)
                }
            }
        }
    }

    /** Removes this account's vault file from the device and locks. */
    fun deleteAccount() {
        val f = synchronized(lock) { file }
        data?.username?.let { u -> if (Boot.pinUser(ctx) == u) clearPinLocal() }
        stopPoller()
        synchronized(lock) { saveQueued = false }
        store()?.deleteAll()
        BgState.clear(ctx)
        BgState.schedule(ctx, false)
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
        if (d.settings.appLock && min >= 0 && backgroundAt != 0L && SystemClock.elapsedRealtime() - backgroundAt >= min * 60_000L) {
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
        if (!d.settings.appLock) return
        val min = d.settings.backgroundLockMin
        if (min == 0) lock() else if (min > 0) main.postDelayed(bgRunnable, min * 60_000L)
    }

    /** Called on user interaction; restarts the idle countdown. */
    fun touch() {
        main.removeCallbacks(idleRunnable)
        val s = data?.settings ?: return
        val min = s.idleLockMin
        if (s.appLock && min > 0 && foreground) main.postDelayed(idleRunnable, min * 60_000L)
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
        val d0 = data ?: return
        if (Invites.purge(d0, now / 1000) !== d0) update { Invites.purge(it, now / 1000) }
        if (d0.chats.values.none { c -> c.messages.any { Expiry.isExpired(it.baseMs, it.ttlS, now) } }) return
        val gone = ArrayList<Message>()
        update { d ->
            d.copy(
                chats = d.chats.mapValues { (_, c) ->
                    val (dead, kept) = c.messages.partition { Expiry.isExpired(it.baseMs, it.ttlS, now) }
                    if (dead.isEmpty()) return@mapValues c
                    gone += dead
                    Chat(kept, minOf(c.unread, kept.count { !it.outgoing && it.timer == null }))
                },
            )
        }
        dropMedia(gone)
    }

    fun purgeNow() = purgeExpired()

    // ---- network -----------------------------------------------------------

    private fun clientFor(s: Settings): Client {
        return gatedClient(s.endpoint, s.proxy).also { it.observe = ::onTraffic }
    }

    private fun onTraffic(req: Int, resp: Int) {
        val sc = sched ?: return
        synchronized(sc) {
            if (req >= 0) sc.recordRequest(req)
            sc.recordResponse(resp)
        }
    }

    fun testConnection(done: (Boolean) -> Unit) {
        val s = data?.settings ?: return done(false)
        busy = true
        net.execute {
            val ok = try { clientFor(s.endpoint, s.proxy).health() } catch (e: Throwable) { false }
            post { busy = false; done(ok) }
        }
    }

    private fun startPoller() {
        stopPoller()
        val t = Thread({
            try {
                runLoop()
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
        pollNow = true
        early = true
        wake.release()
    }

    private fun pollOnce() {
        val started = System.currentTimeMillis()
        purgeExpired()
        val d0 = data ?: return
        val client = clientFor(d0.settings)
        if (!d0.registered) {
            val id = Identity(d0.xSk, d0.edSk)
            try {
                client.register(Registration.sign(id, d0.username, "", System.currentTimeMillis() / 1000))
                if (d0.settings.hidden) client.hide(id, d0.username, true)
            } finally {
                id.wipe()
            }
            update { it.copy(registered = true) }
        }
        retryPending()
        retryAccepts(client)
        publishPrekeys(client, d0)
        purgeFs(d0)
        var incoming = 0
        val inbox = QueueIds.inbox(Crypto.x25519Public(d0.xSk))
        incoming += drain(client, inbox, null, null)
        for (g in (data ?: return).groups) incoming += drain(client, Hex.decode(g.queueHex), g, null)
        for (c in (data ?: return).channels) {
            if (c.official && !Official.available) continue
            incoming += drain(client, ChannelCrypto.queue(c.secret), null, c)
        }
        incoming += retryDeferred(client)
        if (incoming > 0 && !foreground && (data?.settings?.notifications == true)) notifyNew(started)
    }

    /** Notifies about the newest message stored since [since] in a chat that is not muted (spec section 21). */
    private fun notifyNew(since: Long) {
        val d = data ?: return
        var key: String? = null
        var last: Message? = null
        for ((k, c) in d.chats) {
            if (d.pref(k).muted) continue
            val m = c.messages.lastOrNull { !it.outgoing && it.timer == null && it.baseMs >= since } ?: continue
            if (last == null || m.baseMs > last.baseMs) { key = k; last = m }
        }
        val m = last ?: return
        val k = key ?: return
        val chat = when {
            k.startsWith("dm:") -> d.contact(m.sender)?.let { it.title.ifBlank { "@" + it.username } } ?: ("@" + m.sender)
            k.startsWith("g:") -> d.group(k.removePrefix("g:"))?.name ?: ""
            else -> d.channel(k.removePrefix("c:"))?.name ?: ""
        }
        val sender = if (k.startsWith("g:")) m.senderName.ifBlank { "@" + m.sender } else null
        val media = m.media
        val text = when {
            media == null -> m.body
            m.body.isNotEmpty() -> m.body
            media.kind == MediaKind.Video -> ctx.getString(R.string.media_video)
            else -> ctx.getString(R.string.media_photo)
        }
        Notifier.newMessage(ctx, NoteText.Incoming(chat, sender, text), d.settings.showContent)
    }

    private fun drain(client: Client, queue: ByteArray, group: Group?, chan: Channel?): Int {
        val qHex = Hex.encode(queue)
        var count = 0
        var rounds = 0
        while (rounds++ < 50) {
            val d = data ?: return count
            val after = d.cursors[qHex] ?: 0L
            val polled = client.poll(queue, after)
            for ((seq, padded) in polled.frames) {
                count += handleFrame(client, padded, group, chan)
                update { it.copy(cursors = it.cursors + (qHex to seq)) }
            }
            if (!polled.hasMore) break
        }
        return count
    }

    /** Returns the number of new incoming messages. Lookup failures propagate so the cursor stays put. */
    private fun handleFrame(client: Client, padded: ByteArray, group: Group?, chan: Channel?): Int {
        val d = data ?: return 0
        try {
            val frame = Pad.unpad(padded)
            if (chan != null) return handleChannelFrame(client, d, chan, frame)
            if (group != null) {
                if (frame.isNotEmpty() && frame[0] == SenderKey.FRAME) {
                    val set = recvSet(d, groupKey(group.id), SkScope.Group, group.secret, null)
                    val env = synchronized(d.fs) { set.decrypt(frame, nowS()) }
                    queueSave()
                    return ingest(client, env, null, group)
                }
                return ingest(client, GroupCrypto.decrypt(group.secret, frame), null, group)
            }
            if (frame.isNotEmpty() && frame[0] == SessionStore.FRAME_SESSION) return handleSessionFrame(client, d, frame)
            val o = Seal.openDm(d.xSk, frame)
            if (o.envelope.kind == Kind.Iacc) return acceptInviteUse(client, o.envelope, o.senderXPk)
            return ingest(client, o.envelope, o.senderXPk, null)
        } catch (e: AegisException.Network) {
            throw e
        } catch (e: AegisException.Http) {
            throw e
        } catch (e: AegisException.BadResponse) {
            throw e
        } catch (e: AegisException.InvalidEndpoint) {
            throw e
        } catch (e: AegisException.ServerKeyChanged) {
            throw e
        } catch (e: AegisException) {
            if (e is AegisException.Session && e.message?.endsWith("unknown chain") == true) deferFrame(padded, group, chan)
            return 0
        }
    }

    private fun handleChannelFrame(client: Client, d: VaultData, chan: Channel, frame: ByteArray): Int {
        if (chan.official) {
            if (!Official.available) return 0
            return ingestChannel(client, chan, Official.verify(frame))
        }
        if (frame.isNotEmpty() && frame[0] == SenderKey.FRAME) {
            val set = recvSet(d, channelKey(chan.id), SkScope.Channel, chan.secret, chan.ownerEd)
            val env = synchronized(d.fs) { set.decrypt(frame, nowS()) }
            queueSave()
            if (env.sender != chan.owner) return 0
            return ingestChannel(client, chan, env)
        }
        return ingestChannel(client, chan, ChannelCrypto.openPost(chan.secret, chan.owner, chan.ownerEd, frame))
    }

    private fun handleSessionFrame(client: Client, d: VaultData, frame: ByteArray): Int {
        val id = Identity(d.xSk, d.edSk)
        val r = try {
            synchronized(d.fs) { d.fs.store.decrypt(id, frame, nowS()) }
        } finally {
            id.wipe()
        }
        queueSave()
        var lookup: ByteArray? = null
        for (a in r.actions) when (a) {
            is SessionAction.StartNewSession -> try { startSessionWith(client, d, a.contact) } catch (e: AegisException.NeedsUpdate) { /* peer has no prekeys */ }
            is SessionAction.UndecryptableNotice -> post { notice = R.string.err_undecryptable }
            is SessionAction.LookupSender -> lookup = a.xPk
            is SessionAction.NeedsPrekeysFetch -> {}
        }
        lookup?.let { return unknownSender(client, d, frame, it) }
        val env = r.envelope ?: return 0
        val c = d.contact(env.sender) ?: return 0
        return ingest(client, env, c.x, null, true)
    }

    // ---- unknown senders and message requests ---------------------------------

    /** Short form of a sender key for people to compare. */
    fun keyFingerprint(x: ByteArray): String =
        Hex.encode(Crypto.sha256(x).copyOf(10)).chunked(4).joinToString(" ")

    /**
     * A 0x03 frame from a key that is not a contact. The directory has no lookup by key and guessing
     * names would tell the server who we share groups with, so the frame goes straight to the
     * message requests. A key a contact has announced is matched here, without any request.
     */
    private fun unknownSender(client: Client, d: VaultData, frame: ByteArray, x: ByteArray): Int {
        val xHex = Hex.encode(x)
        if (synchronized(d.fs) { xHex in d.fs.blocked }) return 0
        if (d.contacts.any { c -> c.pendingX?.let { Bytes.eq(it, x) } == true } || synchronized(d.fs) { xHex in d.fs.requests }) {
            synchronized(d.fs) { d.fs.hold(xHex, frame) }
            queueSave()
            return 0
        }
        val stored = synchronized(d.fs) { d.fs.hold(xHex, frame) }
        if (stored) { queueSave(); post { requestTick++ } }
        return 0
    }

    /** Bumped when the request list changes, so screens refresh. */
    var requestTick by mutableIntStateOf(0)
        private set

    /**
     * The directory confirmed that [e] owns the sender key. A new name becomes a contact and the held
     * frames are opened; a known contact with another key gets the key-change warning first.
     */
    private fun adoptSender(client: Client, d: VaultData, e: DirEntry, held: List<ByteArray>): Int {
        val xHex = Hex.encode(e.x)
        val existing = d.contact(e.u)
        if (existing != null) {
            update {
                it.withContact(existing.copy(verified = false, keyChanged = true, pendingX = e.x.copyOf(), pendingEd = e.ed.copyOf()))
            }
            synchronized(d.fs) { for (f in held) d.fs.hold(xHex, f) }
            queueSave()
            post { requestTick++ }
            return 0
        }
        val contact = Contact(e.u, e.title, e.x, e.ed)
        update { it.withContact(contact) }
        syncFsContact(contact)
        val cur = data ?: return 0
        var n = 0
        for (f in held) n += handleSessionFrame(client, cur, f)
        return n
    }

    /** The held requests that are not already shown as a key change on a contact. */
    fun requests(): List<Pair<String, Int>> {
        val d = data ?: return emptyList()
        val pend = d.contacts.mapNotNull { it.pendingX }.map { Hex.encode(it) }.toSet()
        return synchronized(d.fs) { d.fs.requests.filter { it.key !in pend }.map { it.key to it.value.size } }
    }

    /** Accepting needs a name whose directory entry carries the sender key. */
    fun acceptRequest(xHex: String, rawName: String, done: (Int?) -> Unit) {
        val d = data ?: return done(R.string.err_generic)
        val user = try { Names.normalizeUsername(rawName) } catch (e: AegisException) { return done(R.string.err_username_invalid) }
        if (user == d.username) return done(R.string.err_self)
        busy = true
        net.execute {
            var err: Int? = null
            try {
                val e = clientFor(d.settings).lookup(user)
                val held = synchronized(d.fs) { d.fs.requests[xHex]?.toList() }
                if (held == null) err = R.string.err_generic
                else if (e == null || Hex.encode(e.x) != xHex) err = R.string.err_request_mismatch
                else {
                    synchronized(d.fs) { d.fs.requests.remove(xHex) }
                    adoptSender(clientFor(d.settings), d, e, held)
                    queueSave()
                }
            } catch (e: Throwable) {
                err = fail(e)
            }
            post { requestTick++; busy = false; done(err) }
        }
    }

    fun blockRequest(xHex: String) {
        val d = data ?: return
        synchronized(d.fs) {
            d.fs.requests.remove(xHex)
            d.fs.blocked.add(xHex)
        }
        queueSave()
        requestTick++
    }

    /** Opens the frames held for a key the user has now accepted on a contact. */
    private fun releaseHeld(xHex: String) {
        val d = data ?: return
        val held = synchronized(d.fs) { d.fs.requests.remove(xHex)?.toList() } ?: return
        queueSave()
        net.execute {
            try {
                val client = clientFor(d.settings)
                for (f in held) {
                    try { handleSessionFrame(client, d, f) } catch (e: AegisException) { /* unreadable frame */ }
                }
            } catch (e: Exception) {
                // the frames are lost; the sender can resend
            }
            post { requestTick++ }
        }
    }

    private fun recvSet(d: VaultData, key: String, scope: SkScope, secret: ByteArray, ownerEd: ByteArray?): RecvSet =
        synchronized(d.fs) { d.fs.recv.getOrPut(key) { RecvSet(scope, secret, ownerEd) } }

    private class Deferred(val padded: ByteArray, val group: Group?, val chan: Channel?)
    private val deferred = ArrayList<Deferred>()

    /** A group frame can arrive before the sender key that opens it; it is tried again after the next inbox pass. */
    private fun deferFrame(padded: ByteArray, group: Group?, chan: Channel?) {
        synchronized(deferred) {
            if (deferred.size >= 100) deferred.removeAt(0)
            deferred.add(Deferred(padded, group, chan))
        }
    }

    private fun retryDeferred(client: Client): Int {
        val list = synchronized(deferred) { ArrayList(deferred).also { deferred.clear() } }
        var n = 0
        for (f in list) {
            val d = data ?: return n
            val g = f.group?.let { d.group(it.id) }
            val c = f.chan?.let { d.channel(it.id) }
            if ((f.group != null && g == null) || (f.chan != null && c == null)) continue
            n += handleFrame(client, f.padded, g, c)
        }
        return n
    }

    private fun markSeen(id: String) {
        update { it.copy(seen = SeenIds(SEEN_CAP, it.seen).also { s -> s.insert(id) }.toList()) }
    }

    private fun ingest(client: Client, env: Envelope, senderX: ByteArray?, group: Group?, viaSession: Boolean = false): Int {
        val d = data ?: return 0
        if (env.sender == d.username) return 0
        if (SeenIds(SEEN_CAP, d.seen).contains(env.msgId)) return 0
        var contact = d.contact(env.sender)
        if (contact == null) {
            // A group member who is not a contact is not looked up: that would show the server who is in the group (section 7).
            if (group != null) {
                markSeen(env.msgId)
                return 0
            }
            val e = client.lookup(env.sender)
            if (e == null || !Bytes.eq(e.ed, env.senderEd) || (senderX != null && !Bytes.eq(e.x, senderX))) {
                markSeen(env.msgId)
                return 0
            }
            contact = Contact(env.sender, e.title, e.x, e.ed)
            update { it.withContact(contact) }
            syncFsContact(contact)
        } else {
            val pinned = PinnedKeys(contact.x, contact.ed)
            try {
                if (group == null) Pinning.checkDm(env, senderX!!, pinned) else Pinning.checkGroup(env, pinned)
            } catch (e: AegisException.SenderMismatch) {
                val c = contact
                update {
                    it.withContact(
                        c.copy(verified = false, keyChanged = true, pendingX = senderX?.copyOf(), pendingEd = env.senderEd.copyOf()),
                    )
                }
                markSeen(env.msgId)
                return 0
            }
        }
        val now = System.currentTimeMillis()
        if (env.kind != Kind.Dmf && env.kind != Kind.Gmf) markSeen(env.msgId)
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
            Kind.Dmf -> {
                if (group != null) return 0
                addIncomingMedia(client, dmKey(env.sender), env, now)
            }
            Kind.Gmf -> {
                if (group == null || env.sender !in group.members) return 0
                addIncomingMedia(client, groupKey(group.id), env, now)
            }
            Kind.Cinv -> {
                if (group != null) return 0
                acceptChannelInvite(env)
                1
            }
            Kind.Prof -> {
                if (group != null || d.contact(env.sender) == null) return 0
                acceptProfile(env)
                0
            }
            Kind.Skey -> {
                if (!viaSession || group != null) return 0
                acceptSkey(env)
                0
            }
            Kind.Ttl -> {
                if (group != null) return 0
                acceptTimer(dmKey(env.sender), env, now)
            }
            Kind.Gttl -> {
                if (group == null || env.sender !in group.members) return 0
                acceptTimer(groupKey(group.id), env, now)
            }
            Kind.Cmsg, Kind.Cmf, Kind.Iacc -> 0
        }
    }

    /**
     * A timer change from the other side (spec section 5.2). One older than the last change applied is
     * ignored, so crossing changes end on the newer one; an actual change leaves a line in the chat.
     */
    private fun acceptTimer(key: String, env: Envelope, now: Long): Int {
        if (!Expiry.allowed(env.ttlS)) return 0
        val line = Message(env.msgId, false, env.sender, env.senderName, env.tsMs, now, 0, "", timer = env.ttlS)
        update { d ->
            val same: Boolean
            val next = if (key.startsWith("dm:")) {
                val c = d.contact(key.removePrefix("dm:")) ?: return@update d
                if (env.tsMs < c.ttlTs) return@update d
                same = c.ttlS == env.ttlS
                d.withContact(c.copy(ttlS = env.ttlS, ttlTs = env.tsMs))
            } else {
                val g = d.group(key.removePrefix("g:")) ?: return@update d
                if (env.tsMs < g.ttlTs) return@update d
                same = g.ttlS == env.ttlS
                d.copy(groups = d.groups.map { if (it.id == g.id) it.copy(ttlS = env.ttlS, ttlTs = env.tsMs) else it })
            }
            if (same) return@update next
            val c = next.chat(key)
            next.withChat(key, Chat((c.messages + line).takeLast(MAX_MESSAGES), c.unread))
        }
        return 0
    }

    /** A sender key arrives only inside a pairwise session frame. */
    private fun acceptSkey(env: Envelope) {
        val d = data ?: return
        val now = nowS()
        val g = d.group(env.groupId)
        if (g != null) {
            if (env.sender !in g.members) return
            val set = recvSet(d, groupKey(g.id), SkScope.Group, g.secret, null)
            try { synchronized(d.fs) { set.addFromSkey(env, now) } } catch (e: AegisException) { return }
            queueSave()
            return
        }
        val ch = d.channel(env.groupId) ?: return
        if (ch.official || env.sender != ch.owner) return
        val set = recvSet(d, channelKey(ch.id), SkScope.Channel, ch.secret, ch.ownerEd)
        try { synchronized(d.fs) { set.addFromSkey(env, now) } } catch (e: AegisException) { return }
        queueSave()
    }

    private fun nowS() = System.currentTimeMillis() / 1000

    private fun syncFsContacts(d: VaultData) {
        for (c in d.contacts) syncFsContact(c)
    }

    private fun syncFsContact(c: Contact) {
        val d = data ?: return
        synchronized(d.fs) {
            try {
                d.fs.store.addContact(c.username, c.ed, c.x)
            } catch (e: AegisException) {
                d.fs.store.removeContact(c.username)
                d.fs.store.addContact(c.username, c.ed, c.x)
            }
        }
    }

    private fun purgeFs(d: VaultData) {
        val now = nowS()
        synchronized(d.fs) {
            d.fs.store.purge(now)
            d.fs.recv.values.forEach { it.purge(now) }
        }
    }

    /** Publishes the signed prekey and one-time prekeys when due (spec section 27.1). */
    private fun publishPrekeys(client: Client, d: VaultData) {
        val fs = d.fs
        val now = nowS()
        if (!synchronized(fs) { fs.putDue(now) }) return
        val id = Identity(d.xSk, d.edSk)
        try {
            val batch = synchronized(fs) {
                val b = fs.store.preparePrekeys(id, now, fs.serverOpks)
                fs.putTimes.add(now)
                b
            }
            val form = Prekeys.putForm(id, d.username, batch.spk, batch.opks, now)
            queueSave()
            val n = client.prekeysPut(form)
            synchronized(fs) { fs.serverOpks = n }
            queueSave()
        } catch (e: AegisException.ServerKeyChanged) {
            throw e
        } catch (e: Exception) {
            // Retried by the next due check; the rate limit counts the attempt.
        } finally {
            id.wipe()
        }
    }

    /** Takes the contact's prekeys and starts a new session with them. No bundle means the contact must update. */
    private fun startSessionWith(client: Client, d: VaultData, user: String) {
        val b = client.prekeysTake(user, (data ?: d).contact(user)?.ed) ?: throw AegisException.NeedsUpdate()
        val id = Identity(d.xSk, d.edSk)
        try {
            synchronized(d.fs) { d.fs.store.startSession(id, user, b, nowS()) }
        } finally {
            id.wipe()
        }
        queueSave()
    }

    /** Sends [env] to [c] in a type 0x03 frame, starting a session first when there is none. */
    private fun sendPairwise(client: Client, d: VaultData, id: Identity, c: Contact, env: Envelope) {
        val fs = d.fs
        var frame: ByteArray? = null
        for (attempt in 0..1) {
            val enc = synchronized(fs) {
                if (!fs.store.hasContact(c.username)) fs.store.addContact(c.username, c.ed, c.x)
                fs.store.encrypt(id, c.username, env, nowS())
            }
            queueSave()
            if (enc is Encrypted.Frame) { frame = enc.bytes; break }
            startSessionWith(client, d, c.username)
        }
        client.send(QueueIds.inbox(c.x), frame ?: throw AegisException.Session("no session"))
    }

    /** The current chain for [key], replaced when it is due for rotation. */
    private fun chainFor(fs: FsState, key: String, now: Long): SendChain {
        var ch = fs.send[key]
        if (ch == null || ch.needsRotation(now, false)) {
            ch = SendChain.create(now)
            fs.send[key] = ch
            fs.given[key] = HashSet()
        }
        return ch
    }

    /** Gives our current chain to every listed user who does not hold it yet. Contacts without prekeys are skipped. */
    private fun distribute(client: Client, d: VaultData, id: Identity, key: String, scopeId: String, users: Collection<String>) {
        val fs = d.fs
        val ch = synchronized(fs) { chainFor(fs, key, nowS()) }
        for (u in users) {
            if (u == d.username) continue
            if (synchronized(fs) { fs.given[key]?.contains(u) == true }) continue
            val c = d.contact(u) ?: continue
            if (c.keyChanged) continue
            val env = synchronized(fs) { ch.skeyEnvelope(d.username, d.settings.displayName, id.edPublic, scopeId, System.currentTimeMillis()) }
            try {
                sendPairwise(client, d, id, c, env)
            } catch (e: AegisException.NeedsUpdate) {
                continue
            }
            synchronized(fs) { if (fs.send[key] === ch) fs.given.getOrPut(key) { HashSet() }.add(u) }
            queueSave()
        }
    }

    private fun sendSenderKeyFrame(
        client: Client, d: VaultData, id: Identity, key: String, scope: SkScope, secret: ByteArray,
        users: Collection<String>, queue: ByteArray, env: Envelope,
    ) {
        distribute(client, d, id, key, env.groupId, users)
        val frame = synchronized(d.fs) { chainFor(d.fs, key, nowS()).encrypt(scope, secret, id.edSecret, env) }
        queueSave()
        client.send(queue, frame)
    }

    private fun ingestChannel(client: Client, ch: Channel, env: Envelope): Int {
        val d = data ?: return 0
        if (env.sender == d.username) return 0
        if (SeenIds(SEEN_CAP, d.seen).contains(env.msgId)) return 0
        val now = System.currentTimeMillis()
        if (env.kind != Kind.Cmf) markSeen(env.msgId)
        return if (env.kind == Kind.Cmf) addIncomingMedia(client, channelKey(ch.id), env, now) else addIncoming(channelKey(ch.id), env, now)
    }

    private fun addIncomingMedia(client: Client, key: String, env: Envelope, now: Long): Int {
        val base = now
        val bytes = try {
            val desc0 = AttachmentDescriptor.parse(env.body)
            Attach.open(desc0, desc0.ids.map { client.blobGet(it) ?: throw AegisException.Media("blob missing") })
        } catch (e: AegisException.Network) { throw e
        } catch (e: AegisException.Http) { throw e
        } catch (e: AegisException.BadResponse) { throw e
        } catch (e: AegisException.InvalidEndpoint) { throw e
        } catch (e: AegisException) { markSeen(env.msgId); return 0 }
        val desc = AttachmentDescriptor.parse(env.body)
        val d = data ?: return 0
        val st = store() ?: return 0
        val file = try { st.save(d.mediaKey, bytes) } finally { bytes.fill(0) }
        markSeen(env.msgId)
        val media = Media(file, desc.kind, desc.width, desc.height, desc.durationMs, desc.encode())
        val m = Message(env.msgId, false, env.sender, env.senderName, env.tsMs, base, env.ttlS, desc.caption, Status.SENT, media)
        update { cur ->
            val c = cur.chat(key)
            val unread = if (openChat == key && foreground) c.unread else c.unread + 1
            cur.withChat(key, Chat((c.messages + m).takeLast(MAX_MESSAGES), unread))
        }
        return 1
    }

    private fun acceptChannelInvite(env: Envelope) {
        val key = env.groupKey ?: return
        if (env.groupId != ChannelCrypto.channelId(key)) return
        update { d ->
            if (d.channel(env.groupId) != null) return@update d
            val name = Text.sanitizeDisplay(env.body)
            d.copy(channels = d.channels + Channel(env.groupId, key.copyOf(), name, env.sender, env.senderEd.copyOf()))
        }
    }

    private fun acceptProfile(env: Envelope) {
        val p = try { Profile.parse(env.body) } catch (e: AegisException) { return }
        update { d ->
            val c = d.contact(env.sender) ?: return@update d
            if (env.tsMs <= c.cardTs) return@update d
            d.withContact(c.copy(about = p.about, particles = p.particles, cardName = Text.sanitizeDisplay(p.name), cardTs = env.tsMs))
        }
    }

    private fun addIncoming(key: String, env: Envelope, now: Long): Int {
        val base = now
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
        val d = data ?: return
        val g = d.group(env.groupId)
        if (g == null) {
            if (d.username !in env.members || env.sender !in env.members) return
            update { cur ->
                if (cur.group(env.groupId) != null) return@update cur
                cur.copy(groups = cur.groups + Group(env.groupId, key.copyOf(), Text.sanitizeDisplay(env.body), env.members, env.ttlS, env.sender))
            }
            return
        }
        // A new member list for a group we have: only from its creator, under the same group key.
        if (g.creator.isEmpty() || env.sender != g.creator || !Bytes.eq(key, g.secret) || env.members == g.members || env.sender !in env.members) return
        if (d.username !in env.members) {
            leaveGroup(g.id)
            post { notice = R.string.removed_from_group }
            return
        }
        update { cur -> cur.copy(groups = cur.groups.map { if (it.id == g.id) it.copy(members = env.members) else it }) }
        rotateGroup(g.id, false)
    }

    /** The creator removes a member (spec section 28): the list goes to the rest and every sender chain is replaced. */
    fun removeMember(groupId: String, user: String) {
        val d = data ?: return
        val g = d.group(groupId) ?: return
        if (g.creator != d.username || user == d.username || user !in g.members) return
        val rest = g.members.filter { it != user }
        if (rest.size < 2) { notice = R.string.err_group_members; return }
        update { cur -> cur.copy(groups = cur.groups.map { if (it.id == groupId) it.copy(members = rest) else it }) }
        rotateGroup(groupId, true)
    }

    /** Drops our sender chain for the group and hands a new one to every member, with the member list when [announce]. */
    private fun rotateGroup(groupId: String, announce: Boolean) {
        val d0 = data ?: return
        val g0 = d0.group(groupId) ?: return
        synchronized(d0.fs) {
            d0.fs.send.remove(groupKey(groupId))
            d0.fs.given.remove(groupKey(groupId))
        }
        queueSave()
        for (u in g0.members) {
            if (u == d0.username) continue
            realRequest {
                val d = data ?: return@realRequest
                val g = d.group(groupId) ?: return@realRequest
                val id = Identity(d.xSk, d.edSk)
                try {
                    val client = clientFor(d.settings)
                    val c = d.contact(u) ?: return@realRequest
                    if (announce) {
                        val env = Envelope(
                            Kind.Ginv, newId(), d.username, d.settings.displayName, id.edPublic,
                            System.currentTimeMillis(), g.ttlS, g.id, g.name, g.secret, g.members,
                        )
                        sendPairwise(client, d, id, c, env)
                    }
                    distribute(client, d, id, groupKey(g.id), g.id, listOf(u))
                } catch (e: Exception) {
                    post { notice = R.string.err_invites }
                } finally {
                    id.wipe()
                }
            }
        }
    }

    // ---- contacts ----------------------------------------------------------

    // ---- invite links (spec section 30) -----------------------------------------

    /** The invite link made last; kept in memory only and gone on lock. */
    var inviteLink by mutableStateOf<String?>(null)
        private set

    /** An `aegis:` link opened from outside, waiting for the user to act on it once unlocked. */
    var linkIn by mutableStateOf<String?>(null)

    /** `iacc` frames that could not be posted yet, as (queue, frame); memory only. */
    private val accepts = ArrayList<Pair<ByteArray, ByteArray>>()

    fun createInvite(done: (Int?) -> Unit) {
        val d = data ?: return done(R.string.err_generic)
        val s = Crypto.randomBytes(32)
        var added = false
        update { cur -> Invites.open(cur, s, nowS())?.also { added = true } ?: cur }
        if (!added) return done(R.string.err_invite_limit)
        busy = true
        net.execute {
            var err: Int? = null
            val id = Identity(d.xSk, d.edSk)
            try {
                // The secret is on disk before the server holds the bundle, so an accept is never lost.
                flush()
                clientFor(d.settings).inviteCreate(id, d.username, s)
                val link = Invite.link(s)
                post { inviteLink = link }
            } catch (e: Throwable) {
                update { Invites.drop(it, s) }
                err = if (e is AegisException.Http && e.code == 429) R.string.err_invite_limit else fail(e)
            } finally {
                id.wipe()
            }
            post { busy = false; done(err) }
        }
    }

    /** Redeems a link: pins the inviter without asking the directory and tells the inviter who used it. */
    fun redeemInvite(raw: String, done: (String?, Int?) -> Unit) {
        val d = data ?: return done(null, R.string.err_generic)
        val s = try { Invite.parseLink(raw) } catch (e: AegisException) { return done(null, R.string.err_invite_link) }
        if (Invites.isOwn(d, s)) return done(null, R.string.err_self)
        busy = true
        net.execute {
            var err: Int? = null
            var user: String? = null
            val id = Identity(d.xSk, d.edSk)
            try {
                val client = clientFor(d.settings)
                val b = client.inviteRedeem(s)
                // A visible inviter must match the directory; the invite is already used up, so a
                // failed lookup does not stop it.
                val listed = if (b == null) null else try { client.lookup(b.u) } catch (e: AegisException) { null }
                if (b == null) err = R.string.err_invite_gone
                else if (listed != null && (!Bytes.eq(listed.x, b.x) || !Bytes.eq(listed.ed, b.ed))) err = R.string.err_invite_link
                else when (Invites.pin(data ?: d, b, id.xPublic, id.edPublic)) {
                    Invites.Pin.Self -> err = R.string.err_self
                    Invites.Pin.Conflict -> err = R.string.err_invite_conflict
                    Invites.Pin.Known -> {
                        sendAccept(client, d, id, s, b)
                        user = b.u
                    }
                    Invites.Pin.New -> {
                        val c = Contact(b.u, "", b.x.copyOf(), b.ed.copyOf())
                        update { it.withContact(c) }
                        syncFsContact(c)
                        sendAccept(client, d, id, s, b)
                        sendProfile(listOf(b.u))
                        user = b.u
                    }
                }
            } catch (e: Throwable) {
                err = fail(e)
            } finally {
                id.wipe()
            }
            post {
                busy = false
                if (user != null) linkIn = null
                done(user, err)
            }
        }
    }

    private fun sendAccept(client: Client, d: VaultData, id: Identity, s: ByteArray, b: Invite.Bundle) {
        val body = Invite.acceptBody(id, s, d.username)
        val env = Envelope(Kind.Iacc, newId(), d.username, d.settings.displayName, id.edPublic, System.currentTimeMillis(), 0, "", body)
        val out = QueueIds.inbox(b.x) to Seal.sealDm(d.xSk, b.x, env)
        try {
            client.send(out.first, out.second)
        } catch (e: AegisException.ServerKeyChanged) {
            synchronized(accepts) { accepts.add(out) }
            throw e
        } catch (e: Exception) {
            synchronized(accepts) { accepts.add(out) }
        }
    }

    private fun retryAccepts(client: Client) {
        val list = synchronized(accepts) { ArrayList(accepts).also { accepts.clear() } }
        for ((i, out) in list.withIndex()) {
            try {
                client.send(out.first, out.second)
            } catch (e: Exception) {
                synchronized(accepts) { accepts.addAll(list.subList(i, list.size)) }
                if (e is AegisException.ServerKeyChanged) throw e
                return
            }
        }
    }

    /** An `iacc` in the inbox. Only a sender proving one of the open invites is pinned; frames it sent earlier are then opened. */
    private fun acceptInviteUse(client: Client, env: Envelope, senderX: ByteArray): Int {
        val d = data ?: return 0
        if (SeenIds(SEEN_CAP, d.seen).contains(env.msgId)) return 0
        // A name listed in the directory must come with the listed keys, so whoever intercepted
        // a link cannot take the name of a visible user. A failed lookup leaves the frame for later.
        val listed = client.lookup(env.sender)
        if (listed != null && (!Bytes.eq(listed.x, senderX) || !Bytes.eq(listed.ed, env.senderEd))) {
            markSeen(env.msgId)
            return 0
        }
        val xHex = Hex.encode(senderX)
        val blocked = synchronized(d.fs) { xHex in d.fs.blocked }
        var added: Contact? = null
        update { cur ->
            val r = Invites.accept(cur, env, senderX, blocked)
            if (r == null) cur else { added = r.second; r.first }
        }
        markSeen(env.msgId)
        val c = added ?: return 0
        flush()
        syncFsContact(c)
        releaseHeld(xHex)
        sendProfile(listOf(c.username))
        post { requestTick++ }
        return 0
    }

    /** Turns the hidden profile on or off; the switch follows the server's answer. */
    fun setHidden(on: Boolean, done: (Int?) -> Unit) {
        val d = data ?: return done(R.string.err_generic)
        busy = true
        net.execute {
            var err: Int? = null
            val id = Identity(d.xSk, d.edSk)
            try {
                clientFor(d.settings).hide(id, d.username, on)
                update { it.copy(settings = it.settings.copy(hidden = on)) }
            } catch (e: Throwable) {
                err = fail(e)
            } finally {
                id.wipe()
            }
            post { busy = false; done(err) }
        }
    }

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
                if (e == null) err = R.string.err_not_found else {
                    update { cur ->
                        if (cur.contact(user) != null) cur else cur.withContact(Contact(user, e.title, e.x, e.ed))
                    }
                    data?.contact(user)?.let { syncFsContact(it) }
                    if (d.profile.name.isNotEmpty()) sendProfile(listOf(user))
                }
            } catch (e: Throwable) {
                err = fail(e)
            }
            post { busy = false; done(if (err == null) user else null, err) }
        }
    }

    fun setVerified(user: String, v: Boolean) = update { d ->
        val c = d.contact(user) ?: return@update d
        d.withContact(c.copy(verified = v))
    }

    /** Keeps the key pinned earlier and clears the warning. */
    fun keepOldKey(user: String) {
        val d = data ?: return
        d.contact(user)?.pendingX?.let { px ->
            synchronized(d.fs) { d.fs.requests.remove(Hex.encode(px)) }
            queueSave()
        }
        update { cur ->
            val c = cur.contact(user) ?: return@update cur
            cur.withContact(c.copy(keyChanged = false, pendingX = null, pendingEd = null))
        }
    }

    /** Replaces the pinned key with the one that triggered the warning; verification is reset. */
    fun acceptNewKey(user: String, done: (Int?) -> Unit) {
        val d = data ?: return done(R.string.err_generic)
        val c = d.contact(user) ?: return done(R.string.err_generic)
        val ped = c.pendingEd ?: return done(R.string.err_generic)
        val px = c.pendingX
        if (px != null) {
            update { cur ->
                cur.withContact(c.copy(x = px, ed = ped, verified = false, keyChanged = false, pendingX = null, pendingEd = null))
            }
            replaceFsContact(user)
            releaseHeld(Hex.encode(px))
            return done(null)
        }
        busy = true
        net.execute {
            var err: Int? = null
            try {
                val e = clientFor(d.settings).lookup(user)
                if (e == null || !Bytes.eq(e.ed, ped)) err = R.string.err_key_unconfirmed
                else {
                    update { cur -> cur.withContact(c.copy(title = e.title, x = e.x, ed = e.ed, verified = false, keyChanged = false, pendingX = null, pendingEd = null)) }
                    replaceFsContact(user)
                }
            } catch (e: Throwable) {
                err = fail(e)
            }
            post { busy = false; done(err) }
        }
    }

    /** Drops the old sessions of a contact whose keys were replaced and registers the new keys. */
    private fun replaceFsContact(user: String) {
        val d = data ?: return
        synchronized(d.fs) { d.fs.store.removeContact(user) }
        d.contact(user)?.let { syncFsContact(it) }
        queueSave()
    }

    fun safetyNumber(c: Contact): String? {
        val d = data ?: return null
        val id = Identity(d.xSk, d.edSk)
        val n = Safety.number(id.edPublic, id.xPublic, c.ed, c.x)
        id.wipe()
        return n
    }

    /** Sets the chat timer and tells the other side (spec section 5.2); the change shows as a line in the chat. */
    fun setChatTtl(key: String, ttlS: Long) {
        val d = data ?: return
        if (!Expiry.allowed(ttlS) || ttlFor(d, key) == ttlS || !canSend(d, key)) return
        val last = if (key.startsWith("dm:")) d.contact(key.removePrefix("dm:"))?.ttlTs else d.group(key.removePrefix("g:"))?.ttlTs
        // Later than any change applied here, so the other side cannot rank it below that one.
        val now = maxOf(System.currentTimeMillis(), (last ?: 0) + 1)
        update { cur ->
            if (key.startsWith("dm:")) {
                val c = cur.contact(key.removePrefix("dm:")) ?: return@update cur
                cur.withContact(c.copy(ttlS = ttlS, ttlTs = now))
            } else {
                val g = cur.group(key.removePrefix("g:")) ?: return@update cur
                cur.copy(groups = cur.groups.map { if (it.id == g.id) it.copy(ttlS = ttlS, ttlTs = now) else it })
            }
        }
        val m = Message(newId(), true, d.username, d.settings.displayName, now, System.currentTimeMillis(), 0, "", Status.SENDING, timer = ttlS)
        appendOutgoing(key, m)
        deliver(key, m)
    }

    fun markRead(key: String) = update { d ->
        val c = d.chats[key]
        if (c == null || c.unread == 0) d else d.withChat(key, Chat(c.messages, 0))
    }

    fun deleteChatHistory(key: String) {
        dropMedia(data?.chat(key)?.messages ?: emptyList())
        update { d -> d.withChat(key, Chat()) }
    }

    // ---- sending -----------------------------------------------------------

    private fun newId(): String = Hex.encode(Crypto.randomBytes(16))

    private fun ttlFor(d: VaultData, key: String): Long = when {
        key.startsWith("dm:") -> d.contact(key.removePrefix("dm:"))?.ttlS ?: 0
        key.startsWith("g:") -> d.group(key.removePrefix("g:"))?.ttlS ?: 0
        else -> 0
    }

    /** Whether the user may send to [key] now; sets a notice when not. */
    private fun canSend(d: VaultData, key: String): Boolean {
        when {
            key.startsWith("dm:") -> {
                val c = d.contact(key.removePrefix("dm:")) ?: return false
                if (c.keyChanged) { notice = R.string.err_key_changed_block; return false }
            }
            key.startsWith("g:") -> if (d.group(key.removePrefix("g:")) == null) return false
            key.startsWith("c:") -> {
                val ch = d.channel(key.removePrefix("c:")) ?: return false
                if (!ch.mine(d.username)) return false
            }
            else -> return false
        }
        return true
    }

    fun sendText(key: String, rawText: String) {
        val d = data ?: return
        if (!canSend(d, key)) return
        val text = Text.sanitizeBody(rawText).trim()
        if (text.isEmpty()) return
        if (text.length > MAX_TEXT_CHARS) { notice = R.string.err_too_large; return }
        val firstToContact = key.startsWith("dm:") && d.chat(key).messages.none { it.outgoing }
        val now = System.currentTimeMillis()
        val m = Message(newId(), true, d.username, d.settings.displayName, now, now, ttlFor(d, key), text, Status.SENDING)
        appendOutgoing(key, m)
        deliver(key, m)
        if (firstToContact && d.profile.name.isNotEmpty()) sendProfile(listOf(key.removePrefix("dm:")))
    }

    fun sendDm(user: String, rawText: String) = sendText(dmKey(user), rawText)
    fun sendGroup(id: String, rawText: String) = sendText(groupKey(id), rawText)

    /** Picks, sanitizes, encrypts and uploads a photo or video, then sends the descriptor. */
    fun sendMedia(key: String, uri: Uri, rawCaption: String) {
        val d = data ?: return
        if (!canSend(d, key)) return
        val caption = Text.sanitizeBody(rawCaption).replace('\n', ' ')
            .filter { !Text.isSpoofing(it.code) && !it.isISOControl() }.trim()
        if (caption.codePointCount(0, caption.length) > MAX_CAPTION) { notice = R.string.err_too_large; return }
        busy = true
        net.execute {
            try {
                val prep = MediaPrep.fromUri(ctx, uri)
                val sealed = Attach.seal(AttachmentMeta(prep.kind, prep.width, prep.height, prep.durationMs, caption), prep.bytes)
                val client = clientFor(d.settings)
                for ((i, id) in sealed.descriptor.ids.withIndex()) client.blobPut(id, sealed.chunks[i])
                val cur = data ?: return@execute
                val file = store()!!.save(cur.mediaKey, prep.bytes)
                prep.bytes.fill(0)
                val media = Media(file, prep.kind, prep.width, prep.height, prep.durationMs, sealed.descriptor.encode())
                val now = System.currentTimeMillis()
                val m = Message(newId(), true, cur.username, cur.settings.displayName, now, now, ttlFor(cur, key), caption, Status.SENDING, media)
                appendOutgoing(key, m)
                deliver(key, m)
            } catch (e: AegisException.Media) {
                post { notice = R.string.err_media }
            } catch (e: Throwable) {
                post { notice = if (e is OutOfMemoryError || e is SecurityException || e is java.io.IOException) R.string.err_media else fail(e) }
            } finally {
                post { busy = false }
            }
        }
    }

    private fun appendOutgoing(key: String, m: Message) = update { d ->
        val c = d.chat(key)
        d.withChat(key, Chat((c.messages + m).takeLast(MAX_MESSAGES), c.unread))
            .copy(seen = SeenIds(SEEN_CAP, d.seen).also { it.insert(m.id) }.toList())
    }

    private fun setStatus(key: String, id: String, status: Int) = update { d ->
        val c = d.chats[key] ?: return@update d
        d.withChat(key, Chat(c.messages.map { if (it.id == id) it.copy(status = status) else it }, c.unread))
    }

    fun retry(key: String, id: String) {
        val m = data?.chats?.get(key)?.messages?.firstOrNull { it.id == id && it.outgoing && it.status == Status.FAILED } ?: return
        setStatus(key, id, Status.SENDING)
        deliver(key, m)
    }

    private fun deliver(key: String, m: Message) {
        realRequest {
            val status = try {
                val d = data ?: return@realRequest
                val id = Identity(d.xSk, d.edSk)
                try {
                    val client = clientFor(d.settings)
                    val media = m.media
                    val body = media?.desc ?: m.body
                    if (key.startsWith("dm:")) {
                        val c = d.contact(key.removePrefix("dm:")) ?: throw AegisException.InvalidUsername()
                        if (c.keyChanged) throw AegisException.SenderMismatch()
                        val kind = if (m.timer != null) Kind.Ttl else if (media != null) Kind.Dmf else Kind.Dm
                        val env = Envelope(kind, m.id, d.username, m.senderName, id.edPublic, m.tsMs, m.timer ?: m.ttlS, "", body)
                        sendPairwise(client, d, id, c, env)
                    } else if (key.startsWith("c:")) {
                        val ch = d.channel(key.removePrefix("c:")) ?: throw AegisException.GroupMismatch()
                        if (!ch.mine(d.username) || ch.official) throw AegisException.SenderMismatch()
                        val kind = if (media != null) Kind.Cmf else Kind.Cmsg
                        val env = Envelope(kind, m.id, d.username, m.senderName, id.edPublic, m.tsMs, m.ttlS, ch.id, body)
                        val to = synchronized(d.fs) { d.fs.audience[key]?.toList() ?: emptyList() }
                        sendSenderKeyFrame(client, d, id, key, SkScope.Channel, ch.secret, to, ChannelCrypto.queue(ch.secret), env)
                    } else {
                        val g = d.group(key.removePrefix("g:")) ?: throw AegisException.GroupMismatch()
                        val kind = if (m.timer != null) Kind.Gttl else if (media != null) Kind.Gmf else Kind.Gmsg
                        val env = Envelope(kind, m.id, d.username, m.senderName, id.edPublic, m.tsMs, m.timer ?: m.ttlS, g.id, body)
                        sendSenderKeyFrame(client, d, id, key, SkScope.Group, g.secret, g.members, Hex.decode(g.queueHex), env)
                    }
                } finally {
                    id.wipe()
                }
                Status.SENT
            } catch (e: AegisException.FrameTooLarge) {
                post { notice = R.string.err_too_large }
                Status.FAILED
            } catch (e: AegisException.NeedsUpdate) {
                post { notice = R.string.err_contact_update }
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
                    Chat(c.messages.map { if (it.status == Status.SENDING && it.tsMs < cutoff) it.copy(status = Status.FAILED) else it }, c.unread)
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
        val g = Group(GroupCrypto.groupId(secret), secret, name, all, 0, d.username)
        update { it.copy(groups = it.groups + g) }
        sendInvites(g.id, null)
        done(g.id, null)
    }

    fun resendInvites(groupId: String) = sendInvites(groupId, null)

    private fun sendInvites(groupId: String, onlyFor: String?) {
        val d0 = data ?: return
        val g0 = d0.group(groupId) ?: return
        for (u in g0.members) {
            if (u == d0.username || (onlyFor != null && u != onlyFor)) continue
            realRequest {
                val d = data ?: return@realRequest
                val g = d.group(groupId) ?: return@realRequest
                val id = Identity(d.xSk, d.edSk)
                try {
                    val client = clientFor(d.settings)
                    val c = d.contact(u) ?: throw AegisException.InvalidUsername()
                    val env = Envelope(
                        Kind.Ginv, newId(), d.username, d.settings.displayName, id.edPublic,
                        System.currentTimeMillis(), g.ttlS, g.id, g.name, g.secret, g.members,
                    )
                    sendPairwise(client, d, id, c, env)
                    distribute(client, d, id, groupKey(g.id), g.id, listOf(u))
                } catch (e: Exception) {
                    post { notice = R.string.err_invites }
                } finally {
                    id.wipe()
                }
            }
        }
    }

    /** Leaving only deletes the local copy; other members are not told. */
    fun leaveGroup(id: String) = update { d ->
        val g = d.group(id) ?: return@update d
        g.secret.fill(0)
        dropMedia(d.chat(groupKey(id)).messages)
        d.copy(groups = d.groups.filter { it.id != id }, chats = d.chats - groupKey(id), cursors = d.cursors - g.queueHex, prefs = d.prefs - groupKey(id))
    }

    // ---- channels ----------------------------------------------------------

    /** Anyone can create a channel; the creator is its only poster. Invites go to the chosen contacts. */
    fun createChannel(rawName: String, subscribers: List<String>, done: (String?, Int?) -> Unit) {
        val d = data ?: return done(null, R.string.err_generic)
        val name = Text.sanitizeDisplay(rawName).trim()
        if (name.isEmpty()) return done(null, R.string.err_group_name)
        if (subscribers.size > ChannelCrypto.MAX_SUBSCRIBERS) return done(null, R.string.err_group_size)
        val secret = ChannelCrypto.newSecret()
        val id = Identity(d.xSk, d.edSk)
        val ownerEd = id.edPublic.copyOf()
        id.wipe()
        val ch = Channel(ChannelCrypto.channelId(secret), secret, name, d.username, ownerEd)
        update { it.copy(channels = it.channels + ch) }
        if (subscribers.isNotEmpty()) inviteToChannel(ch.id, subscribers)
        done(ch.id, null)
    }

    fun inviteToChannel(channelId: String, users: List<String>) {
        val d0 = data ?: return
        val ch0 = d0.channel(channelId) ?: return
        if (!ch0.mine(d0.username)) return
        for (u in users) {
            realRequest {
                val d = data ?: return@realRequest
                val ch = d.channel(channelId) ?: return@realRequest
                val id = Identity(d.xSk, d.edSk)
                try {
                    val client = clientFor(d.settings)
                    val c = d.contact(u) ?: throw AegisException.InvalidUsername()
                    if (c.keyChanged) throw AegisException.SenderMismatch()
                    val env = Envelope(
                        Kind.Cinv, newId(), d.username, d.settings.displayName, id.edPublic,
                        System.currentTimeMillis(), 0, ch.id, ch.name, ch.secret,
                    )
                    sendPairwise(client, d, id, c, env)
                    synchronized(d.fs) { d.fs.audience.getOrPut(channelKey(ch.id)) { HashSet() }.add(u) }
                    distribute(client, d, id, channelKey(ch.id), ch.id, listOf(u))
                } catch (e: Exception) {
                    post { notice = R.string.err_invites }
                } finally {
                    id.wipe()
                }
            }
        }
    }

    /** Removes the local copy. The official channel stays. */
    fun deleteChannel(id: String) = update { d ->
        val ch = d.channel(id) ?: return@update d
        if (ch.official) return@update d
        val qhex = Hex.encode(ChannelCrypto.queue(ch.secret))
        ch.secret.fill(0)
        dropMedia(d.chat(channelKey(id)).messages)
        d.copy(
            channels = d.channels.filter { it.id != id }, chats = d.chats - channelKey(id),
            cursors = d.cursors - qhex, prefs = d.prefs - channelKey(id),
        )
    }

    // ---- chat list actions ---------------------------------------------------

    fun setPinned(keys: Collection<String>, pinned: Boolean) = update { d ->
        d.copy(prefs = d.prefs + keys.associateWith { ChatPrefs(pinned, d.pref(it).muted) })
    }

    fun setMuted(keys: Collection<String>, muted: Boolean) = update { d ->
        d.copy(prefs = d.prefs + keys.associateWith { ChatPrefs(d.pref(it).pinned, muted) })
    }

    /** Direct chats lose their history, groups and channels are removed locally. */
    fun deleteChats(keys: Collection<String>) {
        for (k in keys) when {
            k.startsWith("g:") -> leaveGroup(k.removePrefix("g:"))
            k.startsWith("c:") -> deleteChannel(k.removePrefix("c:"))
            else -> deleteChatHistory(k)
        }
    }

    // ---- profile -------------------------------------------------------------

    /** Saves the profile card and sends it to every contact (spec section 22). */
    fun saveProfile(name: String, about: String, particles: Particles, done: (Int?) -> Unit) {
        val n = Text.sanitizeDisplay(name).trim()
        val a = Text.sanitizeDisplay(about).trim()
        try { Profile(n, a, particles).encode() } catch (e: AegisException) { return done(R.string.err_profile) }
        update { it.copy(profile = OwnProfile(n, a, particles)) }
        sendProfile(null)
        touch()
        done(null)
    }

    fun sendProfile(only: List<String>?) {
        val d0 = data ?: return
        for (c0 in d0.contacts) {
            if (c0.keyChanged || (only != null && c0.username !in only)) continue
            val u = c0.username
            realRequest {
                val d = data ?: return@realRequest
                val c = d.contact(u) ?: return@realRequest
                val body = try { Profile(d.profile.name.ifEmpty { d.settings.displayName }, d.profile.about, d.profile.particles).encode() } catch (e: AegisException) { return@realRequest }
                val id = Identity(d.xSk, d.edSk)
                try {
                    val env = Envelope(Kind.Prof, newId(), d.username, d.settings.displayName, id.edPublic, System.currentTimeMillis(), 0, "", body)
                    sendPairwise(clientFor(d.settings), d, id, c, env)
                } catch (e: Exception) { /* best effort; the next profile change resends */ } finally {
                    id.wipe()
                }
            }
        }
    }

    fun saveLook(l: org.aegis.messenger.data.Look) = update { it.copy(look = l.sanitize()) }

    /** Cleans the picked image like an outgoing photo and keeps it as the wallpaper. */
    fun setWallPhoto(uri: Uri) {
        busy = true
        net.execute {
            try {
                val p = MediaPrep.fromUri(ctx, uri)
                if (p.kind != MediaKind.Image) throw AegisException.Media("type")
                val b64 = android.util.Base64.encodeToString(p.bytes, android.util.Base64.NO_WRAP)
                p.bytes.fill(0)
                post { data?.let { saveLook(it.look.copy(photo = b64, wall = "photo")) } }
            } catch (e: Throwable) {
                post { notice = R.string.err_media }
            } finally {
                post { busy = false }
            }
        }
    }

    fun setTor(on: Boolean) {
        Boot.setTor(ctx, on)
        Tor.setEnabled(on)
    }

    fun setBackgroundPoll(on: Boolean) {
        Boot.setBackgroundPoll(ctx, on)
        if (on) data?.let { BgState.store(ctx, it.settings.endpoint, it.settings.proxy, it.xSk) } else BgState.clear(ctx)
        BgState.schedule(ctx, on)
    }

    /** Deletes every message and attachment but keeps contacts, groups and channels. */
    fun wipeAllChats() {
        store()?.deleteAll()
        update { d -> d.copy(chats = emptyMap()) }
    }

    // ---- settings ----------------------------------------------------------

    fun saveSettings(s: Settings, done: (Int?) -> Unit) {
        try { Endpoint.parse(s.endpoint) } catch (e: AegisException) { return done(R.string.err_endpoint_invalid) }
        try { Route.plan(Tor.enabled, s.endpoint, "") } catch (e: AegisException.Network) { return done(R.string.err_clearnet_tor) }
        if (s.proxy.isNotBlank()) try { ProxyAddr.parse(s.proxy) } catch (e: AegisException) { return done(R.string.err_proxy_invalid) }
        val title = Text.sanitizeDisplay(s.displayName)
        val clean = s.copy(
            endpoint = Endpoint.parse(s.endpoint).origin,
            proxy = if (s.proxy.isBlank()) "" else ProxyAddr.parse(s.proxy).toString(),
            displayName = title,
            pollSeconds = s.pollSeconds.coerceIn(10, 600),
        )
        // The name travels only in the profile card (spec section 3), so a new one goes out as a card.
        val renamed = data?.let { it.settings.displayName != clean.displayName } == true
        update { d ->
            val endpointChanged = d.settings.endpoint != clean.endpoint
            // A different server needs a fresh directory registration; cursors belong to the old server.
            d.copy(
                settings = clean.copy(hidden = d.settings.hidden),
                registered = d.registered && !endpointChanged,
                cursors = if (endpointChanged) emptyMap() else d.cursors,
            )
        }
        if (Boot.backgroundPoll(ctx)) data?.let { BgState.store(ctx, clean.endpoint, clean.proxy, it.xSk) }
        Boot.setAppLock(ctx, clean.appLock)
        touch()
        pollSoon()
        if (renamed) sendProfile(null)
        done(null)
    }
}
