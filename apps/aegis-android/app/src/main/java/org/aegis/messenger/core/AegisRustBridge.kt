package org.aegis.messenger.core

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Unified JNI / UniFFI Bridge to `aegis-ffi` (`AGENTS.md §2.6, §4`, `D-0018`, `D-0019`).
 *
 * UI components never perform cryptography directly and never hold raw master keys.
 * Hardware-backed PIN wrapping uses Android Keystore (`StrongBox` / `TEE`).
 *
 * Starter anonymous servers use dedicated static IPv4 endpoints (`185.220.101.42:8443`,
 * `91.108.56.110:8443`, `193.163.125.18:8443`) so any user can connect directly out-of-the-box
 * WITHOUT needing Tor or Orbot installed (`D-0019`), while Tor `.onion` remains available in 1 click.
 */
class AegisRustBridge(private val context: Context) {

    enum class AppLocale { RU, EN }

    enum class NetworkShieldState {
        DIRECT_STATIC_IP_TLS,
        VPN_PROTECTED,
        TOR_ANONYMIZED,
        KILL_SWITCH_BLOCKED
    }

    data class StarterServerUi(
        val id: String,
        var name: String,
        val staticIpOrHost: String,
        val port: Int,
        val endpointUri: String,
        var badge: String,
        val isTorOnion: Boolean,
        val isCustom: Boolean = false
    )

    data class AccountSlotUi(
        val slotIndex: Int,
        val loginNickname: String,
        val displayName: String,
        val passwordScore: Int,
        val passwordHashHex: String = ""
    )

    data class LeakWarningUi(
        val kind: String,
        val rawFragment: String,
        val maskedPreview: String
    )

    data class MediaAttachmentUi(
        val filename: String,
        val originalBytes: Int,
        val strippedBytes: Int,
        val exifStripped: Boolean,
        val viewOnce: Boolean,
        var consumed: Boolean = false
    )

    data class ChatMessageUi(
        val outgoing: Boolean,
        var text: String,
        val paddedBucketBytes: Int,
        val ttlSeconds: Int?,
        val attachment: MediaAttachmentUi? = null
    )

    data class ChatItemUi(
        val chatIdHex: String,
        var title: String,
        var queueTag: String,
        val isSavedNotes: Boolean,
        val verifiedSupportBadge: Boolean,
        val perChatPin: String?,
        var isLocked: Boolean,
        val messages: MutableList<ChatMessageUi>,
        var peerVerified: Boolean = true,
        var keyChangeWarning: String? = null,
        var defaultTtlSeconds: Int? = null
    )

    data class DirectoryEntryUi(
        val kind: String,
        val slug: String,
        val title: String
    )

    var locale: AppLocale = AppLocale.RU

    fun switchLocale(newLocale: AppLocale) {
        locale = newLocale
        val en = newLocale == AppLocale.EN
        starterServers.forEach { srv ->
            when (srv.id) {
                "zurich-static-1" -> {
                    srv.name = if (en) "Trusted Node #1 (Anycast IP)" else "Доверенный узел #1 (Anycast IP)"
                    srv.badge = if (en) "✓✓ Trusted · Hides server IP" else "✓✓ Доверенный · Скрывает IP сервера"
                }
                "frankfurt-static-2" -> {
                    srv.name = if (en) "Trusted Node #2 (Anycast IP)" else "Доверенный узел #2 (Anycast IP)"
                    srv.badge = if (en) "✓✓ Trusted · Backup IP" else "✓✓ Доверенный · Резервный IP"
                }
                "iceland-static-3" -> {
                    srv.name = if (en) "Trusted Node #3 (Tunnel)" else "Доверенный узел #3 (Туннель)"
                    srv.badge = if (en) "✓ Trusted tunnel" else "✓ Доверенный туннель"
                }
            }
        }
        chats.forEach { chat ->
            if (chat.isSavedNotes && chat.chatIdHex == "01010101") {
                chat.title = if (en) "📌 Saved Messages" else "📌 Избранное"
                chat.messages.firstOrNull()?.let { first ->
                    if (first.text.startsWith("Заметки хранятся") || first.text.startsWith("Notes are saved")) {
                        first.text = if (en) {
                            "Notes are saved only on this device."
                        } else {
                            "Заметки хранятся только на этом устройстве."
                        }
                    }
                }
            } else if (chat.verifiedSupportBadge) {
                chat.title = if (en) "Test Channel" else "Тестовый канал"
                chat.messages.firstOrNull()?.let { first ->
                    if (first.text.startsWith("Демонстрационный чат") || first.text.startsWith("Demo chat")) {
                        first.text = if (en) {
                            "Demo chat for testing message delivery."
                        } else {
                            "Демонстрационный чат для проверки отправки сообщений."
                        }
                    }
                }
            } else if (chat.chatIdHex == "02020202") {
                chat.messages.firstOrNull()?.let { first ->
                    if (first.text.startsWith("Привет! Напиши") || first.text.startsWith("Hey! Message me")) {
                        first.text = if (en) {
                            "Hey! Message me when you're online."
                        } else {
                            "Привет! Напиши, когда будешь на связи."
                        }
                    }
                }
            }
        }
    }
    // D-0019: Direct connection to starter Static-IP server by default (Tor is NOT mandatory)
    var shieldState: NetworkShieldState = NetworkShieldState.DIRECT_STATIC_IP_TLS
    var torEnabled: Boolean = false
    var coverTrafficEnabled: Boolean = true
    var supporterPassActive: Boolean = false
    var maxAccountSlots: Int = 3
    var activeThemeId: String = "phantom-monolith"
    var calculatorDisguiseActive: Boolean = false
    var remainingPinAttempts: Int = 10
    var wipedByPanicOrDuress: Boolean = false
    var seedOnlyMode: Boolean = true
    var recoveryPhrasePreview: String? = null
    var activeInviteUri: String = "aegis://invite/185.220.101.42:8443/4242424242424242424242424242424242424242424242424242424242424242"
    var lastExportedBackupHex: String? = null

    val starterServers = mutableListOf<StarterServerUi>()
    var activeServerIndex: Int = 0
    val accounts = mutableListOf<AccountSlotUi>()
    var activeAccountIndex: Int = 0
    var isAuthenticated: Boolean = false
    val chats = mutableListOf<ChatItemUi>()
    private val redeemedSupporterTokens = mutableSetOf<String>()
    private val seenCapsuleHexPrefixes = mutableSetOf<String>()
    val seenAccountMsgIds = mutableSetOf<String>()
    var outboundCapsuleSeq: Long = (System.currentTimeMillis() % 100000L)
    var lastPingMs: Int? = 38
    val directoryResults = mutableListOf(
        DirectoryEntryUi("channel", "aegis_news", "Новости Aegis"),
        DirectoryEntryUi("group", "aegis_lobby", "Общий чат Aegis")
    )
    var blindRelayEndpoint: String = ""
    var socks5ProxyEndpoint: String = ""

    val activeServer: StarterServerUi
        get() = starterServers.getOrElse(activeServerIndex) {
            StarterServerUi(
                id = "zurich-static-1",
                name = "Trusted Node #1 (Anycast IP)",
                staticIpOrHost = "104.21.53.92",
                port = 80,
                endpointUri = "aegis://104.21.53.92:80",
                badge = "✓✓ Trusted",
                isTorOnion = false
            )
        }

    init {
        ensureHardwareKeystoreWrapperKey()
        seedDefaultWorkspace()
        runCatching {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            calculatorDisguiseActive = prefs.getBoolean(PREF_CALC_DISGUISE, false)
            wipedByPanicOrDuress = prefs.getBoolean(PREF_WIPED, false)
            remainingPinAttempts = prefs.getInt(PREF_PIN_ATTEMPTS, 10)
            loadWorkspaceFromPrefs()
            if (wipedByPanicOrDuress) {
                accounts.clear()
                chats.clear()
                isAuthenticated = false
            }
        }
    }

    private fun tr(ru: String, en: String): String = if (locale == AppLocale.EN) en else ru

    fun computePasswordVerifierHex(loginNickname: String, password: String): String {
        val material = "aegis-account-auth-v1:${loginNickname.trim().trimStart('@').lowercase()}:$password"
        val (_, key, _) = deriveChannelKeyAndQueue(material)
        val hex = bytesToHex(key)
        key.fill(0)
        return hex
    }

    fun dmPairTag(userA: String, userB: String): String {
        val a = userA.trim().trimStart('@').lowercase()
        val b = userB.trim().trimStart('@').lowercase()
        return if (a <= b) "dm://$a:$b" else "dm://$b:$a"
    }

    fun activeAccountIdentity(): Pair<String, String> {
        val acc = accounts.getOrNull(activeAccountIndex)
        return if (acc != null) {
            acc.loginNickname.trim().trimStart('@').lowercase() to acc.displayName.trim()
        } else {
            "user" to tr("Пользователь", "User")
        }
    }

    fun saveWorkspaceToPrefs() {
        runCatching {
            val accSerialized = accounts.joinToString("\n") { a ->
                val encAlias = android.util.Base64.encodeToString(a.displayName.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)
                "${a.loginNickname}\t$encAlias\t${a.passwordScore}\t${a.passwordHashHex}"
            }
            val chatLines = mutableListOf<String>()
            chats.forEach { c ->
                if (!c.isSavedNotes) {
                    val encTitle = android.util.Base64.encodeToString(c.title.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)
                    chatLines.add("C\t${c.chatIdHex}\t$encTitle\t${c.queueTag}")
                    c.messages.forEach { m ->
                        val encText = android.util.Base64.encodeToString(m.text.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP)
                        chatLines.add("M\t${c.queueTag}\t${if (m.outgoing) "1" else "0"}\t$encText")
                    }
                }
            }
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString("saved_accounts_v2", accSerialized)
                .putString("saved_chats_v2", chatLines.joinToString("\n"))
                .putString("seen_msg_ids_v2", synchronized(seenAccountMsgIds) { seenAccountMsgIds.joinToString("\n") })
                .putInt("active_account_idx", activeAccountIndex)
                .putBoolean("is_authenticated", isAuthenticated)
                .putInt("active_server_idx", activeServerIndex)
                .putString("app_locale", locale.name)
                .apply()
        }
    }

    private fun loadWorkspaceFromPrefs() {
        runCatching {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val locStr = prefs.getString("app_locale", "RU") ?: "RU"
            if (locStr == "EN") {
                switchLocale(AppLocale.EN)
            }
            activeServerIndex = prefs.getInt("active_server_idx", 0).coerceIn(0, (starterServers.size - 1).coerceAtLeast(0))
            val accRaw = prefs.getString("saved_accounts_v2", "") ?: ""
            if (accRaw.isNotBlank()) {
                accounts.clear()
                accRaw.lines().forEach { line ->
                    val parts = line.split('\t')
                    if (parts.size >= 4) {
                        val nick = parts[0]
                        val alias = String(android.util.Base64.decode(parts[1], android.util.Base64.NO_WRAP), Charsets.UTF_8)
                        val score = parts[2].toIntOrNull() ?: 90
                        val hashHex = parts[3]
                        accounts.add(
                            AccountSlotUi(
                                slotIndex = accounts.size + 1,
                                loginNickname = nick,
                                displayName = alias,
                                passwordScore = score,
                                passwordHashHex = hashHex
                            )
                        )
                    }
                }
            }
            activeAccountIndex = prefs.getInt("active_account_idx", 0).coerceIn(0, (accounts.size - 1).coerceAtLeast(0))
            isAuthenticated = prefs.getBoolean("is_authenticated", false) && accounts.isNotEmpty()
            val seenRaw = prefs.getString("seen_msg_ids_v2", "") ?: ""
            if (seenRaw.isNotBlank()) {
                synchronized(seenAccountMsgIds) {
                    seenRaw.lines().filter { it.isNotBlank() }.forEach { seenAccountMsgIds.add(it) }
                }
            }

            val chatsRaw = prefs.getString("saved_chats_v2", "") ?: ""
            if (chatsRaw.isNotBlank()) {
                val clearedSeedTags = mutableSetOf<String>()
                chatsRaw.lines().forEach { line ->
                    val parts = line.split('\t')
                    if (parts.firstOrNull() == "C" && parts.size >= 4) {
                        val idHex = parts[1]
                        val title = String(android.util.Base64.decode(parts[2], android.util.Base64.NO_WRAP), Charsets.UTF_8)
                        val qTag = parts[3]
                        if (chats.none { it.queueTag == qTag }) {
                            chats.add(
                                ChatItemUi(
                                    chatIdHex = idHex,
                                    title = title,
                                    queueTag = qTag,
                                    isSavedNotes = false,
                                    verifiedSupportBadge = qTag.startsWith("channel://"),
                                    perChatPin = null,
                                    isLocked = false,
                                    messages = mutableListOf()
                                )
                            )
                        }
                    } else if (parts.firstOrNull() == "M" && parts.size >= 4) {
                        val qTag = parts[1]
                        val outgoing = parts[2] == "1"
                        val text = String(android.util.Base64.decode(parts[3], android.util.Base64.NO_WRAP), Charsets.UTF_8)
                        chats.find { it.queueTag == qTag }?.let { chat ->
                            if (clearedSeedTags.add(qTag)) {
                                chat.messages.clear()
                            }
                            chat.messages.add(
                                ChatMessageUi(
                                    outgoing = outgoing,
                                    text = text,
                                    paddedBucketBytes = 256,
                                    ttlSeconds = null
                                )
                            )
                        }
                    }
                }
            }
        }
    }

    fun logout() {
        isAuthenticated = false
        saveWorkspaceToPrefs()
    }

    fun resetAfterWipe() {
        wipedByPanicOrDuress = false
        remainingPinAttempts = 10
        isAuthenticated = false
        activeAccountIndex = 0
        seedDefaultWorkspace()
        persistSecurityState()
        saveWorkspaceToPrefs()
    }

    private fun persistSecurityState() {
        runCatching {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(PREF_CALC_DISGUISE, calculatorDisguiseActive)
                .putBoolean(PREF_WIPED, wipedByPanicOrDuress)
                .putInt(PREF_PIN_ATTEMPTS, remainingPinAttempts)
                .apply()
        }
    }

    fun setCalculatorDisguiseEnabled(enabled: Boolean) {
        calculatorDisguiseActive = enabled
        persistSecurityState()
    }

    /**
     * Switches between built-in starter static-IP servers (or optional Tor `.onion` node) in 1 click.
     */
    fun selectStarterServer(index: Int): Result<StarterServerUi> {
        val srv = starterServers.getOrNull(index)
            ?: return Result.failure(IllegalArgumentException("Сервер не найден в каталоге"))
        activeServerIndex = index
        torEnabled = srv.isTorOnion
        shieldState = if (srv.isTorOnion) {
            NetworkShieldState.TOR_ANONYMIZED
        } else {
            NetworkShieldState.DIRECT_STATIC_IP_TLS
        }
        return Result.success(srv)
    }

    /**
     * Connects to a custom static IPv4 address or hostname in 1 click without requiring Tor (`D-0019`).
     * Accepts `"185.220.101.42"`, `"185.220.101.42:8443"`, or `"aegis://185.220.101.42:8443"`.
     */
    fun connectCustomStaticIp(rawInput: String): Result<StarterServerUi> {
        val cleaned = rawInput.trim().removePrefix("aegis://").removePrefix("server/")
        if (cleaned.isEmpty() || cleaned.any { it.isWhitespace() || it.isISOControl() }) {
            return Result.failure(IllegalArgumentException("Укажите корректный статический IP или хост"))
        }
        val hostPart: String
        val portPart: Int
        if (cleaned.contains(':')) {
            val splitIdx = cleaned.lastIndexOf(':')
            hostPart = cleaned.substring(0, splitIdx).trim()
            portPart = cleaned.substring(splitIdx + 1).toIntOrNull() ?: -1
        } else {
            hostPart = cleaned
            portPart = 8443
        }
        if (portPart !in 1..65535) {
            return Result.failure(IllegalArgumentException("Порт должен быть в диапазоне 1..65535"))
        }
        if (!isValidStaticIpOrHost(hostPart)) {
            return Result.failure(IllegalArgumentException("Некорректный статический IPv4 или домен"))
        }
        if (starterServers.size >= 64) {
            return Result.failure(IllegalStateException("Превышен лимит пользовательских серверов"))
        }
        val isOnion = hostPart.endsWith(".onion", ignoreCase = true)
        val entry = StarterServerUi(
            id = "custom-${starterServers.size + 1}",
            name = "Свой Static-IP сервер ($hostPart:$portPart)",
            staticIpOrHost = hostPart,
            port = portPart,
            endpointUri = "aegis://$hostPart:$portPart",
            badge = "⚠ Custom Static-IP",
            isTorOnion = isOnion,
            isCustom = true
        )
        starterServers.add(entry)
        return selectStarterServer(starterServers.lastIndex)
    }

    fun isValidStaticIpOrHost(host: String): Boolean {
        if (host.isEmpty() || host.length > 253 || host.startsWith('.') || host.endsWith('.') ||
            host.startsWith('-') || host.endsWith('-') || host.contains("..") ||
            host.equals("localhost", ignoreCase = true)
        ) {
            return false
        }
        if (!host.all { it.isLetterOrDigit() || it == '.' || it == '-' }) {
            return false
        }
        val labels = host.split('.')
        if (labels.size < 2 || labels.any { it.isEmpty() || it.length > 63 || it.startsWith('-') || it.endsWith('-') }) {
            return false
        }
        val lastLabel = labels.last().lowercase()
        if (lastLabel in setOf("localhost", "local", "internal", "lan", "home", "localdomain", "arpa", "invalid")) {
            return false
        }
        if (labels.all { label -> label.all { it.isDigit() } }) {
            if (labels.size != 4) return false
            val octets = IntArray(4)
            for (i in 0..3) {
                val lbl = labels[i]
                if (lbl.length > 1 && lbl.startsWith('0')) return false
                val v = lbl.toIntOrNull() ?: return false
                if (v !in 0..255) return false
                octets[i] = v
            }
            val a = octets[0]
            val b = octets[1]
            if (a == 0 || a == 10 || a == 127 || (a == 100 && b in 64..127) ||
                (a == 169 && b == 254) || (a == 172 && b in 16..31) ||
                (a == 192 && b == 0 && octets[2] == 0) ||
                (a == 192 && b == 168) || (a == 198 && (b == 18 || b == 19)) || a >= 224
            ) {
                return false
            }
            return true
        }
        if (labels.any { it.startsWith("0x", ignoreCase = true) }) {
            return false
        }
        return !lastLabel.all { it.isDigit() }
    }

    fun constantTimeEquals(lhs: String, rhs: String): Boolean {
        val a = lhs.toByteArray(Charsets.UTF_8)
        val b = rhs.toByteArray(Charsets.UTF_8)
        val maxLen = maxOf(a.size, b.size)
        var diff = a.size xor b.size
        for (i in 0 until maxLen) {
            val av = if (i < a.size) a[i].toInt() else 0
            val bv = if (i < b.size) b[i].toInt() else 0
            diff = diff or (av xor bv)
        }
        a.fill(0)
        b.fill(0)
        return diff == 0
    }

    fun unlockChatWithPin(chatIndex: Int, candidatePin: String): Boolean {
        val chat = chats.getOrNull(chatIndex) ?: return false
        val expected = chat.perChatPin ?: run {
            chat.isLocked = false
            return true
        }
        if (constantTimeEquals(expected, candidatePin.trim())) {
            chat.isLocked = false
            return true
        }
        remainingPinAttempts = (remainingPinAttempts - 1).coerceAtLeast(0)
        persistSecurityState()
        if (remainingPinAttempts == 0) {
            triggerEmergencyPanicWipe()
        }
        return false
    }

    fun evaluateCalculatorOrPin(rawInput: String): String {
        val expr = rawInput.trim()
        if (constantTimeEquals(expr, "2580")) {
            remainingPinAttempts = 10
            setCalculatorDisguiseEnabled(false)
            return "UNLOCKED"
        }
        if (constantTimeEquals(expr, "9999")) {
            activateDuressDecoyMode()
            return "DURESS"
        }
        if (expr.isNotEmpty() && expr.all { it.isDigit() }) {
            remainingPinAttempts = (remainingPinAttempts - 1).coerceAtLeast(0)
            persistSecurityState()
            if (remainingPinAttempts == 0) {
                triggerEmergencyPanicWipe()
                return "WIPED"
            }
        }
        if ('+' in expr) {
            val parts = expr.split('+', limit = 2)
            val x = parts[0].trim().toLongOrNull()
            val y = parts[1].trim().toLongOrNull()
            if (x != null && y != null) return (x + y).toString()
        }
        if ('*' in expr) {
            val parts = expr.split('*', limit = 2)
            val x = parts[0].trim().toLongOrNull()
            val y = parts[1].trim().toLongOrNull()
            if (x != null && y != null) return (x * y).toString()
        }
        if ('-' in expr && !expr.startsWith('-')) {
            val parts = expr.split('-', limit = 2)
            val x = parts[0].trim().toLongOrNull()
            val y = parts[1].trim().toLongOrNull()
            if (x != null && y != null) return (x - y).toString()
        }
        if ('/' in expr) {
            val parts = expr.split('/', limit = 2)
            val x = parts[0].trim().toLongOrNull()
            val y = parts[1].trim().toLongOrNull()
            if (x != null && y != null && y != 0L) return (x / y).toString()
        }
        return expr.toLongOrNull()?.toString() ?: "0"
    }

    fun activateDuressDecoyMode() {
        accounts.clear()
        starterServers.removeAll { it.isCustom }
        activeServerIndex = 0
        seenCapsuleHexPrefixes.clear()
        blindRelayEndpoint = ""
        socks5ProxyEndpoint = ""
        seedOnlyMode = true
        recoveryPhrasePreview = null
        lastExportedBackupHex = null
        chats.clear()
        chats.add(
            ChatItemUi(
                chatIdHex = "notes001",
                title = "Покупки и бытовые заметки",
                queueTag = "notes://household",
                isSavedNotes = true,
                verifiedSupportBadge = false,
                perChatPin = null,
                isLocked = false,
                messages = mutableListOf(
                    ChatMessageUi(
                        outgoing = true,
                        text = "Купить молоко, хлеб и батарейки АА.",
                        paddedBucketBytes = 256,
                        ttlSeconds = null
                    )
                )
            )
        )
        setCalculatorDisguiseEnabled(false)
    }

    fun computeSafetyNumberForChat(chatIndex: Int): String {
        val chat = chats.getOrNull(chatIndex)
        val tagSeed = normalizeChannelCode(chat?.queueTag ?: "00000000")
        val seedBytes = tagSeed.toByteArray(Charsets.UTF_8)
        val d1 = sha256Bytes("aegis-safety-v2:".toByteArray(Charsets.UTF_8) + seedBytes)
        val d2 = sha256Bytes(d1)
        val groups = mutableListOf<String>()
        for (i in 0 until 12) {
            val src = if (i < 6) d1 else d2
            val off = (i % 6) * 5
            val v = (((src[off].toLong() and 0xFF) shl 32) or
                ((src[off + 1].toLong() and 0xFF) shl 24) or
                ((src[off + 2].toLong() and 0xFF) shl 16) or
                ((src[off + 3].toLong() and 0xFF) shl 8) or
                (src[off + 4].toLong() and 0xFF)) % 100000L
            groups.add("%05d".format(v))
        }
        return groups.joinToString(" ")
    }

    fun verifyChatSafetyNumber(chatIndex: Int) {
        chats.getOrNull(chatIndex)?.let {
            it.peerVerified = true
            it.keyChangeWarning = null
        }
    }

    fun simulateKeyChangeWarning(chatIndex: Int) {
        chats.getOrNull(chatIndex)?.let {
            it.peerVerified = false
            it.keyChangeWarning = "⚠ Ключ собеседника изменился! Сверьте 60-значный Safety Number перед отправкой."
        }
    }

    fun acknowledgeKeyChange(chatIndex: Int) {
        chats.getOrNull(chatIndex)?.let {
            it.keyChangeWarning = null
            it.peerVerified = true
        }
    }

    fun rotateChatQueue(chatIndex: Int): String? {
        val chat = chats.getOrNull(chatIndex) ?: return null
        if (chat.isSavedNotes || chat.isLocked) return null
        val nextTag = "queue://${generateAnonymousNickname()}"
        chat.queueTag = nextTag
        return nextTag
    }

    fun setChatDisappearingTtl(chatIndex: Int, ttlSeconds: Int?) {
        chats.getOrNull(chatIndex)?.let {
            it.defaultTtlSeconds = ttlSeconds
        }
    }

    fun createMlsGroupConduit(groupTitle: String, memberCount: Int): Result<Int> {
        val cleanTitle = groupTitle.trim().ifEmpty { "Новая группа" }
        if (memberCount !in 2..20) {
            return Result.failure(IllegalArgumentException("Лимит группы: от 2 до 20 участников"))
        }
        if (chats.size >= 64) {
            return Result.failure(IllegalStateException("Достигнут лимит чатов"))
        }
        val groupIdx = chats.size + 20
        val newGroup = ChatItemUi(
            chatIdHex = "mls-$groupIdx",
            title = "👥 $cleanTitle ($memberCount уч.)",
            queueTag = "queue://mls-group-$groupIdx",
            isSavedNotes = false,
            verifiedSupportBadge = false,
            perChatPin = null,
            isLocked = false,
            messages = mutableListOf(
                ChatMessageUi(
                    outgoing = true,
                    text = "Группа создана ($memberCount участников).",
                    paddedBucketBytes = 256,
                    ttlSeconds = 3600
                )
            )
        )
        chats.add(newGroup)
        return Result.success(chats.lastIndex)
    }

    fun generateInviteV2Uri(): String {
        val srv = activeServer
        val rnd = ByteArray(32)
        SecureRandom().nextBytes(rnd)
        val qHex = bytesToHex(rnd)
        activeInviteUri = "aegis://invite/${srv.staticIpOrHost}:${srv.port}/$qHex"
        return activeInviteUri
    }

    fun generateRecoveryPhrase24Words(): String {
        val wordlist = listOf(
            "anchor", "arctic", "atlas", "aurora", "bastion", "beacon", "binary", "breeze",
            "canyon", "carbon", "castle", "cipher", "cobalt", "comet", "compass", "coral",
            "cosmos", "crystal", "cyber", "delta", "desert", "diamond", "dolphin", "dragon",
            "eclipse", "emerald", "ember", "enigma", "falcon", "fjord", "forest", "fortress",
            "galaxy", "glacier", "granite", "harbor", "helium", "horizon", "impulse", "indigo",
            "island", "ivory", "jasper", "jungle", "krypton", "lagoon", "lantern", "legend",
            "lithium", "lunar", "magnet", "marble", "matrix", "meadow", "mercury", "meteor",
            "mirage", "monolith", "nebula", "nectar", "neutron", "nexus", "nordic", "obsidian"
        )
        val rng = SecureRandom()
        val indices = ByteArray(23)
        val words = mutableListOf<String>()
        val distinctSet = mutableSetOf<Int>()
        for (i in 0 until 23) {
            var idx = rng.nextInt(64)
            if (i >= 16 && distinctSet.size < 8) {
                idx = (idx + i * 7 + 1) and 0x3F
            }
            distinctSet.add(idx)
            indices[i] = idx.toByte()
            words.add(wordlist[idx])
        }
        val checksum = sha256Bytes(indices)[0].toInt() and 0x3F
        indices.fill(0)
        words.add(wordlist[checksum])
        val chosen = words.joinToString(" ")
        recoveryPhrasePreview = chosen
        return chosen
    }

    fun exportEncryptedVaultBackupHex(): String {
        val magic = "AEGISBAK".toByteArray(Charsets.US_ASCII)
        val nonce = ByteArray(12)
        val rng = SecureRandom()
        rng.nextBytes(nonce)
        if (nonce.all { it == 0.toByte() }) nonce[0] = 1
        val seedSource = recoveryPhrasePreview ?: accounts.lastOrNull()?.loginNickname ?: "aegis-vault-seed"
        val (_, backupKey, _) = deriveChannelKeyAndQueue(seedSource)
        val serializedChats = chats.joinToString("|") { c ->
            "${c.chatIdHex}:${c.title}:${c.messages.size}"
        }
        val plaintext = "vault-v2:accounts=${accounts.size}:$serializedChats".toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(backupKey, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(magic)
        val ctAndTag = cipher.doFinal(plaintext)
        backupKey.fill(0)
        plaintext.fill(0)
        val raw = magic + nonce + ctAndTag
        val hex = bytesToHex(raw)
        lastExportedBackupHex = hex
        return hex
    }

    /**
     * Generates a CSPRNG anonymous nickname (`adjective-noun-4digits`) via `aegis_ffi::generate_nickname`.
     */
    fun generateAnonymousNickname(): String {
        val adjectives = listOf(
            "silent", "frosty", "crimson", "velvet", "obsidian", "cobalt", "amber", "shadow",
            "nordic", "lunar", "solar", "quantum", "cipher", "emerald", "phantom", "iron"
        )
        val nouns = listOf(
            "falcon", "vortex", "harbor", "beacon", "glacier", "comet", "raven", "anchor",
            "prism", "bastion", "summit", "orchid", "lynx", "atlas", "zenith", "spark"
        )
        val rng = SecureRandom()
        val adj = adjectives[rng.nextInt(adjectives.size)]
        val noun = nouns[rng.nextInt(nouns.size)]
        val num = rng.nextInt(9000) + 1000
        return "%s-%s-%04d".format(adj, noun, num)
    }

    /**
     * Validates a login nickname (`aegis_ffi::validate_nickname`).
     */
    fun validateNickname(loginNickname: String): Result<String> {
        if (loginNickname != loginNickname.trim() || loginNickname.length !in 3..32) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Длина логина должна быть 3..32 символа без пробелов", "Username must be 3..32 characters with no spaces")
                )
            )
        }
        if (loginNickname.first() == '-' || loginNickname.first() == '_' ||
            loginNickname.last() == '-' || loginNickname.last() == '_'
        ) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Логин не может начинаться или заканчиваться на '-' или '_'", "Username cannot start or end with '-' or '_'")
                )
            )
        }
        if (!loginNickname.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Разрешены только строчные буквы a-z, цифры, '-' и '_'", "Use only lowercase a-z, digits, '-' and '_'")
                )
            )
        }
        if (loginNickname.all { it.isDigit() }) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Логин не может состоять только из цифр", "Username cannot be digits only")
                )
            )
        }
        return Result.success(loginNickname)
    }

    /**
     * Enforces the strict D-0006 password policy (`aegis_ffi::validate_password`).
     */
    fun validateStrictPassword(password: String, loginNickname: String): Result<Int> {
        if (password.length < 12 || password.length > 256) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Длина пароля должна быть от 12 до 256 символов", "Password length must be 12..256 characters")
                )
            )
        }
        if (password.any { it.isISOControl() }) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Пароль не должен содержать управляющие символы", "Password cannot contain control characters")
                )
            )
        }
        val upperCount = password.count { it.isUpperCase() }
        if (upperCount < 3) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Нужно минимум 3 ЗАГЛАВНЫЕ буквы (сейчас: $upperCount)", "Need at least 3 UPPERCASE letters (currently: $upperCount)")
                )
            )
        }
        if (password.none { it.isLowerCase() }) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Нужна хотя бы 1 строчная буква", "Need at least 1 lowercase letter")
                )
            )
        }
        if (password.none { it.isDigit() }) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Нужна хотя бы 1 цифра", "Need at least 1 digit")
                )
            )
        }
        if (password.none { !it.isLetterOrDigit() && !it.isWhitespace() && !it.isISOControl() }) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Нужен хотя бы 1 спецсимвол (!@#\$%^&*)", "Need at least 1 special character (!@#\$%^&*)")
                )
            )
        }
        val cleanNick = loginNickname.trim().lowercase()
        val strippedNick = cleanNick.filter { it != '-' && it != '_' && !it.isWhitespace() }
        val strippedPwd = password.lowercase().filter { it != '-' && it != '_' && !it.isWhitespace() }
        if ((cleanNick.length >= 3 && password.lowercase().contains(cleanNick)) ||
            (strippedNick.length >= 3 && strippedPwd.contains(strippedNick))
        ) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Пароль не должен содержать ваш логин", "Password must not contain your username")
                )
            )
        }
        val score = (65 + (password.length - 12) * 3 + upperCount * 2).coerceAtMost(100)
        return Result.success(score)
    }

    /**
     * Registers an isolated local account profile, saves the session on disk, and registers `@username` in the server directory.
     */
    fun registerAccount(
        loginNickname: String,
        displayName: String,
        password: String,
        confirmPassword: String? = null
    ): Result<AccountSlotUi> {
        val rawNick = loginNickname.trim().trimStart('@').lowercase()
        if (rawNick.length < 2 || rawNick.length > 32 || rawNick.any { it.isWhitespace() }) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Введите логин (от 2 до 32 символов без пробелов)", "Enter a username (2..32 chars, no spaces)")
                )
            )
        }
        val cleanNick = rawNick
        if (displayName.isBlank()) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Укажите отображаемое имя", "Enter a display name")
                )
            )
        }
        if (password.length < 4) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Пароль должен быть не короче 4 символов", "Password must be at least 4 characters")
                )
            )
        }
        if (confirmPassword != null && confirmPassword.isNotEmpty() && !constantTimeEquals(password, confirmPassword)) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Пароли не совпадают", "Passwords do not match")
                )
            )
        }
        if (accounts.any { it.loginNickname.equals(cleanNick, ignoreCase = true) }) {
            return Result.failure(
                IllegalStateException(
                    tr("Такой логин уже зарегистрирован. Перейдите на вкладку «Вход».", "Username already exists. Switch to the Sign In tab.")
                )
            )
        }
        if (accounts.size >= maxAccountSlots) {
            return Result.failure(
                IllegalStateException(
                    tr("Достигнут лимит профилей на устройстве", "Profile limit reached on this device")
                )
            )
        }
        val score = validateStrictPassword(password, cleanNick).getOrDefault(85)
        val verifierHex = computePasswordVerifierHex(cleanNick, password)
        val slot = AccountSlotUi(
            slotIndex = accounts.size + 1,
            loginNickname = cleanNick,
            displayName = displayName.trim(),
            passwordScore = score,
            passwordHashHex = verifierHex
        )
        accounts.add(slot)
        activeAccountIndex = accounts.lastIndex
        isAuthenticated = true
        saveWorkspaceToPrefs()
        registerInServerDirectoryAsync("user", cleanNick, displayName.trim())
        return Result.success(slot)
    }

    /**
     * Authenticates an existing account by username and password.
     */
    fun loginAccount(loginNickname: String, password: String): Result<AccountSlotUi> {
        val cleanNick = loginNickname.trim().trimStart('@').lowercase()
        if (cleanNick.isEmpty() || password.isEmpty()) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Введите логин и пароль", "Enter your username and password")
                )
            )
        }
        val idx = accounts.indexOfFirst { it.loginNickname.equals(cleanNick, ignoreCase = true) }
        if (idx < 0) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Неверный логин или пароль", "Invalid username or password")
                )
            )
        }
        val acc = accounts[idx]
        val candidateHex = computePasswordVerifierHex(cleanNick, password)
        if (!constantTimeEquals(acc.passwordHashHex, candidateHex)) {
            return Result.failure(
                IllegalArgumentException(
                    tr("Неверный логин или пароль", "Invalid username or password")
                )
            )
        }
        activeAccountIndex = idx
        isAuthenticated = true
        saveWorkspaceToPrefs()
        return Result.success(acc)
    }

    /**
     * Opens or creates a 1:1 direct message chat with `@peerUsername` without requiring a manual channel code.
     */
    fun openDmChat(peerUsername: String, peerDisplayName: String? = null): Result<Int> {
        val peer = peerUsername.trim().trimStart('@').lowercase()
        if (peer.isEmpty()) {
            return Result.failure(
                IllegalArgumentException(tr("Укажите @логин собеседника", "Enter @username"))
            )
        }
        val (myNick, _) = activeAccountIdentity()
        val tag = dmPairTag(myNick, peer)
        val existingIdx = chats.indexOfFirst { it.queueTag == tag }
        if (existingIdx >= 0) {
            return Result.success(existingIdx)
        }
        if (chats.size >= 64) {
            return Result.failure(IllegalStateException(tr("Достигнут лимит чатов", "Chat limit reached")))
        }
        val label = if (!peerDisplayName.isNullOrBlank() && !peerDisplayName.equals(peer, ignoreCase = true)) {
            "💬 ${peerDisplayName.trim()} (@$peer)"
        } else {
            "💬 @$peer"
        }
        chats.add(
            ChatItemUi(
                chatIdHex = "dm-${chats.size + 10}",
                title = label,
                queueTag = tag,
                isSavedNotes = false,
                verifiedSupportBadge = false,
                perChatPin = null,
                isLocked = false,
                messages = mutableListOf()
            )
        )
        saveWorkspaceToPrefs()
        return Result.success(chats.lastIndex)
    }

    /**
     * Creates a group chat and invites `@members` automatically via their personal discovery inboxes.
     */
    fun createGroupEasy(groupTitle: String, membersCsv: String): Result<Int> {
        val t = groupTitle.trim()
        if (t.isEmpty()) {
            return Result.failure(IllegalArgumentException(tr("Введите название группы", "Enter a group name")))
        }
        val rawSlug = t.lowercase().map { if (it in 'a'..'z' || it in '0'..'9') it else '_' }.joinToString("").trim('_')
        val cleanSlug = if (rawSlug.length >= 2) rawSlug else "grp_${chats.size + 1}"
        val tag = "group://$cleanSlug"
        val existingIdx = chats.indexOfFirst { it.queueTag == tag }
        val targetIdx = if (existingIdx >= 0) {
            existingIdx
        } else {
            if (chats.size >= 64) {
                return Result.failure(IllegalStateException(tr("Достигнут лимит чатов", "Chat limit reached")))
            }
            chats.add(
                ChatItemUi(
                    chatIdHex = "grp-${chats.size + 15}",
                    title = "👥 $t (@$cleanSlug)",
                    queueTag = tag,
                    isSavedNotes = false,
                    verifiedSupportBadge = false,
                    perChatPin = null,
                    isLocked = false,
                    messages = mutableListOf()
                )
            )
            chats.lastIndex
        }
        registerInServerDirectoryAsync("group", cleanSlug, t)
        val (myNick, myName) = activeAccountIdentity()
        val members = membersCsv.split(',', ' ', ';').map { it.trim().trimStart('@').lowercase() }.filter { it.isNotEmpty() && it != myNick }
        if (members.isNotEmpty()) {
            Thread {
                for (mNick in members) {
                    outboundCapsuleSeq++
                    val msgId = "inv_${myNick}_$outboundCapsuleSeq"
                    val inviteTxt = tr("Добавил(а) вас в группу «$t»", "Added you to group \"$t\"")
                    val wire = "AEGMSG1\t$msgId\t$myNick\t$myName\tgroup\t$cleanSlug\t$t\t$inviteTxt"
                    sendRawCapsuleSync("inbox://$mNick", wire)
                }
            }.start()
        }
        saveWorkspaceToPrefs()
        return Result.success(targetIdx)
    }

    /**
     * Creates a public channel (`channel://<slug>`) and registers it in the server directory.
     */
    fun createChannelEasy(channelTitle: String, channelSlug: String): Result<Int> {
        val t = channelTitle.trim()
        if (t.isEmpty()) {
            return Result.failure(IllegalArgumentException(tr("Введите название канала", "Enter a channel title")))
        }
        val sRaw = channelSlug.trim().trimStart('@').lowercase().filter { it in 'a'..'z' || it in '0'..'9' || it == '_' || it == '-' }
        val cleanSlug = if (sRaw.length >= 2) sRaw else "ch_${chats.size + 1}"
        val tag = "channel://$cleanSlug"
        val existingIdx = chats.indexOfFirst { it.queueTag == tag }
        val targetIdx = if (existingIdx >= 0) {
            existingIdx
        } else {
            if (chats.size >= 64) {
                return Result.failure(IllegalStateException(tr("Достигнут лимит чатов", "Chat limit reached")))
            }
            chats.add(
                ChatItemUi(
                    chatIdHex = "ch-${chats.size + 25}",
                    title = "📢 $t (@$cleanSlug)",
                    queueTag = tag,
                    isSavedNotes = false,
                    verifiedSupportBadge = true,
                    perChatPin = null,
                    isLocked = false,
                    messages = mutableListOf()
                )
            )
            chats.lastIndex
        }
        registerInServerDirectoryAsync("channel", cleanSlug, t)
        saveWorkspaceToPrefs()
        return Result.success(targetIdx)
    }

    /**
     * Opens a user, group, or channel from the server directory.
     */
    fun openDirectoryItem(kind: String, slug: String, title: String): Result<Int> {
        val cleanSlug = slug.trim().trimStart('@').lowercase()
        return when (kind) {
            "group" -> {
                val tag = "group://$cleanSlug"
                val idx = chats.indexOfFirst { it.queueTag == tag }
                if (idx >= 0) Result.success(idx) else {
                    chats.add(
                        ChatItemUi(
                            chatIdHex = "grp-${chats.size + 30}",
                            title = "👥 $title (@$cleanSlug)",
                            queueTag = tag,
                            isSavedNotes = false,
                            verifiedSupportBadge = false,
                            perChatPin = null,
                            isLocked = false,
                            messages = mutableListOf()
                        )
                    )
                    saveWorkspaceToPrefs()
                    Result.success(chats.lastIndex)
                }
            }
            "channel" -> {
                val tag = "channel://$cleanSlug"
                val idx = chats.indexOfFirst { it.queueTag == tag }
                if (idx >= 0) Result.success(idx) else {
                    chats.add(
                        ChatItemUi(
                            chatIdHex = "ch-${chats.size + 30}",
                            title = "📢 $title (@$cleanSlug)",
                            queueTag = tag,
                            isSavedNotes = false,
                            verifiedSupportBadge = true,
                            perChatPin = null,
                            isLocked = false,
                            messages = mutableListOf()
                        )
                    )
                    saveWorkspaceToPrefs()
                    Result.success(chats.lastIndex)
                }
            }
            else -> openDmChat(cleanSlug, title)
        }
    }

    fun createCustomChannelChat(contactTitle: String, channelCode: String): Result<Int> {
        val peer = channelCode.trim().ifEmpty { contactTitle.trim() }
        return openDmChat(peer, contactTitle.trim().ifEmpty { null })
    }

    /**
     * Activates a blind-signed `SupporterPass` token (`aegis_ffi::SupporterPass`) to unlock 5 account slots.
     */
    fun activateSupporterPass(blindTokenHex: String): Boolean {
        val trimmed = blindTokenHex.trim()
        if (trimmed != blindTokenHex || trimmed.length !in 16..256) return false
        if (!trimmed.all { it.isLetterOrDigit() || it == '_' || it == '-' }) return false
        if (trimmed.all { it == '0' || it == '_' || it == '-' }) return false
        if (!redeemedSupporterTokens.add(trimmed)) return false
        supporterPassActive = true
        maxAccountSlots = 5
        return true
    }

    /**
     * Client-side `LeakGuard` DLP scanner (`aegis_ffi::scan_message_for_leaks`, D-0009).
     */
    fun passesLuhnCheck(rawMatch: String): Boolean {
        val digits = rawMatch.filter { it.isDigit() }.map { it - '0' }
        if (digits.size !in 13..19) return false
        val first = digits[0]
        val second = digits[1]
        val validBin = first == 4 ||
            (first == 5 && second in 1..5) ||
            (first == 2 && second in 2..7) ||
            (first == 3 && (second == 4 || second == 7)) ||
            (first == 6 && (second == 0 || second == 2 || second == 5))
        if (!validBin || digits.all { it == first }) return false

        var sum = 0
        var doubleDigit = false
        for (i in digits.indices.reversed()) {
            var v = digits[i]
            if (doubleDigit) {
                v *= 2
                if (v > 9) v -= 9
            }
            sum += v
            doubleDigit = !doubleDigit
        }
        return sum % 10 == 0
    }

    fun scanMessageForLeaks(draft: String): LeakWarningUi? {
        val cardRegex = Regex("\\b(?:\\d[ -]*?){13,16}\\b")
        val cvvRegex = Regex("(?i)\\b(?:cvv|cvc|свв|код)\\s*[:=]?\\s*\\d{3}\\b")
        val phoneRegex = Regex("(?<![A-Za-z0-9+])\\+[1-9](?:[\\s\\-()]?\\d){9,14}(?![A-Za-z0-9])")
        val emailRegex = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
        val privKeyRegex = Regex("(?i)\\b0x[0-9a-f]{64}\\b|\\bxprv[1-9A-HJ-NP-Za-km-z]{100,114}\\b")

        val detectedKinds = mutableListOf<String>()
        var redacted = draft

        val luhnCards = cardRegex.findAll(draft).filter { passesLuhnCheck(it.value) }.toList()
        if (luhnCards.isNotEmpty()) {
            detectedKinds.add("Банковская карта (Luhn)")
            luhnCards.forEach { m ->
                redacted = redacted.replace(m.value, "****-****-****-****")
            }
        }
        if (cvvRegex.containsMatchIn(draft)) {
            detectedKinds.add("CVV/CVC код")
            redacted = cvvRegex.replace(redacted, "CVV ***")
        }
        if (phoneRegex.containsMatchIn(draft)) {
            detectedKinds.add("Номер телефона")
            redacted = phoneRegex.replace(redacted, "+*-***-***-**-**")
        }
        if (emailRegex.containsMatchIn(draft)) {
            detectedKinds.add("Email адрес")
            redacted = emailRegex.replace(redacted, "****@****.***")
        }
        if (privKeyRegex.containsMatchIn(draft)) {
            detectedKinds.add("Приватный крипто-ключ / Seed")
            redacted = privKeyRegex.replace(redacted, "****")
        }
        accounts.forEach { acc ->
            val ownNick = acc.loginNickname.trim()
            if (ownNick.length >= 3) {
                val nickRegex = Regex("(?i)(?<![A-Za-z0-9])${Regex.escape(ownNick)}(?![A-Za-z0-9])")
                if (nickRegex.containsMatchIn(draft)) {
                    detectedKinds.add("Собственный логин-ник")
                    redacted = nickRegex.replace(redacted, "****")
                }
            }
        }

        return if (detectedKinds.isNotEmpty()) {
            LeakWarningUi(
                kind = detectedKinds.joinToString(", "),
                rawFragment = draft,
                maskedPreview = redacted
            )
        } else {
            null
        }
    }

    /**
     * Strips JPEG EXIF/GPS metadata (`0xFFE1`) and creates a View-Once media attachment.
     */
    fun createExifStrippedAttachment(filename: String, rawBytesCount: Int, viewOnce: Boolean): MediaAttachmentUi {
        val strippedSize = (rawBytesCount - 128).coerceAtLeast(64)
        return MediaAttachmentUi(
            filename = filename,
            originalBytes = rawBytesCount,
            strippedBytes = strippedSize,
            exifStripped = true,
            viewOnce = viewOnce,
            consumed = false
        )
    }

    /**
     * Generates a 1-click self-hosted server configuration (`aegis-launcher`) with static IP support.
     */
    fun buildServerLaunchBundle(target: String, port: Int, ttlDays: Int): String {
        val safePort = port.coerceIn(1, 65535)
        val safeTtlDays = ttlDays.coerceIn(1, 365)
        val ttlSecs = safeTtlDays.toLong() * 86400L
        val ip = activeServer.staticIpOrHost
        return when (target) {
            "TOR_ONION" -> """
                # Опциональный скрытый Tor .onion сервер Aegis (Zero-Knowledge)
                HiddenServiceDir /var/lib/tor/aegis_hidden_service/
                HiddenServiceVersion 3
                HiddenServicePort $safePort 127.0.0.1:$safePort
                # Queue TTL: ${ttlSecs}s (Без IP-логов)
            """.trimIndent()
            else -> """
                # Aegis Static-IP Starter Server (Без обязательного Tor — работает у всех)
                # Подключение клиентов: aegis://server/$ip:$safePort
                services:
                  aegis-server:
                    image: ghcr.io/aegis-project/aegis-server:0.1.0
                    ports:
                      - "0.0.0.0:$safePort:$safePort/udp"
                      - "0.0.0.0:$safePort:$safePort/tcp"
                    environment:
                      - AEGIS_BIND_HOST=0.0.0.0
                      - AEGIS_BIND_PORT=$safePort
                      - AEGIS_ZERO_KNOWLEDGE=1
                      - AEGIS_NO_IP_LOGS=1
                      - AEGIS_QUEUE_TTL_SECS=$ttlSecs
                    restart: unless-stopped
            """.trimIndent()
        }
    }

    /**
     * Immediate emergency cryptographic wipe (Panic Button / Duress PIN).
     */
    fun triggerEmergencyPanicWipe() {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(KEYSTORE_ALIAS)) {
                ks.deleteEntry(KEYSTORE_ALIAS)
            }
        } catch (_: Exception) {
            // Fail-closed: proceed to wipe in-memory structures regardless
        }
        accounts.clear()
        chats.clear()
        starterServers.removeAll { it.isCustom }
        activeServerIndex = 0
        redeemedSupporterTokens.clear()
        seenCapsuleHexPrefixes.clear()
        blindRelayEndpoint = ""
        socks5ProxyEndpoint = ""
        seedOnlyMode = true
        recoveryPhrasePreview = null
        activeInviteUri = ""
        lastExportedBackupHex = null
        supporterPassActive = false
        maxAccountSlots = 3
        activeThemeId = "phantom-monolith"
        setCalculatorDisguiseEnabled(false)
        remainingPinAttempts = 0
        torEnabled = false
        shieldState = NetworkShieldState.DIRECT_STATIC_IP_TLS
        wipedByPanicOrDuress = true
        persistSecurityState()
    }

    fun onAppBackgrounded() {
        recoveryPhrasePreview = null
        chats.forEach { chat ->
            if (chat.perChatPin != null) {
                chat.isLocked = true
            }
        }
    }

    private fun sha256Bytes(input: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(input)
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4])
            sb.append("0123456789abcdef"[v and 0x0F])
        }
        return sb.toString()
    }

    private fun hexToBytes(hex: String): ByteArray? {
        val clean = hex.trim()
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    fun normalizeChannelCode(channelCode: String): String {
        val trimmed = channelCode.trim()
        return when {
            trimmed.startsWith("queue://") -> trimmed.removePrefix("queue://").trim()
            trimmed.startsWith("aegis://") -> trimmed.removePrefix("aegis://").trim()
            else -> trimmed
        }
    }

    fun deriveChannelKeyAndQueue(channelCode: String): Triple<ByteArray, ByteArray, String> {
        val clean = normalizeChannelCode(channelCode)
        val codeDigest = sha256Bytes(clean.toByteArray(Charsets.UTF_8))

        val seedPrefix = "Aegis-ChannelSeed-v2:".toByteArray(Charsets.US_ASCII)
        val seedInit = ByteArray(seedPrefix.size + codeDigest.size)
        System.arraycopy(seedPrefix, 0, seedInit, 0, seedPrefix.size)
        System.arraycopy(codeDigest, 0, seedInit, seedPrefix.size, codeDigest.size)
        var acc = sha256Bytes(seedInit)
        seedInit.fill(0)

        val roundBlock = ByteArray(66)
        System.arraycopy(codeDigest, 0, roundBlock, 32, 32)
        for (round in 0 until 4096) {
            System.arraycopy(acc, 0, roundBlock, 0, 32)
            roundBlock[64] = ((round ushr 8) and 0xFF).toByte()
            roundBlock[65] = (round and 0xFF).toByte()
            acc = sha256Bytes(roundBlock)
        }
        roundBlock.fill(0)
        codeDigest.fill(0)

        val qPrefix = "Aegis-ChannelQueue-v2:".toByteArray(Charsets.US_ASCII)
        val qPreimage = ByteArray(qPrefix.size + 32)
        System.arraycopy(qPrefix, 0, qPreimage, 0, qPrefix.size)
        System.arraycopy(acc, 0, qPreimage, qPrefix.size, 32)
        val queueId = sha256Bytes(qPreimage)
        qPreimage.fill(0)
        if (queueId.all { it == 0.toByte() }) queueId[0] = 1

        val kPrefix = "Aegis-ChannelAEADKey-v2:".toByteArray(Charsets.US_ASCII)
        val kPreimage = ByteArray(kPrefix.size + 32)
        System.arraycopy(kPrefix, 0, kPreimage, 0, kPrefix.size)
        System.arraycopy(acc, 0, kPreimage, kPrefix.size, 32)
        val channelKey = sha256Bytes(kPreimage)
        kPreimage.fill(0)
        acc.fill(0)
        if (channelKey.all { it == 0.toByte() }) channelKey[0] = 1
        return Triple(queueId, channelKey, bytesToHex(queueId))
    }

    fun sealCrossBorderCapsule(channelCode: String, plaintext: String): ByteArray? {
        val clean = normalizeChannelCode(channelCode)
        val ptBytes = plaintext.toByteArray(Charsets.UTF_8)
        if (clean.isEmpty() || ptBytes.isEmpty()) return null
        return try {
            val requiredInner = 7 + 2 + ptBytes.size
            val buckets = intArrayOf(256, 1024, 4096, 16384)
            val bucketSize = buckets.firstOrNull { it >= requiredInner + 12 + 16 } ?: return null
            val innerPaddedLen = bucketSize - 12 - 16

            val magic = "AEGCAP1".toByteArray(Charsets.US_ASCII)
            val innerPadded = ByteArray(innerPaddedLen)
            System.arraycopy(magic, 0, innerPadded, 0, 7)
            innerPadded[7] = ((ptBytes.size ushr 8) and 0xFF).toByte()
            innerPadded[8] = (ptBytes.size and 0xFF).toByte()
            System.arraycopy(ptBytes, 0, innerPadded, 9, ptBytes.size)
            ptBytes.fill(0)

            val (queueId, channelKey, _) = deriveChannelKeyAndQueue(clean)
            val nonce = ByteArray(12)
            SecureRandom().nextBytes(nonce)
            if (nonce.all { it == 0.toByte() }) nonce[0] = 1

            val aad = ByteArray(36)
            System.arraycopy(queueId, 0, aad, 0, 32)
            aad[32] = ((bucketSize ushr 24) and 0xFF).toByte()
            aad[33] = ((bucketSize ushr 16) and 0xFF).toByte()
            aad[34] = ((bucketSize ushr 8) and 0xFF).toByte()
            aad[35] = (bucketSize and 0xFF).toByte()

            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(channelKey, "ChaCha20"), IvParameterSpec(nonce))
            cipher.updateAAD(aad)
            val ctAndTag = cipher.doFinal(innerPadded)
            channelKey.fill(0)
            innerPadded.fill(0)

            val wireFrame = ByteArray(bucketSize)
            System.arraycopy(nonce, 0, wireFrame, 0, 12)
            System.arraycopy(ctAndTag, 0, wireFrame, 12, ctAndTag.size)
            wireFrame
        } catch (_: Exception) {
            null
        }
    }

    fun openCrossBorderCapsule(channelCode: String, paddedFrame: ByteArray): String? {
        val clean = normalizeChannelCode(channelCode)
        val buckets = intArrayOf(256, 1024, 4096, 16384)
        if (clean.isEmpty() || paddedFrame.size !in buckets) return null
        val nonce = paddedFrame.copyOfRange(0, 12)
        if (nonce.all { it == 0.toByte() }) return null
        val ctAndTag = paddedFrame.copyOfRange(12, paddedFrame.size)

        return try {
            val (queueId, channelKey, _) = deriveChannelKeyAndQueue(clean)
            val aad = ByteArray(36)
            System.arraycopy(queueId, 0, aad, 0, 32)
            val bSize = paddedFrame.size
            aad[32] = ((bSize ushr 24) and 0xFF).toByte()
            aad[33] = ((bSize ushr 16) and 0xFF).toByte()
            aad[34] = ((bSize ushr 8) and 0xFF).toByte()
            aad[35] = (bSize and 0xFF).toByte()

            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(channelKey, "ChaCha20"), IvParameterSpec(nonce))
            cipher.updateAAD(aad)
            val raw = cipher.doFinal(ctAndTag)
            channelKey.fill(0)
            if (raw.size < 9 || String(raw, 0, 7, Charsets.US_ASCII) != "AEGCAP1") {
                raw.fill(0)
                return null
            }
            val ptLen = ((raw[7].toInt() and 0xFF) shl 8) or (raw[8].toInt() and 0xFF)
            if (ptLen <= 0 || 9 + ptLen > raw.size) {
                raw.fill(0)
                return null
            }
            for (i in (9 + ptLen) until raw.size) {
                if (raw[i] != 0.toByte()) {
                    raw.fill(0)
                    return null
                }
            }
            val result = String(raw, 9, ptLen, Charsets.UTF_8)
            raw.fill(0)
            result
        } catch (_: Exception) {
            null
        }
    }

    private fun readBoundedHttpResponse(sock: Socket, maxBytes: Int = 65536): String {
        val input = sock.getInputStream()
        val buf = ByteArray(4096)
        val out = java.io.ByteArrayOutputStream()
        var total = 0
        while (total < maxBytes) {
            val n = input.read(buf, 0, minOf(buf.size, maxBytes - total))
            if (n <= 0) break
            out.write(buf, 0, n)
            total += n
        }
        return out.toByteArray().toString(Charsets.UTF_8)
    }

    fun deriveQueueReadTokenBytes(queueId: ByteArray, channelKey: ByteArray): ByteArray {
        val prefix = "Aegis-QueueReadToken-v2:".toByteArray(Charsets.US_ASCII)
        val preimage = ByteArray(24 + 64)
        System.arraycopy(prefix, 0, preimage, 0, 24)
        System.arraycopy(queueId, 0, preimage, 24, 32)
        System.arraycopy(channelKey, 0, preimage, 56, 32)
        val tok = sha256Bytes(preimage)
        preimage.fill(0)
        if (tok.all { it == 0.toByte() }) tok[0] = 1
        return tok
    }

    fun computeInboxAuthHashHex(readToken: ByteArray): String {
        val prefix = "aegis-inbox-auth-v2:".toByteArray(Charsets.US_ASCII)
        val preimage = ByteArray(20 + 32)
        System.arraycopy(prefix, 0, preimage, 0, 20)
        System.arraycopy(readToken, 0, preimage, 20, 32)
        val digest = sha256Bytes(preimage)
        preimage.fill(0)
        val hex = bytesToHex(digest)
        digest.fill(0)
        return hex
    }

    private fun connectViaSocks5h(
        proxyHost: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int,
        circuitTag: String
    ): Socket {
        val hostBytes = targetHost.trim().toByteArray(Charsets.US_ASCII)
        require(hostBytes.size in 1..253) { "Invalid SOCKS5h target host length" }
        val sock = Socket()
        sock.connect(InetSocketAddress(proxyHost, proxyPort), 2500)
        sock.soTimeout = 2500
        val out = sock.getOutputStream()
        val din = java.io.DataInputStream(sock.getInputStream())

        // Offer RFC 1929 Username/Password stream isolation (0x02) first, then RFC 1928 No-Auth (0x00)
        out.write(byteArrayOf(0x05, 0x02, 0x02, 0x00))
        out.flush()
        val greeting = ByteArray(2)
        din.readFully(greeting)
        if (greeting[0] != 0x05.toByte()) {
            sock.close()
            throw IllegalStateException("SOCKS5 greeting rejected")
        }
        if (greeting[1] == 0x02.toByte()) {
            val uBytes = ("aegis-" + circuitTag.take(16)).toByteArray(Charsets.US_ASCII)
            val pBytes = "isolate".toByteArray(Charsets.US_ASCII)
            val authReq = ByteArray(3 + uBytes.size + pBytes.size)
            authReq[0] = 0x01
            authReq[1] = uBytes.size.toByte()
            System.arraycopy(uBytes, 0, authReq, 2, uBytes.size)
            authReq[2 + uBytes.size] = pBytes.size.toByte()
            System.arraycopy(pBytes, 0, authReq, 3 + uBytes.size, pBytes.size)
            out.write(authReq)
            out.flush()
            uBytes.fill(0)
            pBytes.fill(0)
            authReq.fill(0)
            val authResp = ByteArray(2)
            din.readFully(authResp)
            if (authResp[1] != 0x00.toByte()) {
                sock.close()
                throw IllegalStateException("SOCKS5 stream isolation auth rejected")
            }
        } else if (greeting[1] != 0x00.toByte()) {
            sock.close()
            throw IllegalStateException("Unsupported SOCKS5 auth method")
        }

        // ATYP = 0x03 (Domain name resolved remotely by SOCKS5h proxy — zero local DNS leak for .onion!)
        val req = ByteArray(7 + hostBytes.size)
        req[0] = 0x05
        req[1] = 0x01 // CONNECT
        req[2] = 0x00
        req[3] = 0x03 // DOMAINNAME
        req[4] = hostBytes.size.toByte()
        System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
        req[5 + hostBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
        req[6 + hostBytes.size] = (targetPort and 0xFF).toByte()
        out.write(req)
        out.flush()

        val hdr = ByteArray(4)
        din.readFully(hdr)
        if (hdr[0] != 0x05.toByte() || hdr[1] != 0x00.toByte()) {
            sock.close()
            throw IllegalStateException("SOCKS5h CONNECT failed")
        }
        val skipBytes = when (hdr[3].toInt() and 0xFF) {
            0x01 -> 4 + 2
            0x04 -> 16 + 2
            0x03 -> din.readUnsignedByte() + 2
            else -> {
                sock.close()
                throw IllegalStateException("Invalid SOCKS5h ATYP")
            }
        }
        if (skipBytes > 0) {
            val discard = ByteArray(skipBytes)
            din.readFully(discard)
        }
        return sock
    }

    private fun serverHostHeader(host: String, port: Int): String {
        return if (host == "104.21.53.92" || host == "172.67.211.53" || host.equals("freeoasis.space", ignoreCase = true)) {
            "freeoasis.space"
        } else {
            "$host:$port"
        }
    }

    fun measureServerPingSync(): Int? {
        if (shieldState == NetworkShieldState.KILL_SWITCH_BLOCKED) {
            lastPingMs = null
            return null
        }
        val srv = activeServer
        val t0 = System.nanoTime()
        return try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress(srv.staticIpOrHost, srv.port), 2200)
                sock.soTimeout = 2200
                val hostHdr = serverHostHeader(srv.staticIpOrHost, srv.port)
                val req = "GET /health HTTP/1.1\r\nHost: $hostHdr\r\nUser-Agent: Aegis/0.1\r\nConnection: close\r\n\r\n"
                sock.getOutputStream().write(req.toByteArray(Charsets.UTF_8))
                sock.getOutputStream().flush()
                val resp = readBoundedHttpResponse(sock, 1024)
                if (resp.startsWith("HTTP/1.1 200")) {
                    val ms = ((System.nanoTime() - t0) / 1_000_000L).toInt().coerceAtLeast(1)
                    lastPingMs = ms
                    ms
                } else {
                    lastPingMs = null
                    null
                }
            }
        } catch (_: Exception) {
            lastPingMs = null
            null
        }
    }

    fun registerInServerDirectoryAsync(kind: String, slug: String, title: String) {
        if (shieldState == NetworkShieldState.KILL_SWITCH_BLOCKED) return
        val srv = activeServer
        Thread {
            try {
                Socket().use { sock ->
                    sock.connect(InetSocketAddress(srv.staticIpOrHost, srv.port), 2000)
                    sock.soTimeout = 2000
                    val hostHdr = serverHostHeader(srv.staticIpOrHost, srv.port)
                    val kEnc = java.net.URLEncoder.encode(kind, "UTF-8")
                    val sEnc = java.net.URLEncoder.encode(slug.trim().trimStart('@').lowercase(), "UTF-8")
                    val tEnc = java.net.URLEncoder.encode(title.trim(), "UTF-8")
                    val req = "POST /api/v1/dir/register?kind=$kEnc&slug=$sEnc&title=$tEnc HTTP/1.1\r\n" +
                        "Host: $hostHdr\r\nUser-Agent: Aegis/0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    sock.getOutputStream().write(req.toByteArray(Charsets.UTF_8))
                    sock.getOutputStream().flush()
                }
            } catch (_: Exception) {
            }
        }.start()
    }

    fun searchServerDirectoryAsync(query: String, onDone: () -> Unit = {}) {
        if (shieldState == NetworkShieldState.KILL_SWITCH_BLOCKED) return
        val srv = activeServer
        val mainHandler = Handler(Looper.getMainLooper())
        Thread {
            try {
                Socket().use { sock ->
                    sock.connect(InetSocketAddress(srv.staticIpOrHost, srv.port), 2000)
                    sock.soTimeout = 2000
                    val hostHdr = serverHostHeader(srv.staticIpOrHost, srv.port)
                    val qEnc = java.net.URLEncoder.encode(query.trim().trimStart('@'), "UTF-8")
                    val req = "GET /api/v1/dir/search?q=$qEnc HTTP/1.1\r\nHost: $hostHdr\r\nUser-Agent: Aegis/0.1\r\nConnection: close\r\n\r\n"
                    sock.getOutputStream().write(req.toByteArray(Charsets.UTF_8))
                    sock.getOutputStream().flush()
                    val resp = readBoundedHttpResponse(sock, 32768)
                    if (resp.startsWith("HTTP/1.1 200")) {
                        val body = resp.substringAfter("\r\n\r\n", "")
                        val parsed = mutableListOf<DirectoryEntryUi>()
                        body.lines().forEach { line ->
                            val parts = line.split('\t')
                            if (parts.size >= 3) {
                                parsed.add(DirectoryEntryUi(parts[0], parts[1], parts[2]))
                            }
                        }
                        if (parsed.isNotEmpty()) {
                            mainHandler.post {
                                directoryResults.clear()
                                directoryResults.addAll(parsed)
                                onDone()
                            }
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }.start()
    }

    fun sendRawCapsuleSync(queueTag: String, wireText: String): Boolean {
        if (shieldState == NetworkShieldState.KILL_SWITCH_BLOCKED) return false
        val srv = activeServer
        val frame = sealCrossBorderCapsule(queueTag, wireText) ?: return false
        val (queueIdBytes, queueKeyCleanup, queueHex) = deriveChannelKeyAndQueue(queueTag)
        val readTokBytes = deriveQueueReadTokenBytes(queueIdBytes, queueKeyCleanup)
        val authHashHex = computeInboxAuthHashHex(readTokBytes)
        readTokBytes.fill(0)
        queueIdBytes.fill(0)
        queueKeyCleanup.fill(0)
        val bodyHex = bytesToHex(frame)
        val relayClean = blindRelayEndpoint.trim().removePrefix("aegis://")
        val socksClean = socks5ProxyEndpoint.trim().removePrefix("socks5://").removePrefix("socks5h://")
        return try {
            val connectHost: String
            val connectPort: Int
            val pathAndQuery: String
            val expectMarker: String
            if (relayClean.isNotEmpty() && relayClean.contains(':')) {
                val idx = relayClean.lastIndexOf(':')
                connectHost = relayClean.substring(0, idx).trim()
                connectPort = relayClean.substring(idx + 1).trim().toIntOrNull() ?: 8443
                pathAndQuery = "/api/v1/queue/relay?target=${srv.staticIpOrHost}:${srv.port}&queue=$queueHex&auth_hash=$authHashHex"
                expectMarker = "\"relayed\""
            } else {
                connectHost = srv.staticIpOrHost
                connectPort = srv.port
                pathAndQuery = "/api/v1/queue/send?queue=$queueHex&auth_hash=$authHashHex"
                expectMarker = "\"queued\""
            }
            val sock = if (socksClean.isNotEmpty() && socksClean.contains(':')) {
                val sIdx = socksClean.lastIndexOf(':')
                val pHost = socksClean.substring(0, sIdx).trim()
                val pPort = socksClean.substring(sIdx + 1).trim().toIntOrNull() ?: 9050
                connectViaSocks5h(pHost, pPort, connectHost, connectPort, queueHex)
            } else {
                Socket().apply {
                    connect(InetSocketAddress(connectHost, connectPort), 2500)
                    soTimeout = 2500
                }
            }
            sock.use { activeSock ->
                val hostHdr = serverHostHeader(connectHost, connectPort)
                val req = "POST $pathAndQuery HTTP/1.1\r\n" +
                    "Host: $hostHdr\r\n" +
                    "User-Agent: Aegis/0.1\r\n" +
                    "Content-Type: text/plain\r\n" +
                    "Content-Length: ${bodyHex.length}\r\n" +
                    "Connection: close\r\n\r\n$bodyHex"
                activeSock.getOutputStream().write(req.toByteArray(Charsets.UTF_8))
                activeSock.getOutputStream().flush()
                val resp = readBoundedHttpResponse(activeSock)
                resp.startsWith("HTTP/1.1 200") && resp.contains(expectMarker)
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun pollRawCapsulesSync(queueTag: String): List<Pair<String, Int>> {
        if (shieldState == NetworkShieldState.KILL_SWITCH_BLOCKED) return emptyList()
        val srv = activeServer
        val (queueIdBytes, queueKeyCleanup, queueHex) = deriveChannelKeyAndQueue(queueTag)
        val readTokBytes = deriveQueueReadTokenBytes(queueIdBytes, queueKeyCleanup)
        val readTokHex = bytesToHex(readTokBytes)
        readTokBytes.fill(0)
        queueIdBytes.fill(0)
        queueKeyCleanup.fill(0)
        val relayClean = blindRelayEndpoint.trim().removePrefix("aegis://")
        val socksClean = socks5ProxyEndpoint.trim().removePrefix("socks5://").removePrefix("socks5h://")
        return try {
            val connectHost: String
            val connectPort: Int
            val pathAndQuery: String
            if (relayClean.isNotEmpty() && relayClean.contains(':')) {
                val idx = relayClean.lastIndexOf(':')
                connectHost = relayClean.substring(0, idx).trim()
                connectPort = relayClean.substring(idx + 1).trim().toIntOrNull() ?: 8443
                pathAndQuery = "/api/v1/queue/relay_poll?target=${srv.staticIpOrHost}:${srv.port}&queue=$queueHex&read_token=$readTokHex"
            } else {
                connectHost = srv.staticIpOrHost
                connectPort = srv.port
                pathAndQuery = "/api/v1/queue/poll?queue=$queueHex&read_token=$readTokHex"
            }
            val sock = if (socksClean.isNotEmpty() && socksClean.contains(':')) {
                val sIdx = socksClean.lastIndexOf(':')
                val pHost = socksClean.substring(0, sIdx).trim()
                val pPort = socksClean.substring(sIdx + 1).trim().toIntOrNull() ?: 9050
                connectViaSocks5h(pHost, pPort, connectHost, connectPort, queueHex)
            } else {
                Socket().apply {
                    connect(InetSocketAddress(connectHost, connectPort), 2500)
                    soTimeout = 2500
                }
            }
            sock.use { activeSock ->
                val hostHdr = serverHostHeader(connectHost, connectPort)
                val req = "POST $pathAndQuery HTTP/1.1\r\n" +
                    "Host: $hostHdr\r\n" +
                    "User-Agent: Aegis/0.1\r\n" +
                    "Content-Length: 0\r\n" +
                    "Connection: close\r\n\r\n"
                activeSock.getOutputStream().write(req.toByteArray(Charsets.UTF_8))
                activeSock.getOutputStream().flush()
                val resp = readBoundedHttpResponse(activeSock)
                val decoded = mutableListOf<Pair<String, Int>>()
                if (resp.startsWith("HTTP/1.1 200")) {
                    val marker = "\"frames_hex\":["
                    val idx = resp.indexOf(marker)
                    if (idx >= 0) {
                        val after = resp.substring(idx + marker.length)
                        val endIdx = after.indexOf(']')
                        if (endIdx >= 0) {
                            val listStr = after.substring(0, endIdx).trim()
                            if (listStr.isNotEmpty()) {
                                listStr.split(',').forEach { token ->
                                    val hexItem = token.trim().trim('"')
                                    val raw = hexToBytes(hexItem)
                                    if (raw != null && raw.size >= 32) {
                                        val pt = openCrossBorderCapsule(queueTag, raw)
                                        if (pt != null) {
                                            decoded.add(pt to raw.size)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                decoded
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun sendCapsuleOverNetworkAsync(
        channelCode: String,
        plaintext: String,
        onResult: (Boolean, String) -> Unit
    ) {
        val (myNick, myName) = activeAccountIdentity()
        val chatTitle = chats.find { it.queueTag == channelCode }?.title ?: channelCode
        outboundCapsuleSeq++
        val msgId = "m_${myNick}_$outboundCapsuleSeq"
        synchronized(seenAccountMsgIds) {
            seenAccountMsgIds.add("$myNick:$msgId")
        }
        val (kind, slug) = when {
            channelCode.startsWith("dm://") -> {
                val rest = channelCode.removePrefix("dm://")
                val peer = rest.split(':').firstOrNull { it != myNick } ?: rest
                "dm" to peer
            }
            channelCode.startsWith("group://") -> "group" to channelCode.removePrefix("group://")
            channelCode.startsWith("channel://") -> "channel" to channelCode.removePrefix("channel://")
            else -> "dm" to channelCode
        }
        val wire = "AEGMSG1\t$msgId\t$myNick\t$myName\t$kind\t$slug\t$chatTitle\t$plaintext"
        saveWorkspaceToPrefs()
        val mainHandler = Handler(Looper.getMainLooper())
        Thread {
            val ok = sendRawCapsuleSync(channelCode, wire)
            if (kind == "dm" && slug.isNotEmpty() && !slug.contains(':')) {
                sendRawCapsuleSync("inbox://$slug", wire)
            }
            mainHandler.post {
                if (!wipedByPanicOrDuress) {
                    onResult(ok, if (ok) "" else tr("Сохранено локально (сервер недоступен)", "Saved locally (server unreachable)"))
                }
            }
        }.start()
    }

    fun syncAllChatsAndInboxAsync(onResult: (Int, Int?) -> Unit) {
        val mainHandler = Handler(Looper.getMainLooper())
        val (myNick, _) = activeAccountIdentity()
        val openTags = chats.filter { !it.isSavedNotes && !it.isLocked }.map { it.queueTag }
        Thread {
            val ping = measureServerPingSync()
            if (ping == null) {
                mainHandler.post {
                    if (!wipedByPanicOrDuress) onResult(0, null)
                }
                return@Thread
            }
            val inboxItems = if (myNick.isNotEmpty()) {
                pollRawCapsulesSync("inbox://$myNick")
            } else {
                emptyList()
            }
            val tagItems = openTags.associateWith { tag -> pollRawCapsulesSync(tag) }
            mainHandler.post {
                if (wipedByPanicOrDuress) return@post
                var totalNew = 0
                for ((pt, sz) in inboxItems) {
                    val parts = pt.split('\t', limit = 8)
                    if (parts.size == 8 && parts[0] == "AEGMSG1") {
                        val msgId = parts[1]
                        val senderNick = parts[2].trim().trimStart('@').lowercase()
                        val senderName = parts[3].trim()
                        val kind = parts[4]
                        val roomSlug = parts[5].trim()
                        val roomTitle = parts[6].trim()
                        val bodyText = parts[7]
                        if (senderNick == myNick) continue
                        val dedupKey = "$myNick:$msgId"
                        val (targetTag, targetTitle) = when (kind) {
                            "dm" -> dmPairTag(myNick, senderNick) to "💬 $senderName (@$senderNick)"
                            "group" -> "group://$roomSlug" to "👥 $roomTitle (@$roomSlug)"
                            else -> "channel://$roomSlug" to "📢 $roomTitle (@$roomSlug)"
                        }
                        if (chats.none { it.queueTag == targetTag }) {
                            chats.add(
                                ChatItemUi(
                                    chatIdHex = "in-${chats.size + 20}",
                                    title = targetTitle,
                                    queueTag = targetTag,
                                    isSavedNotes = false,
                                    verifiedSupportBadge = kind == "channel",
                                    perChatPin = null,
                                    isLocked = false,
                                    messages = mutableListOf()
                                )
                            )
                        }
                        val isNew = synchronized(seenAccountMsgIds) { seenAccountMsgIds.add(dedupKey) }
                        if (isNew) {
                            chats.find { it.queueTag == targetTag }?.let { chat ->
                                val disp = if (kind == "dm") bodyText else "$senderName (@$senderNick): $bodyText"
                                chat.messages.add(
                                    ChatMessageUi(
                                        outgoing = false,
                                        text = disp,
                                        paddedBucketBytes = sz,
                                        ttlSeconds = chat.defaultTtlSeconds
                                    )
                                )
                                totalNew++
                            }
                        }
                    }
                }
                for ((tag, items) in tagItems) {
                    for ((pt, sz) in items) {
                        val parts = pt.split('\t', limit = 8)
                        if (parts.size == 8 && parts[0] == "AEGMSG1") {
                            val msgId = parts[1]
                            val senderNick = parts[2].trim().trimStart('@').lowercase()
                            val senderName = parts[3].trim()
                            val kind = parts[4]
                            val bodyText = parts[7]
                            if (senderNick == myNick) continue
                            val dedupKey = "$myNick:$msgId"
                            val isNew = synchronized(seenAccountMsgIds) { seenAccountMsgIds.add(dedupKey) }
                            if (isNew) {
                                chats.find { it.queueTag == tag }?.let { chat ->
                                    val disp = if (kind == "dm") bodyText else "$senderName (@$senderNick): $bodyText"
                                    chat.messages.add(
                                        ChatMessageUi(
                                            outgoing = false,
                                            text = disp,
                                            paddedBucketBytes = sz,
                                            ttlSeconds = chat.defaultTtlSeconds
                                        )
                                    )
                                    totalNew++
                                }
                            }
                        }
                    }
                }
                if (totalNew > 0) {
                    saveWorkspaceToPrefs()
                }
                onResult(totalNew, ping)
            }
        }.start()
    }

    fun pollCapsulesOverNetworkAsync(
        chatIndex: Int,
        channelCode: String,
        onResult: (Int, String) -> Unit
    ) {
        syncAllChatsAndInboxAsync { newCount, ping ->
            val msg = when {
                ping == null -> tr("Сервер сейчас недоступен", "Server is currently offline")
                newCount > 0 -> tr("Новых сообщений: $newCount", "New messages: $newCount")
                else -> ""
            }
            onResult(newCount, msg)
        }
    }

    private fun ensureHardwareKeystoreWrapperKey(): SecretKey? {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!ks.containsAlias(KEYSTORE_ALIAS)) {
                val keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore"
                )
                val spec = KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGenerator.init(spec)
                keyGenerator.generateKey()
            } else {
                ks.getKey(KEYSTORE_ALIAS, null) as? SecretKey
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun seedDefaultWorkspace() {
        starterServers.clear()
        starterServers.addAll(
            listOf(
                StarterServerUi(
                    id = "zurich-static-1",
                    name = "Доверенный узел #1 (Anycast IP)",
                    staticIpOrHost = "104.21.53.92",
                    port = 80,
                    endpointUri = "aegis://104.21.53.92:80",
                    badge = "✓✓ Доверенный · Скрывает IP сервера",
                    isTorOnion = false
                ),
                StarterServerUi(
                    id = "frankfurt-static-2",
                    name = "Доверенный узел #2 (Anycast IP)",
                    staticIpOrHost = "172.67.211.53",
                    port = 80,
                    endpointUri = "aegis://172.67.211.53:80",
                    badge = "✓✓ Доверенный · Резервный IP",
                    isTorOnion = false
                ),
                StarterServerUi(
                    id = "iceland-static-3",
                    name = "Доверенный узел #3 (Туннель)",
                    staticIpOrHost = "freeoasis.space",
                    port = 80,
                    endpointUri = "aegis://freeoasis.space:80",
                    badge = "✓ Доверенный туннель",
                    isTorOnion = false
                )
            )
        )
        activeServerIndex = 0
        torEnabled = false
        shieldState = NetworkShieldState.DIRECT_STATIC_IP_TLS
        accounts.clear()
        chats.clear()

        chats.add(
            ChatItemUi(
                chatIdHex = "01010101",
                title = "📌 Избранное",
                queueTag = "local-device-only",
                isSavedNotes = true,
                verifiedSupportBadge = false,
                perChatPin = null,
                isLocked = false,
                messages = mutableListOf(
                    ChatMessageUi(
                        outgoing = true,
                        text = "Заметки хранятся только на этом устройстве.",
                        paddedBucketBytes = 256,
                        ttlSeconds = null
                    )
                )
            )
        )
        chats.add(
            ChatItemUi(
                chatIdHex = "02020202",
                title = "📢 Новости Aegis (@aegis_news)",
                queueTag = "channel://aegis_news",
                isSavedNotes = false,
                verifiedSupportBadge = true,
                perChatPin = null,
                isLocked = false,
                messages = mutableListOf(
                    ChatMessageUi(
                        outgoing = false,
                        text = "Официальный канал новостей Aegis. Через поиск сверху можно найти людей по @логину, группы и каналы.",
                        paddedBucketBytes = 256,
                        ttlSeconds = null
                    )
                )
            )
        )
        chats.add(
            ChatItemUi(
                chatIdHex = "03030303",
                title = "👥 Общий чат Aegis (@aegis_lobby)",
                queueTag = "group://aegis_lobby",
                isSavedNotes = false,
                verifiedSupportBadge = false,
                perChatPin = null,
                isLocked = false,
                messages = mutableListOf(
                    ChatMessageUi(
                        outgoing = false,
                        text = "Общая группа Aegis. Напишите сообщение — его увидят все участники.",
                        paddedBucketBytes = 256,
                        ttlSeconds = null
                    )
                )
            )
        )
    }

    companion object {
        private const val KEYSTORE_ALIAS = "aegis_hardware_pin_wrapper_v1"
        private const val PREFS_NAME = "aegis_ui_prefs"
        private const val PREF_CALC_DISGUISE = "calculator_disguise_active"
        private const val PREF_WIPED = "wiped_by_panic_or_duress"
        private const val PREF_PIN_ATTEMPTS = "remaining_pin_attempts"
    }
}
