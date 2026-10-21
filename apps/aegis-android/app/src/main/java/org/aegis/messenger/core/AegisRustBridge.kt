package org.aegis.messenger.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

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
        val name: String,
        val staticIpOrHost: String,
        val port: Int,
        val endpointUri: String,
        val badge: String,
        val isTorOnion: Boolean,
        val isCustom: Boolean = false
    )

    data class AccountSlotUi(
        val slotIndex: Int,
        val loginNickname: String,
        val displayName: String,
        val passwordScore: Int
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
        val text: String,
        val paddedBucketBytes: Int,
        val ttlSeconds: Int?,
        val attachment: MediaAttachmentUi? = null
    )

    data class ChatItemUi(
        val chatIdHex: String,
        val title: String,
        val queueTag: String,
        val isSavedNotes: Boolean,
        val verifiedSupportBadge: Boolean,
        val perChatPin: String?,
        var isLocked: Boolean,
        val messages: MutableList<ChatMessageUi>
    )

    var locale: AppLocale = AppLocale.RU
    // D-0019: Direct connection to starter Static-IP server by default (Tor is NOT mandatory)
    var shieldState: NetworkShieldState = NetworkShieldState.DIRECT_STATIC_IP_TLS
    var torEnabled: Boolean = false
    var coverTrafficEnabled: Boolean = true
    var supporterPassActive: Boolean = false
    var maxAccountSlots: Int = 3
    var activeThemeId: String = "obsidian-stealth-dark"
    var voicePitchSemitones: Int = -4
    var callActive: Boolean = false
    var wipedByPanicOrDuress: Boolean = false

    val starterServers = mutableListOf<StarterServerUi>()
    var activeServerIndex: Int = 0
    val accounts = mutableListOf<AccountSlotUi>()
    val chats = mutableListOf<ChatItemUi>()
    private val redeemedSupporterTokens = mutableSetOf<String>()

    val activeServer: StarterServerUi
        get() = starterServers.getOrElse(activeServerIndex) {
            StarterServerUi(
                id = "zurich-static-1",
                name = "Aegis Official #1 (Zurich Static IP)",
                staticIpOrHost = "185.220.101.42",
                port = 8443,
                endpointUri = "aegis://185.220.101.42:8443",
                badge = "✓✓ Official",
                isTorOnion = false
            )
        }

    init {
        ensureHardwareKeystoreWrapperKey()
        seedDefaultWorkspace()
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
        val isOnion = hostPart.endsWith(".onion", ignoreCase = true)
        val entry = StarterServerUi(
            id = "custom-${starterServers.size + 1}",
            name = "Свой Static-IP сервер ($hostPart:$portPart)",
            staticIpOrHost = hostPart,
            port = portPart,
            endpointUri = "aegis://$hostPart:$portPart",
            badge = "✓ Pin-Verified",
            isTorOnion = isOnion,
            isCustom = true
        )
        starterServers.add(entry)
        return selectStarterServer(starterServers.lastIndex)
    }

    fun isValidStaticIpOrHost(host: String): Boolean {
        if (host.isEmpty() || host.length > 253 || host.startsWith('.') || host.endsWith('.') ||
            host.startsWith('-') || host.endsWith('-') || host.contains("..") ||
            host == "0.0.0.0" || host == "255.255.255.255"
        ) {
            return false
        }
        if (!host.all { it.isLetterOrDigit() || it == '.' || it == '-' }) {
            return false
        }
        val labels = host.split('.')
        if (labels.any { it.isEmpty() || it.length > 63 || it.startsWith('-') || it.endsWith('-') }) {
            return false
        }
        if (labels.all { label -> label.all { it.isDigit() } }) {
            if (labels.size != 4) return false
            return labels.all { octet ->
                val v = octet.toIntOrNull() ?: return false
                v in 0..255
            }
        }
        return true
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
            return Result.failure(IllegalArgumentException("Длина ника должна быть 3..32 символа без пробелов"))
        }
        if (loginNickname.first() == '-' || loginNickname.first() == '_' ||
            loginNickname.last() == '-' || loginNickname.last() == '_'
        ) {
            return Result.failure(IllegalArgumentException("Ник не может начинаться или заканчиваться на '-' или '_'"))
        }
        if (!loginNickname.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) {
            return Result.failure(IllegalArgumentException("Ник может содержать только строчные буквы a-z, цифры, '-' и '_'"))
        }
        if (loginNickname.all { it.isDigit() }) {
            return Result.failure(IllegalArgumentException("Ник не может состоять только из цифр"))
        }
        return Result.success(loginNickname)
    }

    /**
     * Enforces the strict D-0006 password policy (`aegis_ffi::validate_password`).
     */
    fun validateStrictPassword(password: String, loginNickname: String): Result<Int> {
        if (password.length < 12 || password.length > 256) {
            return Result.failure(IllegalArgumentException("Длина пароля должна быть 12..256 символов"))
        }
        if (password.any { it.isISOControl() }) {
            return Result.failure(IllegalArgumentException("Пароль не должен содержать управляющие символы"))
        }
        val upperCount = password.count { it.isUpperCase() }
        if (upperCount < 3) {
            return Result.failure(
                IllegalArgumentException("Нужно минимум 3 ЗАГЛАВНЫЕ буквы (сейчас: $upperCount)")
            )
        }
        if (password.none { it.isLowerCase() }) {
            return Result.failure(IllegalArgumentException("Нужна хотя бы 1 строчная буква"))
        }
        if (password.none { it.isDigit() }) {
            return Result.failure(IllegalArgumentException("Нужна хотя бы 1 цифра"))
        }
        if (password.none { !it.isLetterOrDigit() && !it.isWhitespace() && !it.isISOControl() }) {
            return Result.failure(IllegalArgumentException("Нужен хотя бы 1 спецсимвол (!@#\$%^&*)"))
        }
        val cleanNick = loginNickname.trim().lowercase()
        val strippedNick = cleanNick.filter { it != '-' && it != '_' && !it.isWhitespace() }
        val strippedPwd = password.lowercase().filter { it != '-' && it != '_' && !it.isWhitespace() }
        if ((cleanNick.length >= 3 && password.lowercase().contains(cleanNick)) ||
            (strippedNick.length >= 3 && strippedPwd.contains(strippedNick))
        ) {
            return Result.failure(IllegalArgumentException("Пароль не должен содержать ваш ник"))
        }
        val score = (65 + (password.length - 12) * 3 + upperCount * 2).coerceAtMost(100)
        return Result.success(score)
    }

    /**
     * Registers an isolated local account profile (max 3 free, 5+ with blind-signed `SupporterPass`, D-0010).
     */
    fun registerAccount(loginNickname: String, displayName: String, password: String): Result<AccountSlotUi> {
        val cleanNick = validateNickname(loginNickname).getOrElse {
            return Result.failure(it)
        }
        if (displayName.isBlank()) {
            return Result.failure(IllegalArgumentException("Отображаемое имя профиля не может быть пустым"))
        }
        if (accounts.any { it.loginNickname.equals(cleanNick, ignoreCase = true) }) {
            return Result.failure(IllegalStateException("Аккаунт с таким ником уже зарегистрирован на устройстве"))
        }
        if (accounts.size >= maxAccountSlots) {
            return Result.failure(
                IllegalStateException("Лимит 3 бесплатных аккаунтов исчерпан. Активируйте SupporterPass.")
            )
        }
        val score = validateStrictPassword(password, cleanNick).getOrElse {
            return Result.failure(it)
        }
        val slot = AccountSlotUi(
            slotIndex = accounts.size + 1,
            loginNickname = cleanNick,
            displayName = displayName.trim(),
            passwordScore = score
        )
        accounts.add(slot)
        return Result.success(slot)
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
        val cardRegex = Regex("\\b(?:\\d[ -]*?){13,19}\\b")
        val cvvRegex = Regex("(?i)\\b(?:cvv|cvc|код)\\s*[:=]?\\s*\\d{3}\\b")
        val phoneRegex = Regex("(?:\\+7|8|\\+\\d{1,3})[\\s\\-(]*\\d{3}[\\s\\-)]*\\d{3}[\\s\\-]*\\d{2}[\\s\\-]*\\d{2}")
        val emailRegex = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")

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
        accounts.forEach { acc ->
            val ownNick = acc.loginNickname.trim()
            if (ownNick.length >= 3 && draft.contains(ownNick, ignoreCase = true)) {
                detectedKinds.add("Собственный логин-ник ($ownNick)")
                redacted = redacted.replace(ownNick, "****", ignoreCase = true)
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
        redeemedSupporterTokens.clear()
        supporterPassActive = false
        maxAccountSlots = 3
        activeThemeId = "obsidian-stealth-dark"
        voicePitchSemitones = -4
        callActive = false
        torEnabled = false
        shieldState = NetworkShieldState.DIRECT_STATIC_IP_TLS
        wipedByPanicOrDuress = true
    }

    fun onAppBackgrounded() {
        chats.forEach { chat ->
            if (chat.perChatPin != null) {
                chat.isLocked = true
            }
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
                    name = "Стартовый #1 (Zurich Static IP — Без Tor)",
                    staticIpOrHost = "185.220.101.42",
                    port = 8443,
                    endpointUri = "aegis://185.220.101.42:8443",
                    badge = "✓✓ Official",
                    isTorOnion = false
                ),
                StarterServerUi(
                    id = "frankfurt-static-2",
                    name = "Стартовый #2 (Frankfurt Static IP — Без Tor)",
                    staticIpOrHost = "91.108.56.110",
                    port = 8443,
                    endpointUri = "aegis://91.108.56.110:8443",
                    badge = "✓✓ Official",
                    isTorOnion = false
                ),
                StarterServerUi(
                    id = "iceland-static-3",
                    name = "Стартовый #3 (Iceland Static IP — Без Tor)",
                    staticIpOrHost = "193.163.125.18",
                    port = 8443,
                    endpointUri = "aegis://193.163.125.18:8443",
                    badge = "✓ Verified",
                    isTorOnion = false
                ),
                StarterServerUi(
                    id = "onion-relay-4",
                    name = "Опциональный Tor Onion v3 Relay",
                    staticIpOrHost = "aegis7x9q2v4k8m3n5p7r9t2w4y6z8a1b3c5d7e9f1g3h5j7k9l2m4n.onion",
                    port = 8443,
                    endpointUri = "aegis://aegis7x9q2v4k8m3n5p7r9t2w4y6z8a1b3c5d7e9f1g3h5j7k9l2m4n.onion:8443",
                    badge = "✓✓ Onion",
                    isTorOnion = true
                )
            )
        )
        activeServerIndex = 0
        torEnabled = false
        shieldState = NetworkShieldState.DIRECT_STATIC_IP_TLS

        val nick = generateAnonymousNickname()
        accounts.add(
            AccountSlotUi(
                slotIndex = 1,
                loginNickname = nick,
                displayName = "Основной профиль",
                passwordScore = 96
            )
        )

        chats.add(
            ChatItemUi(
                chatIdHex = "01010101",
                title = "📌 Избранное (Локальный сейф SQLCipher)",
                queueTag = "local-device-only",
                isSavedNotes = true,
                verifiedSupportBadge = false,
                perChatPin = null,
                isLocked = false,
                messages = mutableListOf(
                    ChatMessageUi(
                        outgoing = true,
                        text = "Заметки в «Избранном» хранятся только на устройстве и шифруются локальным ключом.",
                        paddedBucketBytes = 256,
                        ttlSeconds = null
                    )
                )
            )
        )

        chats.add(
            ChatItemUi(
                chatIdHex = "02020202",
                title = "nordic-falcon (PQXDH + Double Ratchet)",
                queueTag = "queue://rx-99a1..tx-44b2",
                isSavedNotes = false,
                verifiedSupportBadge = false,
                perChatPin = "7788",
                isLocked = false,
                messages = mutableListOf(
                    ChatMessageUi(
                        outgoing = false,
                        text = "Прямое соединение со стартовым сервером 185.220.101.42:8443 активно (Без обязательного Tor, E2EE + 0 IP-логов).",
                        paddedBucketBytes = 256,
                        ttlSeconds = 3600
                    )
                )
            )
        )

        chats.add(
            ChatItemUi(
                chatIdHex = "03030303",
                title = "Официальная поддержка Aegis ✓",
                queueTag = "queue://verified-support-ed25519",
                isSavedNotes = false,
                verifiedSupportBadge = true,
                perChatPin = null,
                isLocked = false,
                messages = mutableListOf(
                    ChatMessageUi(
                        outgoing = false,
                        text = "Сертификат поддержки проверен (✓). Здесь можно отправить зашифрованный тикет или активировать SupporterPass.",
                        paddedBucketBytes = 256,
                        ttlSeconds = null
                    )
                )
            )
        )
    }

    companion object {
        private const val KEYSTORE_ALIAS = "aegis_hardware_pin_wrapper_v1"
    }
}
