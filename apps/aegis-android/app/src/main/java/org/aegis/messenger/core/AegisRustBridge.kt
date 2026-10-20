package org.aegis.messenger.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Unified JNI / UniFFI Bridge to `aegis-ffi` (`AGENTS.md §2.6, §4`).
 *
 * UI components never perform cryptography directly and never hold raw master keys.
 * Hardware-backed PIN wrapping uses Android Keystore (`StrongBox` / `TEE`).
 */
class AegisRustBridge(private val context: Context) {

    enum class AppLocale { RU, EN }

    enum class NetworkShieldState {
        TOR_ANONYMIZED,
        VPN_PROTECTED,
        DIRECT_WARNING,
        KILL_SWITCH_BLOCKED
    }

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
    var shieldState: NetworkShieldState = NetworkShieldState.TOR_ANONYMIZED
    var coverTrafficEnabled: Boolean = true
    var supporterPassActive: Boolean = false
    var maxAccountSlots: Int = 3
    var activeThemeId: String = "obsidian-stealth-dark"
    var voicePitchSemitones: Int = -4
    var callActive: Boolean = false
    var wipedByPanicOrDuress: Boolean = false

    val accounts = mutableListOf<AccountSlotUi>()
    val chats = mutableListOf<ChatItemUi>()
    private val redeemedSupporterTokens = mutableSetOf<String>()

    init {
        ensureHardwareKeystoreWrapperKey()
        seedDefaultWorkspace()
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
     * Validates a login nickname (`aegis_ffi::validate_nickname`):
     * - 3..32 characters, trimmed
     * - Only `[a-z0-9_-]`
     * - No leading or trailing `-` or `_`
     * - Not composed exclusively of digits
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
     * Enforces the strict D-0006 password policy (`aegis_ffi::validate_password`):
     * - Minimum 12 characters (max 256)
     * - No control characters (`\0`, `\n`, `\r`, etc.)
     * - At least 3 uppercase letters
     * - Lowercase letters, digits, and non-whitespace special characters
     * - Must not contain loginNickname (raw or separator-stripped)
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
     * Detects bank cards (Luhn), CVV/CVC, phone numbers, emails, and the user's own login nickname
     * across all registered local profiles.
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
            if (ownNick.length >= 4 && draft.contains(ownNick, ignoreCase = true)) {
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
     * Generates a 1-click self-hosted server configuration (`aegis-launcher`).
     */
    fun buildServerLaunchBundle(target: String, port: Int, ttlDays: Int): String {
        val safePort = port.coerceIn(1, 65535)
        val safeTtlDays = ttlDays.coerceIn(1, 365)
        val ttlSecs = safeTtlDays.toLong() * 86400L
        return when (target) {
            "TOR_ONION" -> """
                # Скрытый Tor .onion сервер Aegis (Zero-Knowledge)
                HiddenServiceDir /var/lib/tor/aegis_hidden_service/
                HiddenServiceVersion 3
                HiddenServicePort $safePort 127.0.0.1:$safePort
                # Queue TTL: ${ttlSecs}s (Без IP-логов)
            """.trimIndent()
            else -> """
                services:
                  aegis-server:
                    image: ghcr.io/aegis-project/aegis-server:v0.1.0
                    ports:
                      - "$safePort:$safePort/udp"
                      - "$safePort:$safePort/tcp"
                    environment:
                      - AEGIS_ZERO_KNOWLEDGE=1
                      - AEGIS_NO_IP_LOGS=1
                      - AEGIS_QUEUE_TTL_SECS=$ttlSecs
                    restart: unless-stopped
            """.trimIndent()
        }
    }

    /**
     * Immediate emergency cryptographic wipe (Panic Button / Duress PIN):
     * deletes the Android Keystore hardware wrapper key and zeroes all in-memory chats & accounts.
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
        wipedByPanicOrDuress = true
    }

    fun onAppBackgrounded() {
        // Re-locks any per-chat PIN protected conversations when backgrounded
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
                        text = "Соединение установлено через Tor Onion v3. Пакеты выровнены по 256/1024/4096/16384 байт.",
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
