package org.aegis.messenger.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.aegis.messenger.core.AegisRustBridge

/**
 * Clean, messenger-first Android UI for Aegis.
 *
 * The visual language is intentionally close to familiar private messengers:
 * a quiet dark palette, clear chat rows, simple bubbles, and a single composer.
 * Security behavior is unchanged: LeakGuard, key-change blocking, PIN-locked
 * chats, Kill Switch, calculator disguise and panic wipe all remain wired to
 * [AegisRustBridge].
 */
@Composable
fun AegisComposeApp(
    bridge: AegisRustBridge,
    onToggleCalculatorLauncherIcon: (Boolean) -> Unit,
    onPanicWipeTriggered: () -> Unit
) {
    var uiTick by remember { mutableStateOf(0) }
    var activeScreen by remember { mutableStateOf("STEP_1_ACCOUNT") }
    var activeChatIndex by remember { mutableStateOf(1) }
    var draftText by remember { mutableStateOf("") }
    var statusBanner by remember { mutableStateOf("") }
    var pendingLeakWarning by remember { mutableStateOf<AegisRustBridge.LeakWarningUi?>(null) }
    var calculatorDisplay by remember { mutableStateOf("") }
    var chatPinInput by remember { mutableStateOf("") }

    // Account onboarding state. The password is deliberately never pre-filled.
    var generatedNickname by remember { mutableStateOf(bridge.generateAnonymousNickname()) }
    var displayNameInput by remember { mutableStateOf("Призрак Сети") }
    var onboardingPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }

    // Server selection state.
    var customStaticIpInput by remember { mutableStateOf("185.220.101.42:8443") }
    var blindRelayInput by remember { mutableStateOf(bridge.blindRelayEndpoint) }
    var socks5ProxyInput by remember { mutableStateOf(bridge.socks5ProxyEndpoint) }
    var launcherTarget by remember { mutableStateOf("VPS_DOCKER") }

    // Chat list and dialogs.
    var showNewChatDialog by remember { mutableStateOf(false) }
    var newChatPeerName by remember { mutableStateOf("") }
    var newChatChannelCode by remember { mutableStateOf("") }
    var searchQuery by remember { mutableStateOf("") }
    var showMenu by remember { mutableStateOf(false) }
    var showChatMenu by remember { mutableStateOf(false) }
    var showSafetyDialog by remember { mutableStateOf(false) }
    var showInviteDialog by remember { mutableStateOf(false) }
    var inviteDialogValue by remember { mutableStateOf("") }
    var showPanicConfirm by remember { mutableStateOf(false) }

    val currentTick = uiTick
    val isRu = bridge.locale == AegisRustBridge.AppLocale.RU
    val incognitoKeyboardOptions = KeyboardOptions(autoCorrect = false)

    fun applyStatus(message: String) {
        statusBanner = message
        uiTick++
    }

    fun go(screen: String) {
        activeScreen = screen
        uiTick++
    }

    fun toggleLanguage() {
        bridge.locale = if (isRu) AegisRustBridge.AppLocale.EN else AegisRustBridge.AppLocale.RU
        applyStatus(
            if (bridge.locale == AegisRustBridge.AppLocale.RU) {
                "Язык интерфейса: Русский."
            } else {
                "Interface language: English."
            }
        )
    }

    fun enterCalculator() {
        bridge.onAppBackgrounded()
        bridge.setCalculatorDisguiseEnabled(true)
        pendingLeakWarning = null
        draftText = ""
        chatPinInput = ""
        onboardingPassword = ""
        onToggleCalculatorLauncherIcon(true)
        activeScreen = "CALCULATOR_DISGUISE"
        uiTick++
    }

    fun runPanicWipe() {
        draftText = ""
        pendingLeakWarning = null
        calculatorDisplay = ""
        chatPinInput = ""
        onboardingPassword = ""
        showPanicConfirm = false
        onPanicWipeTriggered()
        uiTick++
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = AegisColors.accent,
            onPrimary = AegisColors.onAccent,
            secondary = AegisColors.info,
            background = AegisColors.bg,
            surface = AegisColors.panel,
            surfaceVariant = AegisColors.panel2,
            onBackground = AegisColors.text,
            onSurface = AegisColors.text,
            onSurfaceVariant = AegisColors.muted,
            error = AegisColors.danger
        )
    ) {
        Surface(modifier = Modifier.fillMaxSize(), color = AegisColors.bg) {
            // Reading the tick here is intentional: the bridge is a mutable
            // view-model, so a tick forces Compose to observe its latest state.
            if (currentTick >= 0 && bridge.wipedByPanicOrDuress) {
                WipedScreen()
                return@Surface
            }

            if (activeScreen == "CALCULATOR_DISGUISE" || bridge.calculatorDisguiseActive) {
                CalculatorScreen(
                    display = calculatorDisplay,
                    onDisplayChange = { calculatorDisplay = it },
                    onEvaluate = {
                        when (val result = bridge.evaluateCalculatorOrPin(calculatorDisplay)) {
                            "UNLOCKED" -> {
                                calculatorDisplay = ""
                                onToggleCalculatorLauncherIcon(false)
                                activeScreen = "STEP_3_CHAT_LIST"
                                applyStatus("PIN принят. Открыт Aegis.")
                            }
                            "DURESS" -> {
                                calculatorDisplay = ""
                                onToggleCalculatorLauncherIcon(false)
                                activeScreen = "STEP_3_CHAT_LIST"
                                activeChatIndex = 0
                                applyStatus("Открыт профиль по умолчанию.")
                            }
                            "WIPED" -> {
                                calculatorDisplay = ""
                                runPanicWipe()
                            }
                            else -> calculatorDisplay = result
                        }
                    },
                    onClear = { calculatorDisplay = "" }
                )
                return@Surface
            }

            when (activeScreen) {
                "STEP_1_ACCOUNT" -> {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(horizontal = 20.dp, vertical = 24.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            BrandMark(size = 44.dp)
                            Spacer(Modifier.width(12.dp))
                            Column {
                                Text("Aegis", color = AegisColors.text, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                                Text(
                                    "Приватный мессенджер",
                                    color = AegisColors.muted,
                                    fontSize = 12.sp
                                )
                            }
                        }
                        Spacer(Modifier.height(24.dp))
                        Text(
                            "Общение без номера телефона и почты",
                            color = AegisColors.text,
                            fontSize = 28.sp,
                            fontWeight = FontWeight.Bold,
                            lineHeight = 34.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Ключи и переписка остаются на устройстве. Сервер не видит, кто с кем говорит.",
                            color = AegisColors.muted,
                            fontSize = 14.sp,
                            lineHeight = 20.sp
                        )
                        Spacer(Modifier.height(18.dp))
                        StatusBanner(statusBanner)
                        Spacer(Modifier.height(12.dp))

                        AuthCard {
                            Text("Создание профиля", color = AegisColors.text, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                            Text("Шаг 1 из 3", color = AegisColors.accent, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            Spacer(Modifier.height(14.dp))

                            OutlinedTextField(
                                value = generatedNickname,
                                onValueChange = { generatedNickname = it },
                                label = { Text("Логин-ник") },
                                singleLine = true,
                                keyboardOptions = incognitoKeyboardOptions,
                                modifier = Modifier.fillMaxWidth()
                            )
                            TextButton(
                                onClick = { generatedNickname = bridge.generateAnonymousNickname() },
                                contentPadding = PaddingValues(horizontal = 0.dp)
                            ) {
                                Text("Сгенерировать случайный ник", color = AegisColors.info, fontSize = 12.sp)
                            }

                            OutlinedTextField(
                                value = displayNameInput,
                                onValueChange = { displayNameInput = it },
                                label = { Text("Отображаемое имя") },
                                singleLine = true,
                                keyboardOptions = incognitoKeyboardOptions,
                                modifier = Modifier.fillMaxWidth()
                            )
                            Spacer(Modifier.height(8.dp))

                            OutlinedTextField(
                                value = onboardingPassword,
                                onValueChange = { onboardingPassword = it },
                                label = { Text("Пароль") },
                                singleLine = true,
                                visualTransformation = if (showPassword) {
                                    VisualTransformation.None
                                } else {
                                    PasswordVisualTransformation()
                                },
                                keyboardOptions = incognitoKeyboardOptions,
                                trailingIcon = {
                                    TextButton(onClick = { showPassword = !showPassword }) {
                                        Text(if (showPassword) "Скрыть" else "Показать", fontSize = 11.sp)
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            )
                            Text(
                                "Минимум 12 символов, 3 заглавные, цифра и спецсимвол.",
                                color = AegisColors.muted,
                                fontSize = 11.sp
                            )
                            Spacer(Modifier.height(10.dp))

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("Только на этом устройстве", color = AegisColors.text, fontSize = 13.sp)
                                    Text(
                                        "Seed-only режим без серверного аккаунта",
                                        color = AegisColors.muted,
                                        fontSize = 11.sp
                                    )
                                }
                                Switch(
                                    checked = bridge.seedOnlyMode,
                                    onCheckedChange = {
                                        bridge.seedOnlyMode = it
                                        applyStatus(
                                            if (it) "Включён seed-only режим." else "Включён OPAQUE-режим."
                                        )
                                    }
                                )
                            }

                            Spacer(Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                TextButton(
                                    onClick = {
                                        bridge.generateRecoveryPhrase24Words()
                                        applyStatus("Фраза восстановления создана. Сохраните её офлайн.")
                                    }
                                ) {
                                    Text("24 слова", color = AegisColors.info, fontSize = 12.sp)
                                }
                                TextButton(
                                    onClick = {
                                        val hex = bridge.exportEncryptedVaultBackupHex()
                                        applyStatus("Зашифрованный экспорт готов: ${hex.length / 2} байт.")
                                    }
                                ) {
                                    Text("Экспорт", color = AegisColors.info, fontSize = 12.sp)
                                }
                            }

                            bridge.recoveryPhrasePreview?.let { phrase ->
                                Surface(
                                    color = AegisColors.panel2,
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
                                ) {
                                    Column(Modifier.padding(12.dp)) {
                                        Text(
                                            "Фраза восстановления",
                                            color = AegisColors.warning,
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Spacer(Modifier.height(4.dp))
                                        Text(phrase, color = AegisColors.text, fontSize = 12.sp, lineHeight = 18.sp)
                                    }
                                }
                            }

                            Spacer(Modifier.height(14.dp))
                            Button(
                                onClick = {
                                    bridge.registerAccount(
                                        generatedNickname.trim(),
                                        displayNameInput.ifBlank { "Основной профиль" },
                                        onboardingPassword
                                    ).onSuccess { slot ->
                                        onboardingPassword = ""
                                        activeScreen = "STEP_2_SERVERS"
                                        applyStatus("Профиль ${slot.displayName} создан. Выберите сервер.")
                                    }.onFailure { error ->
                                        applyStatus("Проверьте данные: ${error.message}")
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Text("Создать профиль", fontWeight = FontWeight.Bold)
                            }
                            TextButton(
                                onClick = { go("STEP_2_SERVERS") },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("Продолжить к выбору сервера", color = AegisColors.muted, fontSize = 12.sp)
                            }
                        }

                        Spacer(Modifier.height(18.dp))
                        SecurityPoint("Сквозное шифрование", "ChaCha20-Poly1305 и Double Ratchet")
                        SecurityPoint("Без телеметрии", "Ни аналитики, ни рекламных SDK")
                        SecurityPoint("Локальное хранение", "Ключи не покидают устройство")
                        Spacer(Modifier.height(10.dp))
                        Text(
                            "AGPL-3.0 · открытый код",
                            color = AegisColors.muted,
                            fontSize = 11.sp
                        )
                    }
                }

                "STEP_2_SERVERS" -> {
                    Column(Modifier.fillMaxSize()) {
                        AppTopBar(
                            title = "Серверы",
                            subtitle = "Выберите узел связи",
                            onMenu = { showMenu = true }
                        )
                        StatusBanner(statusBanner)
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .verticalScroll(rememberScrollState())
                                .padding(horizontal = 14.dp, vertical = 8.dp)
                        ) {
                            Surface(
                                color = AegisColors.panel2,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .size(10.dp)
                                            .background(AegisColors.accent, CircleShape)
                                    )
                                    Spacer(Modifier.width(10.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            shieldLabel(bridge.shieldState),
                                            color = AegisColors.text,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.SemiBold
                                        )
                                        Text(
                                            "Текущий маршрут защиты",
                                            color = AegisColors.muted,
                                            fontSize = 11.sp
                                        )
                                    }
                                }
                            }

                            SectionLabel("Доступные серверы")
                            bridge.starterServers.forEachIndexed { index, server ->
                                val selected = index == bridge.activeServerIndex
                                Surface(
                                    color = if (selected) AegisColors.panel2 else AegisColors.panel,
                                    shape = RoundedCornerShape(14.dp),
                                    border = BorderStroke(
                                        1.dp,
                                        if (selected) AegisColors.accent else AegisColors.line
                                    ),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(bottom = 8.dp)
                                        .clickable {
                                            bridge.selectStarterServer(index).onSuccess {
                                                applyStatus("Подключён ${it.staticIpOrHost}:${it.port}.")
                                            }
                                        }
                                ) {
                                    Row(
                                        modifier = Modifier.padding(14.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                server.name,
                                                color = AegisColors.text,
                                                fontSize = 14.sp,
                                                fontWeight = FontWeight.SemiBold
                                            )
                                            Text(
                                                "${server.staticIpOrHost}:${server.port} · ${server.badge}",
                                                color = AegisColors.muted,
                                                fontSize = 11.sp
                                            )
                                        }
                                        Text(
                                            if (selected) "✓" else "→",
                                            color = if (selected) AegisColors.accent else AegisColors.muted,
                                            fontSize = 18.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                }
                            }

                            SectionLabel("Свой сервер")
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    OutlinedTextField(
                                        value = customStaticIpInput,
                                        onValueChange = { customStaticIpInput = it },
                                        label = { Text("IP или домен:порт") },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Button(
                                        onClick = {
                                            bridge.connectCustomStaticIp(customStaticIpInput)
                                                .onSuccess { server ->
                                                    applyStatus("Подключён ${server.staticIpOrHost}:${server.port}.")
                                                }
                                                .onFailure { error ->
                                                    applyStatus("Ошибка адреса: ${error.message}")
                                                }
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp)
                                    ) {
                                        Text("Подключить")
                                    }
                                }
                            }

                            SectionLabel("Приватный маршрут")
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    OutlinedTextField(
                                        value = blindRelayInput,
                                        onValueChange = {
                                            blindRelayInput = it
                                            bridge.blindRelayEndpoint = it.trim()
                                        },
                                        label = { Text("Слепой релей, host:port") },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    OutlinedTextField(
                                        value = socks5ProxyInput,
                                        onValueChange = {
                                            socks5ProxyInput = it
                                            bridge.socks5ProxyEndpoint = it.trim()
                                            if (it.isNotBlank()) {
                                                bridge.shieldState =
                                                    AegisRustBridge.NetworkShieldState.TOR_ANONYMIZED
                                            }
                                        },
                                        label = { Text("SOCKS5h / Tor, host:port") },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Row(
                                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                                    ) {
                                        SmallChoice("Tor") {
                                            bridge.shieldState =
                                                AegisRustBridge.NetworkShieldState.TOR_ANONYMIZED
                                            applyStatus("Маршрут Tor включён.")
                                        }
                                        SmallChoice("VPN") {
                                            bridge.shieldState =
                                                AegisRustBridge.NetworkShieldState.VPN_PROTECTED
                                            applyStatus("Маршрут VPN включён.")
                                        }
                                        SmallChoice("Напрямую") {
                                            bridge.shieldState =
                                                AegisRustBridge.NetworkShieldState.DIRECT_STATIC_IP_TLS
                                            applyStatus("Прямое TLS-подключение.")
                                        }
                                        SmallChoice("Kill Switch", danger = true) {
                                            bridge.shieldState =
                                                AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                            applyStatus("Kill Switch: сеть заблокирована.")
                                        }
                                    }
                                }
                            }

                            SectionLabel("Свой сервер за минуту")
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        SmallChoice("VPS") { launcherTarget = "VPS_DOCKER" }
                                        SmallChoice("Tor") { launcherTarget = "TOR_ONION" }
                                    }
                                    Spacer(Modifier.height(8.dp))
                                    Text(
                                        bridge.buildServerLaunchBundle(launcherTarget, 8443, 30),
                                        color = AegisColors.muted,
                                        fontSize = 10.sp,
                                        lineHeight = 14.sp
                                    )
                                }
                            }

                            Spacer(Modifier.height(14.dp))
                            Button(
                                onClick = { go("STEP_3_CHAT_LIST") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Text("Перейти к чатам", fontWeight = FontWeight.Bold)
                            }
                            Spacer(Modifier.height(16.dp))
                        }
                        AppBottomBar(
                            active = "servers",
                            onChats = { go("STEP_3_CHAT_LIST") },
                            onServers = {},
                            onProfile = { go("PROFILE") }
                        )
                    }
                }

                "PROFILE" -> {
                    Column(Modifier.fillMaxSize()) {
                        AppTopBar(
                            title = "Профиль",
                            subtitle = "Локальный аккаунт",
                            onMenu = { showMenu = true }
                        )
                        StatusBanner(statusBanner)
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .verticalScroll(rememberScrollState())
                                .padding(horizontal = 14.dp, vertical = 8.dp)
                        ) {
                            val account = bridge.accounts.firstOrNull()
                            if (account != null) {
                                Surface(
                                    color = AegisColors.panel,
                                    shape = RoundedCornerShape(16.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Row(
                                        modifier = Modifier.padding(16.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Avatar(account.displayName, size = 58.dp)
                                        Spacer(Modifier.width(12.dp))
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                account.displayName,
                                                color = AegisColors.text,
                                                fontSize = 17.sp,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(
                                                "@${account.loginNickname}",
                                                color = AegisColors.muted,
                                                fontSize = 12.sp
                                            )
                                            Text(
                                                "Пароль: ${account.passwordScore}%",
                                                color = AegisColors.accent,
                                                fontSize = 11.sp
                                            )
                                        }
                                    }
                                }
                            } else {
                                Text("Профиль ещё не создан.", color = AegisColors.muted)
                            }

                            SectionLabel("Аккаунты")
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(12.dp)) {
                                    bridge.accounts.forEach { slot ->
                                        Row(
                                            modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Box(
                                                modifier = Modifier
                                                    .size(8.dp)
                                                    .background(AegisColors.accent, CircleShape)
                                            )
                                            Spacer(Modifier.width(10.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(slot.displayName, color = AegisColors.text, fontSize = 13.sp)
                                                Text("@${slot.loginNickname}", color = AegisColors.muted, fontSize = 11.sp)
                                            }
                                            Text("${slot.passwordScore}%", color = AegisColors.muted, fontSize = 11.sp)
                                        }
                                    }
                                    Spacer(Modifier.height(6.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        SmallChoice("Добавить профиль") { go("STEP_1_ACCOUNT") }
                                        SmallChoice("SupporterPass") {
                                            if (bridge.activateSupporterPass("BLIND_TOKEN_ED25519_VERIFIED_2026")) {
                                                applyStatus("SupporterPass активирован: до 5 профилей.")
                                            } else {
                                                applyStatus("SupporterPass уже активирован или токен неверен.")
                                            }
                                        }
                                    }
                                }
                            }

                            SectionLabel("Приватность")
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text("Seed-only", color = AegisColors.text, fontSize = 13.sp)
                                            Text("Без серверного аккаунта", color = AegisColors.muted, fontSize = 11.sp)
                                        }
                                        Switch(
                                            checked = bridge.seedOnlyMode,
                                            onCheckedChange = {
                                                bridge.seedOnlyMode = it
                                                applyStatus(if (it) "Seed-only включён." else "OPAQUE включён.")
                                            }
                                        )
                                    }
                                    Spacer(Modifier.height(8.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        SmallChoice("24 слова") {
                                            bridge.generateRecoveryPhrase24Words()
                                            applyStatus("Фраза восстановления создана.")
                                        }
                                        SmallChoice("Экспорт") {
                                            val hex = bridge.exportEncryptedVaultBackupHex()
                                            applyStatus("Экспорт: ${hex.length / 2} байт.")
                                        }
                                        SmallChoice("Приглашение") {
                                            inviteDialogValue = bridge.generateInviteV2Uri()
                                            showInviteDialog = true
                                        }
                                    }
                                    bridge.recoveryPhrasePreview?.let { phrase ->
                                        Spacer(Modifier.height(10.dp))
                                        Text("Фраза восстановления", color = AegisColors.warning, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                        Text(phrase, color = AegisColors.text, fontSize = 11.sp, lineHeight = 17.sp)
                                    }
                                    bridge.lastExportedBackupHex?.let { hex ->
                                        Spacer(Modifier.height(8.dp))
                                        Text(
                                            "Экспорт: ${hex.length / 2} байт · ${hex.take(32)}…",
                                            color = AegisColors.muted,
                                            fontSize = 10.sp
                                        )
                                    }
                                }
                            }

                            SectionLabel("Сеть")
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    ProfileRow("Сервер", "${bridge.activeServer.staticIpOrHost}:${bridge.activeServer.port}")
                                    ProfileRow("Маршрут", shieldLabel(bridge.shieldState))
                                    ProfileRow(
                                        "Релей",
                                        bridge.blindRelayEndpoint.ifBlank { "не задан" }
                                    )
                                    ProfileRow(
                                        "SOCKS5h",
                                        bridge.socks5ProxyEndpoint.ifBlank { "не задан" }
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    TextButton(onClick = { go("STEP_2_SERVERS") }, contentPadding = PaddingValues(0.dp)) {
                                        Text("Изменить маршрут", color = AegisColors.info, fontSize = 12.sp)
                                    }
                                }
                            }

                            SectionLabel("Приложение")
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        SmallChoice(if (isRu) "English" else "Русский") { toggleLanguage() }
                                        SmallChoice("Калькулятор") { enterCalculator() }
                                    }
                                    Spacer(Modifier.height(10.dp))
                                    Button(
                                        onClick = { showPanicConfirm = true },
                                        colors = ButtonDefaults.buttonColors(containerColor = AegisColors.danger),
                                        shape = RoundedCornerShape(12.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text("Стереть все данные", fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                            Spacer(Modifier.height(16.dp))
                        }
                        AppBottomBar(
                            active = "profile",
                            onChats = { go("STEP_3_CHAT_LIST") },
                            onServers = { go("STEP_2_SERVERS") },
                            onProfile = {}
                        )
                    }
                }

                "STEP_3_CONVERSATION" -> {
                    val safeIndex = activeChatIndex.coerceIn(0, (bridge.chats.size - 1).coerceAtLeast(0))
                    val currentChat = bridge.chats.getOrNull(safeIndex)
                    if (currentChat == null) {
                        Column(Modifier.fillMaxSize().padding(20.dp)) {
                            Text("Чат не найден", color = AegisColors.text, fontSize = 18.sp)
                            TextButton(onClick = { go("STEP_3_CHAT_LIST") }) {
                                Text("Вернуться к чатам", color = AegisColors.info)
                            }
                        }
                    } else {
                        Column(Modifier.fillMaxSize().imePadding()) {
                            AppTopBar(
                                title = currentChat.title,
                                subtitle = "${bridge.activeServer.staticIpOrHost} · сквозное шифрование",
                                onBack = {
                                    pendingLeakWarning = null
                                    go("STEP_3_CHAT_LIST")
                                },
                                onMenu = { showChatMenu = true },
                                trailing = {
                                    Text(
                                        "⟳",
                                        color = AegisColors.info,
                                        fontSize = 22.sp,
                                        modifier = Modifier
                                            .clickable {
                                                if (!currentChat.isSavedNotes &&
                                                    bridge.shieldState ==
                                                    AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                                ) {
                                                    applyStatus("Синхронизация заблокирована Kill Switch.")
                                                } else {
                                                    bridge.pollCapsulesOverNetworkAsync(
                                                        safeIndex,
                                                        currentChat.queueTag
                                                    ) { _, syncStatus ->
                                                        statusBanner = syncStatus
                                                        uiTick++
                                                    }
                                                }
                                            }
                                            .padding(8.dp)
                                    )
                                }
                            )
                            StatusBanner(statusBanner)

                            currentChat.keyChangeWarning?.let { warning ->
                                Surface(
                                    color = AegisColors.warning.copy(alpha = 0.12f),
                                    shape = RoundedCornerShape(12.dp),
                                    border = BorderStroke(1.dp, AegisColors.warning.copy(alpha = 0.45f)),
                                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
                                ) {
                                    Column(Modifier.padding(12.dp)) {
                                        Text("Ключ собеседника изменился", color = AegisColors.warning, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                                        Text(warning, color = AegisColors.text, fontSize = 11.sp, lineHeight = 16.sp)
                                        Spacer(Modifier.height(6.dp))
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            TextButton(onClick = {
                                                bridge.acknowledgeKeyChange(safeIndex)
                                                applyStatus("Новый ключ подтверждён после сверки Safety Number.")
                                            }) {
                                                Text("Подтвердить", color = AegisColors.warning, fontSize = 12.sp)
                                            }
                                            TextButton(onClick = { showSafetyDialog = true }) {
                                                Text("Safety Number", color = AegisColors.info, fontSize = 12.sp)
                                            }
                                        }
                                    }
                                }
                            }

                            pendingLeakWarning?.let { warning ->
                                Surface(
                                    color = AegisColors.danger.copy(alpha = 0.12f),
                                    shape = RoundedCornerShape(12.dp),
                                    border = BorderStroke(1.dp, AegisColors.danger.copy(alpha = 0.45f)),
                                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
                                ) {
                                    Column(Modifier.padding(12.dp)) {
                                        Text("LeakGuard: чувствительные данные", color = AegisColors.danger, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                                        Text("Найдено: ${warning.kind}", color = AegisColors.text, fontSize = 11.sp)
                                        Text("Безопасный вариант: ${warning.maskedPreview}", color = AegisColors.muted, fontSize = 11.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
                                        Spacer(Modifier.height(6.dp))
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            TextButton(onClick = {
                                                if (!currentChat.isSavedNotes && currentChat.keyChangeWarning != null) {
                                                    applyStatus("Сначала подтвердите смену ключа собеседника.")
                                                } else if (!currentChat.isSavedNotes &&
                                                    bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                                ) {
                                                    applyStatus("Отправка заблокирована Kill Switch.")
                                                } else {
                                                    val masked = warning.maskedPreview
                                                    currentChat.messages.add(
                                                        AegisRustBridge.ChatMessageUi(
                                                            outgoing = true,
                                                            text = masked,
                                                            paddedBucketBytes = 256,
                                                            ttlSeconds = currentChat.defaultTtlSeconds
                                                        )
                                                    )
                                                    pendingLeakWarning = null
                                                    draftText = ""
                                                    uiTick++
                                                    if (!currentChat.isSavedNotes) {
                                                        bridge.sendCapsuleOverNetworkAsync(
                                                            currentChat.queueTag,
                                                            masked
                                                        ) { _, msgStatus ->
                                                            statusBanner = msgStatus
                                                            uiTick++
                                                        }
                                                    }
                                                }
                                            }) {
                                                Text("Замаскировать", color = AegisColors.accent, fontSize = 12.sp)
                                            }
                                            TextButton(onClick = {
                                                if (!currentChat.isSavedNotes && currentChat.keyChangeWarning != null) {
                                                    applyStatus("Сначала подтвердите смену ключа собеседника.")
                                                } else if (!currentChat.isSavedNotes &&
                                                    bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                                ) {
                                                    applyStatus("Отправка заблокирована Kill Switch.")
                                                } else {
                                                    val raw = warning.rawFragment
                                                    currentChat.messages.add(
                                                        AegisRustBridge.ChatMessageUi(
                                                            outgoing = true,
                                                            text = raw,
                                                            paddedBucketBytes = 256,
                                                            ttlSeconds = currentChat.defaultTtlSeconds
                                                        )
                                                    )
                                                    pendingLeakWarning = null
                                                    draftText = ""
                                                    uiTick++
                                                    if (!currentChat.isSavedNotes) {
                                                        bridge.sendCapsuleOverNetworkAsync(
                                                            currentChat.queueTag,
                                                            raw
                                                        ) { _, msgStatus ->
                                                            statusBanner = msgStatus
                                                            uiTick++
                                                        }
                                                    }
                                                }
                                            }) {
                                                Text("Отправить как есть", color = AegisColors.danger, fontSize = 12.sp)
                                            }
                                            TextButton(onClick = { pendingLeakWarning = null }) {
                                                Text("Отмена", color = AegisColors.muted, fontSize = 12.sp)
                                            }
                                        }
                                    }
                                }
                            }

                            if (currentChat.isLocked) {
                                Column(
                                    modifier = Modifier.fillMaxSize().padding(24.dp),
                                    verticalArrangement = Arrangement.Center,
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Text("🔒", fontSize = 42.sp)
                                    Spacer(Modifier.height(8.dp))
                                    Text("Чат заблокирован", color = AegisColors.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        "Введите PIN, чтобы открыть переписку.",
                                        color = AegisColors.muted,
                                        fontSize = 13.sp
                                    )
                                    Spacer(Modifier.height(16.dp))
                                    OutlinedTextField(
                                        value = chatPinInput,
                                        onValueChange = { chatPinInput = it },
                                        label = { Text("PIN чата") },
                                        singleLine = true,
                                        visualTransformation = PasswordVisualTransformation(),
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Button(
                                        onClick = {
                                            if (bridge.unlockChatWithPin(safeIndex, chatPinInput)) {
                                                chatPinInput = ""
                                                applyStatus("Чат разблокирован.")
                                            } else {
                                                chatPinInput = ""
                                                if (bridge.wipedByPanicOrDuress) {
                                                    runPanicWipe()
                                                } else {
                                                    applyStatus("Неверный PIN. Осталось попыток: ${bridge.remainingPinAttempts}.")
                                                }
                                            }
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp)
                                    ) {
                                        Text("Открыть чат")
                                    }
                                }
                            } else {
                                LazyColumn(
                                    modifier = Modifier.weight(1f),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    items(currentChat.messages) { message ->
                                        MessageBubble(message)
                                    }
                                }
                                ComposerBar(
                                    draft = draftText,
                                    onDraftChange = { draftText = it },
                                    onSend = {
                                        if (draftText.isBlank()) {
                                            applyStatus("Введите сообщение.")
                                        } else if (!currentChat.isSavedNotes && currentChat.keyChangeWarning != null) {
                                            applyStatus("Сначала подтвердите смену ключа собеседника.")
                                        } else if (!currentChat.isSavedNotes &&
                                            bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                        ) {
                                            applyStatus("Отправка заблокирована Kill Switch.")
                                        } else {
                                            val leak = bridge.scanMessageForLeaks(draftText)
                                            if (leak != null) {
                                                pendingLeakWarning = leak
                                                uiTick++
                                            } else {
                                                val outgoing = draftText
                                                currentChat.messages.add(
                                                    AegisRustBridge.ChatMessageUi(
                                                        outgoing = true,
                                                        text = outgoing,
                                                        paddedBucketBytes = 256,
                                                        ttlSeconds = currentChat.defaultTtlSeconds
                                                    )
                                                )
                                                draftText = ""
                                                uiTick++
                                                if (!currentChat.isSavedNotes) {
                                                    bridge.sendCapsuleOverNetworkAsync(
                                                        currentChat.queueTag,
                                                        outgoing
                                                    ) { _, msgStatus ->
                                                        statusBanner = msgStatus
                                                        uiTick++
                                                    }
                                                }
                                            }
                                        }
                                    },
                                    onPhoto = {
                                        if (!currentChat.isSavedNotes && currentChat.keyChangeWarning != null) {
                                            applyStatus("Сначала подтвердите смену ключа собеседника.")
                                        } else if (!currentChat.isSavedNotes &&
                                            bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                        ) {
                                            applyStatus("Отправка заблокирована Kill Switch.")
                                        } else {
                                            val attachment = bridge.createExifStrippedAttachment(
                                                "view_once.jpg",
                                                4096,
                                                true
                                            )
                                            currentChat.messages.add(
                                                AegisRustBridge.ChatMessageUi(
                                                    outgoing = true,
                                                    text = "Фото без метаданных",
                                                    paddedBucketBytes = 4096,
                                                    ttlSeconds = 60,
                                                    attachment = attachment
                                                )
                                            )
                                            applyStatus("EXIF/GPS удалены. Фото отправлено как view-once.")
                                        }
                                    }
                                )
                            }
                        }

                        if (showChatMenu) {
                            AlertDialog(
                                onDismissRequest = { showChatMenu = false },
                                title = { Text("Чат") },
                                text = {
                                    Column {
                                        TextButton(onClick = {
                                            showChatMenu = false
                                            showSafetyDialog = true
                                        }) { Text("Safety Number") }
                                        TextButton(onClick = {
                                            showChatMenu = false
                                            bridge.rotateChatQueue(safeIndex)?.let { newQueue ->
                                                applyStatus("Очередь изменена: $newQueue")
                                            }
                                        }) { Text("Сменить очередь") }
                                        TextButton(onClick = {
                                            showChatMenu = false
                                            val nextTtl = when (currentChat.defaultTtlSeconds) {
                                                60 -> 3600
                                                3600 -> null
                                                else -> 60
                                            }
                                            bridge.setChatDisappearingTtl(safeIndex, nextTtl)
                                            applyStatus("Таймер: ${nextTtl ?: "∞"} с.")
                                        }) { Text("Таймер исчезновения") }
                                        TextButton(onClick = {
                                            showChatMenu = false
                                            bridge.simulateKeyChangeWarning(safeIndex)
                                            applyStatus("Смена ключа отмечена. Сверьте Safety Number.")
                                        }) { Text("Проверить смену ключа") }
                                    }
                                },
                                confirmButton = {},
                                dismissButton = {
                                    TextButton(onClick = { showChatMenu = false }) { Text("Закрыть") }
                                }
                            )
                        }

                        if (showSafetyDialog) {
                            AlertDialog(
                                onDismissRequest = { showSafetyDialog = false },
                                title = { Text("Safety Number") },
                                text = {
                                    Column {
                                        Text(
                                            "Сверьте эти 60 цифр с собеседником по другому каналу.",
                                            color = AegisColors.muted,
                                            fontSize = 12.sp
                                        )
                                        Spacer(Modifier.height(10.dp))
                                        Text(
                                            bridge.computeSafetyNumberForChat(safeIndex),
                                            color = AegisColors.text,
                                            fontSize = 13.sp,
                                            lineHeight = 20.sp
                                        )
                                        Spacer(Modifier.height(8.dp))
                                        Text(
                                            if (currentChat.peerVerified) "Ключ подтверждён" else "Ключ не подтверждён",
                                            color = if (currentChat.peerVerified) AegisColors.accent else AegisColors.warning,
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                    }
                                },
                                confirmButton = {
                                    TextButton(onClick = {
                                        bridge.verifyChatSafetyNumber(safeIndex)
                                        showSafetyDialog = false
                                        applyStatus("Safety Number подтверждён.")
                                    }) { Text("Сверить") }
                                },
                                dismissButton = {
                                    TextButton(onClick = { showSafetyDialog = false }) { Text("Закрыть") }
                                }
                            )
                        }
                    }
                }

                else -> {
                    Column(Modifier.fillMaxSize()) {
                        AppTopBar(
                            title = "Aegis",
                            subtitle = "Приватный мессенджер",
                            onMenu = { showMenu = true },
                            trailing = {
                                Text(
                                    "＋",
                                    color = AegisColors.accent,
                                    fontSize = 26.sp,
                                    modifier = Modifier
                                        .clickable { showNewChatDialog = true }
                                        .padding(horizontal = 8.dp, vertical = 2.dp)
                                )
                            }
                        )
                        StatusBanner(statusBanner)
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text("Поиск по чатам") },
                            singleLine = true,
                            keyboardOptions = incognitoKeyboardOptions,
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)
                        )

                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState())
                                .padding(horizontal = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            SmallChoice("Новый чат") { showNewChatDialog = true }
                            SmallChoice("Группа") {
                                bridge.createMlsGroupConduit("Новая группа", 5).onSuccess { index ->
                                    activeChatIndex = index
                                    activeScreen = "STEP_3_CONVERSATION"
                                    applyStatus("Группа MLS создана.")
                                }.onFailure { error ->
                                    applyStatus("Группа не создана: ${error.message}")
                                }
                            }
                            SmallChoice("Приглашение") {
                                inviteDialogValue = bridge.generateInviteV2Uri()
                                showInviteDialog = true
                            }
                        }

                        val filter = searchQuery.trim().lowercase()
                        fun chatMatches(chat: AegisRustBridge.ChatItemUi): Boolean {
                            if (filter.isEmpty()) return true
                            return chat.title.lowercase().contains(filter) ||
                                (!chat.isLocked && chat.messages.any { it.text.lowercase().contains(filter) })
                        }
                        val hasVisibleChats = bridge.chats.any(::chatMatches)

                        if (!hasVisibleChats) {
                            Column(
                                modifier = Modifier.weight(1f).fillMaxWidth(),
                                verticalArrangement = Arrangement.Center,
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text("⌕", fontSize = 40.sp, color = AegisColors.muted)
                                Text("Ничего не найдено", color = AegisColors.text, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                                Text("Измените запрос или создайте новый чат.", color = AegisColors.muted, fontSize = 12.sp)
                            }
                        } else {
                            LazyColumn(
                                modifier = Modifier.weight(1f),
                                contentPadding = PaddingValues(vertical = 4.dp)
                            ) {
                                itemsIndexed(bridge.chats) { actualIndex, chat ->
                                    if (!chatMatches(chat)) return@itemsIndexed
                                    val preview = if (chat.isLocked) {
                                        "Метаданные скрыты до ввода PIN"
                                    } else {
                                        chat.messages.lastOrNull()?.text ?: "Нет сообщений"
                                    }
                                    Surface(
                                        color = Color.Transparent,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                activeChatIndex = actualIndex
                                                pendingLeakWarning = null
                                                activeScreen = "STEP_3_CONVERSATION"
                                                uiTick++
                                            }
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Avatar(chat.title, size = 50.dp)
                                            Spacer(Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Row(verticalAlignment = Alignment.CenterVertically) {
                                                    Text(
                                                        chat.title,
                                                        color = AegisColors.text,
                                                        fontSize = 15.sp,
                                                        fontWeight = FontWeight.SemiBold,
                                                        maxLines = 1,
                                                        overflow = TextOverflow.Ellipsis,
                                                        modifier = Modifier.weight(1f)
                                                    )
                                                    if (chat.isLocked) {
                                                        Text("🔒", fontSize = 12.sp)
                                                    }
                                                }
                                                Text(
                                                    preview,
                                                    color = AegisColors.muted,
                                                    fontSize = 12.sp,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                                Text(
                                                    if (chat.isLocked) {
                                                        "Защищено PIN-кодом"
                                                    } else {
                                                        "${chat.messages.size} сообщений · ${chat.queueTag.take(28)}"
                                                    },
                                                    color = AegisColors.accent.copy(alpha = 0.85f),
                                                    fontSize = 10.sp,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                            }
                                        }
                                    }
                                    Box(
                                        Modifier
                                            .fillMaxWidth()
                                            .padding(start = 74.dp)
                                            .height(1.dp)
                                            .background(AegisColors.line.copy(alpha = 0.55f))
                                    )
                                }
                            }
                        }

                        AppBottomBar(
                            active = "chats",
                            onChats = {},
                            onServers = { go("STEP_2_SERVERS") },
                            onProfile = { go("PROFILE") }
                        )
                    }
                }
            }

            if (showMenu) {
                AlertDialog(
                    onDismissRequest = { showMenu = false },
                    title = { Text("Aegis") },
                    text = {
                        Column {
                            TextButton(onClick = {
                                showMenu = false
                                enterCalculator()
                            }) { Text("Калькулятор") }
                            TextButton(onClick = {
                                showMenu = false
                                toggleLanguage()
                            }) { Text(if (isRu) "Switch to English" else "Переключить на русский") }
                            TextButton(onClick = {
                                showMenu = false
                                go("PROFILE")
                            }) { Text("Профиль") }
                            TextButton(onClick = {
                                showMenu = false
                                go("STEP_2_SERVERS")
                            }) { Text("Серверы") }
                            TextButton(onClick = {
                                showMenu = false
                                showPanicConfirm = true
                            }) { Text("Экстренное стирание", color = AegisColors.danger) }
                        }
                    },
                    confirmButton = {},
                    dismissButton = {
                        TextButton(onClick = { showMenu = false }) { Text("Закрыть") }
                    }
                )
            }

            if (showNewChatDialog) {
                AlertDialog(
                    onDismissRequest = { showNewChatDialog = false },
                    title = { Text("Новый чат") },
                    text = {
                        Column {
                            Text(
                                "Договоритесь с собеседником об общем коде канала. Код не передаётся серверу.",
                                color = AegisColors.muted,
                                fontSize = 12.sp
                            )
                            Spacer(Modifier.height(10.dp))
                            OutlinedTextField(
                                value = newChatPeerName,
                                onValueChange = { newChatPeerName = it },
                                label = { Text("Имя собеседника") },
                                singleLine = true,
                                keyboardOptions = incognitoKeyboardOptions,
                                modifier = Modifier.fillMaxWidth()
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                value = newChatChannelCode,
                                onValueChange = { newChatChannelCode = it },
                                label = { Text("Код канала") },
                                singleLine = true,
                                keyboardOptions = incognitoKeyboardOptions,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            bridge.createCustomChannelChat(newChatPeerName, newChatChannelCode)
                                .onSuccess { index ->
                                    newChatPeerName = ""
                                    newChatChannelCode = ""
                                    showNewChatDialog = false
                                    activeChatIndex = index
                                    activeScreen = "STEP_3_CONVERSATION"
                                    applyStatus("Чат создан.")
                                }
                                .onFailure { error ->
                                    applyStatus("Чат не создан: ${error.message}")
                                }
                        }) { Text("Создать") }
                    },
                    dismissButton = {
                        TextButton(onClick = { showNewChatDialog = false }) { Text("Отмена") }
                    }
                )
            }

            if (showInviteDialog) {
                AlertDialog(
                    onDismissRequest = { showInviteDialog = false },
                    title = { Text("Приглашение") },
                    text = {
                        Column {
                            Text(
                                "Передайте ссылку лично. Она открывает доступ к этому чату.",
                                color = AegisColors.muted,
                                fontSize = 12.sp
                            )
                            Spacer(Modifier.height(10.dp))
                            Text(inviteDialogValue, color = AegisColors.text, fontSize = 11.sp, lineHeight = 16.sp)
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { showInviteDialog = false }) { Text("Готово") }
                    }
                )
            }

            if (showPanicConfirm) {
                AlertDialog(
                    onDismissRequest = { showPanicConfirm = false },
                    title = { Text("Стереть все данные?") },
                    text = {
                        Text(
                            "Ключи, профили и переписка будут уничтожены без возможности восстановления.",
                            color = AegisColors.muted,
                            fontSize = 13.sp
                        )
                    },
                    confirmButton = {
                        TextButton(onClick = { runPanicWipe() }) {
                            Text("Стереть", color = AegisColors.danger, fontWeight = FontWeight.Bold)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showPanicConfirm = false }) { Text("Отмена") }
                    }
                )
            }
        }
    }
}

private object AegisColors {
    val bg = Color(0xFF0B141A)
    val panel = Color(0xFF111B21)
    val panel2 = Color(0xFF202C33)
    val line = Color(0xFF2A3942)
    val text = Color(0xFFE9EDEF)
    val muted = Color(0xFF8696A0)
    val accent = Color(0xFF00A884)
    val onAccent = Color(0xFF042018)
    val info = Color(0xFF53BDEB)
    val danger = Color(0xFFF15C6D)
    val warning = Color(0xFFF0B429)
    val outgoing = Color(0xFF005C4B)
    val incoming = Color(0xFF202C33)
}

@Composable
private fun WipedScreen() {
    Column(
        modifier = Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("✓", fontSize = 44.sp, color = AegisColors.accent)
        Spacer(Modifier.height(12.dp))
        Text(
            "Данные удалены",
            color = AegisColors.text,
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(8.dp))
        Text(
            "Ключи, профили и локальная переписка уничтожены. Восстановление невозможно.",
            color = AegisColors.muted,
            fontSize = 13.sp,
            textAlign = TextAlign.Center,
            lineHeight = 19.sp
        )
    }
}

@Composable
private fun CalculatorScreen(
    display: String,
    onDisplayChange: (String) -> Unit,
    onEvaluate: () -> Unit,
    onClear: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xFF0E1114))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("Калькулятор", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Surface(
            color = Color(0xFF1A1F24),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                text = display.ifEmpty { "0" },
                color = Color.White,
                fontSize = 42.sp,
                fontWeight = FontWeight.Light,
                textAlign = TextAlign.End,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 24.dp)
            )
        }
        Spacer(Modifier.height(8.dp))
        val rows = listOf(
            listOf("7", "8", "9", "/"),
            listOf("4", "5", "6", "*"),
            listOf("1", "2", "3", "-"),
            listOf("C", "0", "+", "=")
        )
        rows.forEach { row ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                row.forEach { key ->
                    Button(
                        onClick = {
                            when (key) {
                                "C" -> onClear()
                                "=" -> onEvaluate()
                                else -> onDisplayChange(display + key)
                            }
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = when (key) {
                                "=" -> AegisColors.accent
                                "C" -> Color(0xFF3A2326)
                                in listOf("/", "*", "-", "+") -> Color(0xFF2A3138)
                                else -> Color(0xFF1E2429)
                            }
                        ),
                        shape = RoundedCornerShape(12.dp),
                        contentPadding = PaddingValues(0.dp),
                        modifier = Modifier.weight(1f).height(64.dp)
                    ) {
                        Text(
                            key,
                            color = if (key == "=") AegisColors.onAccent else Color.White,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun BrandMark(size: Dp) {
    Box(
        modifier = Modifier
            .size(size)
            .background(AegisColors.accent, RoundedCornerShape(size / 3f)),
        contentAlignment = Alignment.Center
    ) {
        Text(
            "A",
            color = AegisColors.onAccent,
            fontSize = (size.value * 0.48f).sp,
            fontWeight = FontWeight.Black
        )
    }
}

@Composable
private fun AuthCard(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        color = AegisColors.panel,
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(18.dp),
            content = content
        )
    }
}

@Composable
private fun SecurityPoint(title: String, subtitle: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text("✓", color = AegisColors.accent, fontSize = 14.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.width(10.dp))
        Column {
            Text(title, color = AegisColors.text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = AegisColors.muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun StatusBanner(text: String) {
    if (text.isBlank()) return
    Surface(
        color = AegisColors.panel2,
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
    ) {
        Text(
            text,
            color = AegisColors.text,
            fontSize = 11.sp,
            lineHeight = 15.sp,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
        )
    }
}

@Composable
private fun AppTopBar(
    title: String,
    subtitle: String,
    onBack: (() -> Unit)? = null,
    onMenu: () -> Unit,
    trailing: (@Composable () -> Unit)? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(AegisColors.panel)
            .padding(horizontal = 6.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (onBack != null) {
            Text(
                "‹",
                color = AegisColors.text,
                fontSize = 30.sp,
                modifier = Modifier.clickable { onBack() }.padding(horizontal = 10.dp)
            )
        } else {
            Spacer(Modifier.width(6.dp))
            Avatar(title, size = 38.dp)
            Spacer(Modifier.width(10.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                title,
                color = AegisColors.text,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                subtitle,
                color = AegisColors.muted,
                fontSize = 11.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (trailing != null) {
            trailing()
        }
        Text(
            "⋮",
            color = AegisColors.muted,
            fontSize = 22.sp,
            modifier = Modifier.clickable(onClick = onMenu).padding(horizontal = 10.dp, vertical = 4.dp)
        )
    }
}

@Composable
private fun AppBottomBar(
    active: String,
    onChats: () -> Unit,
    onServers: () -> Unit,
    onProfile: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(AegisColors.panel)
            .padding(vertical = 4.dp)
    ) {
        BottomItem("💬", "Чаты", active == "chats", onChats, Modifier.weight(1f))
        BottomItem("🌐", "Серверы", active == "servers", onServers, Modifier.weight(1f))
        BottomItem("👤", "Профиль", active == "profile", onProfile, Modifier.weight(1f))
    }
}

@Composable
private fun BottomItem(
    icon: String,
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier
) {
    Column(
        modifier = modifier.clickable(onClick = onClick).padding(vertical = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(icon, fontSize = 18.sp)
        Text(
            label,
            color = if (selected) AegisColors.accent else AegisColors.muted,
            fontSize = 10.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
        )
    }
}

@Composable
private fun Avatar(name: String, size: Dp) {
    val palette = listOf(
        Color(0xFF1F6F5F),
        Color(0xFF2A5275),
        Color(0xFF5B4A7A),
        Color(0xFF7A4A4A),
        Color(0xFF4A5F7A),
        Color(0xFF6B5A2A)
    )
    val color = palette[(name.hashCode() and Int.MAX_VALUE) % palette.size]
    Box(
        modifier = Modifier.size(size).background(color, CircleShape),
        contentAlignment = Alignment.Center
    ) {
        Text(
            name.trim().firstOrNull()?.uppercase() ?: "A",
            color = Color.White,
            fontSize = (size.value * 0.36f).sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        color = AegisColors.muted,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 14.dp, bottom = 6.dp)
    )
}

@Composable
private fun SmallChoice(label: String, danger: Boolean = false, onClick: () -> Unit) {
    Surface(
        color = if (danger) AegisColors.danger.copy(alpha = 0.12f) else AegisColors.panel2,
        shape = RoundedCornerShape(999.dp),
        border = BorderStroke(
            1.dp,
            if (danger) AegisColors.danger.copy(alpha = 0.45f) else AegisColors.line
        ),
        modifier = Modifier.clickable(onClick = onClick)
    ) {
        Text(
            label,
            color = if (danger) AegisColors.danger else AegisColors.text,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 11.dp, vertical = 7.dp)
        )
    }
}

@Composable
private fun ProfileRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = AegisColors.muted, fontSize = 12.sp)
        Text(
            value,
            color = AegisColors.text,
            fontSize = 12.sp,
            textAlign = TextAlign.End,
            modifier = Modifier.weight(1f).padding(start = 12.dp)
        )
    }
}

@Composable
private fun MessageBubble(message: AegisRustBridge.ChatMessageUi) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (message.outgoing) Arrangement.End else Arrangement.Start
    ) {
        Surface(
            color = if (message.outgoing) AegisColors.outgoing else AegisColors.incoming,
            shape = RoundedCornerShape(
                topStart = 14.dp,
                topEnd = 14.dp,
                bottomStart = if (message.outgoing) 14.dp else 4.dp,
                bottomEnd = if (message.outgoing) 4.dp else 14.dp
            ),
            modifier = Modifier.widthIn(max = 330.dp)
        ) {
            Column(Modifier.padding(horizontal = 11.dp, vertical = 8.dp)) {
                Text(
                    message.text,
                    color = AegisColors.text,
                    fontSize = 14.sp,
                    lineHeight = 20.sp
                )
                message.attachment?.let { attachment ->
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "📷 ${attachment.filename} · EXIF очищен",
                        color = AegisColors.info,
                        fontSize = 11.sp
                    )
                }
                Spacer(Modifier.height(3.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    Text(
                        "${message.paddedBucketBytes} B",
                        color = AegisColors.muted,
                        fontSize = 9.sp
                    )
                    message.ttlSeconds?.let { ttl ->
                        Text(
                            " · ${ttl}с",
                            color = AegisColors.muted,
                            fontSize = 9.sp
                        )
                    }
                    if (message.outgoing) {
                        Text(
                            " ✓✓",
                            color = AegisColors.info,
                            fontSize = 9.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ComposerBar(
    draft: String,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit,
    onPhoto: () -> Unit
) {
    Surface(color = AegisColors.panel) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            Text(
                "＋",
                color = AegisColors.info,
                fontSize = 25.sp,
                modifier = Modifier
                    .clickable(onClick = onPhoto)
                    .padding(horizontal = 6.dp, vertical = 4.dp)
            )
            OutlinedTextField(
                value = draft,
                onValueChange = onDraftChange,
                placeholder = { Text("Сообщение") },
                maxLines = 4,
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.weight(1f).padding(horizontal = 4.dp)
            )
            Text(
                "➤",
                color = AegisColors.accent,
                fontSize = 24.sp,
                modifier = Modifier
                    .clickable(onClick = onSend)
                    .padding(horizontal = 8.dp, vertical = 6.dp)
            )
        }
    }
}

private fun shieldLabel(state: AegisRustBridge.NetworkShieldState): String = when (state) {
    AegisRustBridge.NetworkShieldState.TOR_ANONYMIZED -> "Tor / Onion"
    AegisRustBridge.NetworkShieldState.VPN_PROTECTED -> "VPN / SOCKS5"
    AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED -> "Kill Switch: сеть заблокирована"
    AegisRustBridge.NetworkShieldState.DIRECT_STATIC_IP_TLS -> "Прямое TLS-подключение"
}
