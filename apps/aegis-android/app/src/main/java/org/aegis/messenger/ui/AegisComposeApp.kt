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

@Composable
fun AegisComposeApp(
    bridge: AegisRustBridge,
    onPanicWipeTriggered: () -> Unit
) {
    var uiTick by remember { mutableStateOf(0) }
    var activeScreen by remember { mutableStateOf("STEP_1_ACCOUNT") }
    var activeChatIndex by remember { mutableStateOf(0) }
    var draftText by remember { mutableStateOf("") }
    var statusBanner by remember { mutableStateOf("") }
    var pendingLeakWarning by remember { mutableStateOf<AegisRustBridge.LeakWarningUi?>(null) }
    var chatPinInput by remember { mutableStateOf("") }

    var generatedNickname by remember { mutableStateOf(bridge.generateAnonymousNickname()) }
    var displayNameInput by remember { mutableStateOf("Призрак Сети") }
    var onboardingPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }

    var customStaticIpInput by remember { mutableStateOf("") }
    var blindRelayInput by remember { mutableStateOf(bridge.blindRelayEndpoint) }
    var socks5ProxyInput by remember { mutableStateOf(bridge.socks5ProxyEndpoint) }
    var showAdvancedNetwork by remember { mutableStateOf(false) }

    var showNewChatDialog by remember { mutableStateOf(false) }
    var newChatPeerName by remember { mutableStateOf("") }
    var newChatChannelCode by remember { mutableStateOf("") }
    var searchQuery by remember { mutableStateOf("") }
    var showMenu by remember { mutableStateOf(false) }
    var showChatMenu by remember { mutableStateOf(false) }
    var showPanicConfirm by remember { mutableStateOf(false) }

    val currentTick = uiTick
    val isRu = bridge.locale == AegisRustBridge.AppLocale.RU
    val incognitoKeyboardOptions = KeyboardOptions(autoCorrect = false)

    fun tr(ru: String, en: String): String = if (bridge.locale == AegisRustBridge.AppLocale.RU) ru else en

    fun applyStatus(message: String) {
        statusBanner = message
        uiTick++
    }

    fun go(screen: String) {
        activeScreen = screen
        uiTick++
    }

    fun toggleLanguage() {
        val next = if (bridge.locale == AegisRustBridge.AppLocale.RU) {
            AegisRustBridge.AppLocale.EN
        } else {
            AegisRustBridge.AppLocale.RU
        }
        bridge.switchLocale(next)
        if (displayNameInput == "Призрак Сети" && next == AegisRustBridge.AppLocale.EN) {
            displayNameInput = "Network Ghost"
        } else if (displayNameInput == "Network Ghost" && next == AegisRustBridge.AppLocale.RU) {
            displayNameInput = "Призрак Сети"
        }
        applyStatus(
            if (next == AegisRustBridge.AppLocale.RU) {
                "Язык интерфейса: Русский."
            } else {
                "Interface language: English."
            }
        )
    }

    fun runPanicWipe() {
        draftText = ""
        pendingLeakWarning = null
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
            if (currentTick >= 0 && bridge.wipedByPanicOrDuress) {
                WipedScreen(isRu = isRu)
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
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                BrandMark(size = 44.dp)
                                Spacer(Modifier.width(12.dp))
                                Column {
                                    Text("Aegis", color = AegisColors.text, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                                    Text(
                                        tr("Мессенджер", "Messenger"),
                                        color = AegisColors.muted,
                                        fontSize = 12.sp
                                    )
                                }
                            }
                            SmallChoice(if (isRu) "EN" else "RU") { toggleLanguage() }
                        }
                        Spacer(Modifier.height(24.dp))
                        Text(
                            tr("Вход без номера телефона и почты", "Sign in without a phone number or email"),
                            color = AegisColors.text,
                            fontSize = 26.sp,
                            fontWeight = FontWeight.Bold,
                            lineHeight = 32.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            tr(
                                "Создайте локальный профиль и укажите адрес сервера для обмена сообщениями.",
                                "Create a local profile and enter a server address to exchange messages."
                            ),
                            color = AegisColors.muted,
                            fontSize = 14.sp,
                            lineHeight = 20.sp
                        )
                        Spacer(Modifier.height(18.dp))
                        StatusBanner(statusBanner)
                        Spacer(Modifier.height(12.dp))

                        AuthCard {
                            Text(
                                tr("Создание профиля", "Create profile"),
                                color = AegisColors.text,
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                tr("Шаг 1 из 3", "Step 1 of 3"),
                                color = AegisColors.accent,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(Modifier.height(14.dp))

                            OutlinedTextField(
                                value = generatedNickname,
                                onValueChange = { generatedNickname = it },
                                label = { Text(tr("Логин", "Username")) },
                                singleLine = true,
                                keyboardOptions = incognitoKeyboardOptions,
                                modifier = Modifier.fillMaxWidth()
                            )
                            TextButton(
                                onClick = { generatedNickname = bridge.generateAnonymousNickname() },
                                contentPadding = PaddingValues(horizontal = 0.dp)
                            ) {
                                Text(
                                    tr("Сгенерировать случайный логин", "Generate random username"),
                                    color = AegisColors.info,
                                    fontSize = 12.sp
                                )
                            }

                            OutlinedTextField(
                                value = displayNameInput,
                                onValueChange = { displayNameInput = it },
                                label = { Text(tr("Имя", "Display name")) },
                                singleLine = true,
                                keyboardOptions = incognitoKeyboardOptions,
                                modifier = Modifier.fillMaxWidth()
                            )
                            Spacer(Modifier.height(8.dp))

                            OutlinedTextField(
                                value = onboardingPassword,
                                onValueChange = { onboardingPassword = it },
                                label = { Text(tr("Пароль", "Password")) },
                                singleLine = true,
                                visualTransformation = if (showPassword) {
                                    VisualTransformation.None
                                } else {
                                    PasswordVisualTransformation()
                                },
                                keyboardOptions = incognitoKeyboardOptions,
                                trailingIcon = {
                                    TextButton(onClick = { showPassword = !showPassword }) {
                                        Text(
                                            if (showPassword) tr("Скрыть", "Hide") else tr("Показать", "Show"),
                                            fontSize = 11.sp
                                        )
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            )
                            Text(
                                tr(
                                    "Минимум 12 символов, 3 заглавные, цифра и спецсимвол.",
                                    "At least 12 characters, 3 uppercase letters, a digit and a symbol."
                                ),
                                color = AegisColors.muted,
                                fontSize = 11.sp
                            )

                            Spacer(Modifier.height(14.dp))
                            Button(
                                onClick = {
                                    bridge.registerAccount(
                                        generatedNickname.trim(),
                                        displayNameInput.ifBlank { tr("Основной профиль", "Main Profile") },
                                        onboardingPassword
                                    ).onSuccess { slot ->
                                        onboardingPassword = ""
                                        activeScreen = "STEP_2_SERVERS"
                                        applyStatus(
                                            tr(
                                                "Профиль ${slot.displayName} создан. Выберите сервер.",
                                                "Profile ${slot.displayName} created. Select a server."
                                            )
                                        )
                                    }.onFailure { error ->
                                        applyStatus(tr("Проверьте данные: ${error.message}", "Check details: ${error.message}"))
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Text(tr("Продолжить", "Continue"), fontWeight = FontWeight.Bold)
                            }
                            TextButton(
                                onClick = { go("STEP_2_SERVERS") },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    tr("Перейти к выбору сервера →", "Go to server selection →"),
                                    color = AegisColors.muted,
                                    fontSize = 12.sp
                                )
                            }
                        }
                    }
                }

                "STEP_2_SERVERS" -> {
                    Column(Modifier.fillMaxSize()) {
                        AppTopBar(
                            title = tr("Серверы", "Servers"),
                            subtitle = "${bridge.activeServer.staticIpOrHost}:${bridge.activeServer.port}",
                            onMenu = { showMenu = true }
                        )
                        StatusBanner(statusBanner)
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .verticalScroll(rememberScrollState())
                                .padding(horizontal = 14.dp, vertical = 8.dp)
                        ) {
                            SectionLabel(tr("Доверенные серверы (активны)", "Trusted servers (online)"))
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
                                                applyStatus(
                                                    tr(
                                                        "Подключён ${it.staticIpOrHost}:${it.port}.",
                                                        "Connected to ${it.staticIpOrHost}:${it.port}."
                                                    )
                                                )
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

                            SectionLabel(tr("Или подключите свой адрес", "Or connect a custom address"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    OutlinedTextField(
                                        value = customStaticIpInput,
                                        onValueChange = { customStaticIpInput = it },
                                        label = { Text(tr("Адрес сервера (host:port)", "Server address (host:port)")) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Button(
                                        onClick = {
                                            bridge.connectCustomStaticIp(customStaticIpInput)
                                                .onSuccess { server ->
                                                    applyStatus(
                                                        tr(
                                                            "Подключён ${server.staticIpOrHost}:${server.port}.",
                                                            "Connected to ${server.staticIpOrHost}:${server.port}."
                                                        )
                                                    )
                                                }
                                                .onFailure { error ->
                                                    applyStatus(tr("Ошибка адреса: ${error.message}", "Address error: ${error.message}"))
                                                }
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp)
                                    ) {
                                        Text(tr("Подключить", "Connect"))
                                    }
                                }
                            }

                            SectionLabel(tr("Переключатели", "Toggles"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            tr("Блокировка сети (Kill Switch)", "Network Lock (Kill Switch)"),
                                            color = AegisColors.text,
                                            fontSize = 14.sp,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Switch(
                                            checked = bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED,
                                            onCheckedChange = { enabled ->
                                                bridge.shieldState = if (enabled) {
                                                    AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                                } else {
                                                    AegisRustBridge.NetworkShieldState.DIRECT_STATIC_IP_TLS
                                                }
                                                applyStatus(
                                                    if (enabled) tr("Сеть заблокирована.", "Network locked.") else tr("Сеть включена.", "Network enabled.")
                                                )
                                            }
                                        )
                                    }
                                    TextButton(
                                        onClick = { showAdvancedNetwork = !showAdvancedNetwork },
                                        contentPadding = PaddingValues(0.dp)
                                    ) {
                                        Text(
                                            if (showAdvancedNetwork) {
                                                tr("Скрыть прокси и релей", "Hide proxy & relay")
                                            } else {
                                                tr("SOCKS5 прокси и релей", "SOCKS5 proxy & relay")
                                            },
                                            color = AegisColors.info,
                                            fontSize = 12.sp
                                        )
                                    }
                                    if (showAdvancedNetwork) {
                                        OutlinedTextField(
                                            value = blindRelayInput,
                                            onValueChange = {
                                                blindRelayInput = it
                                                bridge.blindRelayEndpoint = it.trim()
                                            },
                                            label = { Text(tr("Релей (host:port)", "Relay (host:port)")) },
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
                                            },
                                            label = { Text(tr("SOCKS5 прокси (127.0.0.1:9050)", "SOCKS5 proxy (127.0.0.1:9050)")) },
                                            singleLine = true,
                                            keyboardOptions = incognitoKeyboardOptions,
                                            modifier = Modifier.fillMaxWidth()
                                        )
                                    }
                                }
                            }

                            Spacer(Modifier.height(14.dp))
                            Button(
                                onClick = { go("STEP_3_CHAT_LIST") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Text(tr("Открыть чаты", "Open chats"), fontWeight = FontWeight.Bold)
                            }
                            Spacer(Modifier.height(16.dp))
                        }
                        AppBottomBar(
                            isRu = isRu,
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
                            title = tr("Профиль", "Profile"),
                            subtitle = tr("Настройки", "Settings"),
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
                                        }
                                    }
                                }
                            } else {
                                Text(tr("Профиль ещё не создан.", "No profile created yet."), color = AegisColors.muted)
                            }

                            SectionLabel(tr("Аккаунты", "Accounts"))
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
                                        }
                                    }
                                    Spacer(Modifier.height(6.dp))
                                    SmallChoice(tr("+ Профиль", "+ Profile")) { go("STEP_1_ACCOUNT") }
                                }
                            }

                            SectionLabel(tr("Переключатели", "Toggles"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            tr("Блокировка сети (Kill Switch)", "Network Lock (Kill Switch)"),
                                            color = AegisColors.text,
                                            fontSize = 13.sp,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Switch(
                                            checked = bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED,
                                            onCheckedChange = { enabled ->
                                                bridge.shieldState = if (enabled) {
                                                    AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                                } else {
                                                    AegisRustBridge.NetworkShieldState.DIRECT_STATIC_IP_TLS
                                                }
                                                applyStatus(
                                                    if (enabled) tr("Сеть заблокирована.", "Network locked.")
                                                    else tr("Сеть включена.", "Network enabled.")
                                                )
                                            }
                                        )
                                    }
                                }
                            }

                            SectionLabel(tr("Приложение", "Application"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(14.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(14.dp)) {
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        SmallChoice(if (isRu) "English" else "Русский") { toggleLanguage() }
                                        SmallChoice(tr("Серверы", "Servers")) { go("STEP_2_SERVERS") }
                                    }
                                    Spacer(Modifier.height(10.dp))
                                    Button(
                                        onClick = { showPanicConfirm = true },
                                        colors = ButtonDefaults.buttonColors(containerColor = AegisColors.danger),
                                        shape = RoundedCornerShape(12.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(tr("Стереть все данные", "Wipe all data"), fontWeight = FontWeight.Bold)
                                    }
                                }
                            }
                            Spacer(Modifier.height(16.dp))
                        }
                        AppBottomBar(
                            isRu = isRu,
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
                            Text(tr("Чат не найден", "Chat not found"), color = AegisColors.text, fontSize = 18.sp)
                            TextButton(onClick = { go("STEP_3_CHAT_LIST") }) {
                                Text(tr("Вернуться к чатам", "Back to chats"), color = AegisColors.info)
                            }
                        }
                    } else {
                        val chatSubtitle = when {
                            currentChat.isSavedNotes -> tr("Локальные заметки", "Local notes")
                            bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED ->
                                tr("Сеть заблокирована", "Network locked")
                            else -> tr("Канал сообщений", "Message channel")
                        }
                        Column(Modifier.fillMaxSize().imePadding()) {
                            AppTopBar(
                                title = currentChat.title,
                                subtitle = chatSubtitle,
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
                                                    applyStatus(tr("Сеть заблокирована.", "Network is locked."))
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

                            currentChat.keyChangeWarning?.let {
                                Surface(
                                    color = AegisColors.warning.copy(alpha = 0.12f),
                                    shape = RoundedCornerShape(12.dp),
                                    border = BorderStroke(1.dp, AegisColors.warning.copy(alpha = 0.45f)),
                                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
                                ) {
                                    Column(Modifier.padding(12.dp)) {
                                        Text(
                                            tr("Ключ собеседника изменился", "Contact key has changed"),
                                            color = AegisColors.warning,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Spacer(Modifier.height(6.dp))
                                        TextButton(onClick = {
                                            bridge.acknowledgeKeyChange(safeIndex)
                                            applyStatus(tr("Новый ключ подтверждён.", "New key approved."))
                                        }) {
                                            Text(tr("Подтвердить", "Approve"), color = AegisColors.warning, fontSize = 12.sp)
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
                                        Text(
                                            tr("Обнаружены личные данные", "Sensitive data detected"),
                                            color = AegisColors.danger,
                                            fontSize = 13.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Text(
                                            warning.maskedPreview,
                                            color = AegisColors.muted,
                                            fontSize = 11.sp,
                                            maxLines = 3,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Spacer(Modifier.height(6.dp))
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            TextButton(onClick = {
                                                if (!currentChat.isSavedNotes && currentChat.keyChangeWarning != null) {
                                                    applyStatus(tr("Сначала подтвердите ключ собеседника.", "Approve contact key first."))
                                                } else if (!currentChat.isSavedNotes &&
                                                    bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                                ) {
                                                    applyStatus(tr("Сеть заблокирована.", "Network is locked."))
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
                                                Text(tr("Скрыть и отправить", "Mask & send"), color = AegisColors.accent, fontSize = 12.sp)
                                            }
                                            TextButton(onClick = {
                                                if (!currentChat.isSavedNotes && currentChat.keyChangeWarning != null) {
                                                    applyStatus(tr("Сначала подтвердите ключ собеседника.", "Approve contact key first."))
                                                } else if (!currentChat.isSavedNotes &&
                                                    bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                                ) {
                                                    applyStatus(tr("Сеть заблокирована.", "Network is locked."))
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
                                                Text(tr("Отправить как есть", "Send anyway"), color = AegisColors.danger, fontSize = 12.sp)
                                            }
                                            TextButton(onClick = { pendingLeakWarning = null }) {
                                                Text(tr("Отмена", "Cancel"), color = AegisColors.muted, fontSize = 12.sp)
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
                                    Text(
                                        tr("Чат закрыт", "Chat is locked"),
                                        color = AegisColors.text,
                                        fontSize = 20.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Text(
                                        tr("Введите PIN, чтобы открыть переписку.", "Enter PIN to unlock this conversation."),
                                        color = AegisColors.muted,
                                        fontSize = 13.sp
                                    )
                                    Spacer(Modifier.height(16.dp))
                                    OutlinedTextField(
                                        value = chatPinInput,
                                        onValueChange = { chatPinInput = it },
                                        label = { Text(tr("PIN чата", "Chat PIN")) },
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
                                                applyStatus(tr("Чат разблокирован.", "Chat unlocked."))
                                            } else {
                                                chatPinInput = ""
                                                if (bridge.wipedByPanicOrDuress) {
                                                    runPanicWipe()
                                                } else {
                                                    applyStatus(
                                                        tr(
                                                            "Неверный PIN. Осталось попыток: ${bridge.remainingPinAttempts}.",
                                                            "Wrong PIN. Attempts left: ${bridge.remainingPinAttempts}."
                                                        )
                                                    )
                                                }
                                            }
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                        shape = RoundedCornerShape(12.dp)
                                    ) {
                                        Text(tr("Открыть чат", "Unlock chat"))
                                    }
                                }
                            } else {
                                LazyColumn(
                                    modifier = Modifier.weight(1f),
                                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    items(currentChat.messages) { message ->
                                        MessageBubble(message, isRu = isRu)
                                    }
                                }
                                ComposerBar(
                                    isRu = isRu,
                                    draft = draftText,
                                    onDraftChange = { draftText = it },
                                    onSend = {
                                        if (draftText.isBlank()) {
                                            applyStatus(tr("Введите сообщение.", "Enter a message."))
                                        } else if (!currentChat.isSavedNotes && currentChat.keyChangeWarning != null) {
                                            applyStatus(tr("Сначала подтвердите ключ собеседника.", "Approve contact key first."))
                                        } else if (!currentChat.isSavedNotes &&
                                            bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED
                                        ) {
                                            applyStatus(tr("Сеть заблокирована.", "Network is locked."))
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
                                    }
                                )
                            }
                        }

                        if (showChatMenu) {
                            AlertDialog(
                                onDismissRequest = { showChatMenu = false },
                                title = { Text(tr("Чат", "Chat")) },
                                text = {
                                    Column {
                                        if (currentChat.perChatPin != null && !currentChat.isLocked) {
                                            TextButton(onClick = {
                                                showChatMenu = false
                                                currentChat.isLocked = true
                                                applyStatus(tr("Чат закрыт PIN-кодом.", "Chat locked with PIN."))
                                            }) { Text(tr("Закрыть чат PIN-кодом", "Lock chat with PIN")) }
                                        }
                                        TextButton(onClick = {
                                            showChatMenu = false
                                            val nextTtl = when (currentChat.defaultTtlSeconds) {
                                                60 -> 3600
                                                3600 -> null
                                                else -> 60
                                            }
                                            bridge.setChatDisappearingTtl(safeIndex, nextTtl)
                                            applyStatus(
                                                if (nextTtl == null) {
                                                    tr("Таймер выключен.", "Timer disabled.")
                                                } else {
                                                    tr("Таймер: $nextTtl с.", "Timer: $nextTtl s.")
                                                }
                                            )
                                        }) { Text(tr("Таймер исчезновения", "Disappearing timer")) }
                                    }
                                },
                                confirmButton = {},
                                dismissButton = {
                                    TextButton(onClick = { showChatMenu = false }) { Text(tr("Закрыть", "Close")) }
                                }
                            )
                        }
                    }
                }

                else -> {
                    Column(Modifier.fillMaxSize()) {
                        AppTopBar(
                            title = "Aegis",
                            subtitle = tr("Мессенджер", "Messenger"),
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
                            placeholder = { Text(tr("Поиск по чатам", "Search chats")) },
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
                            SmallChoice(tr("+ Новый чат", "+ New chat")) { showNewChatDialog = true }
                            SmallChoice(if (isRu) "EN" else "RU") { toggleLanguage() }
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
                                Text(
                                    tr("Ничего не найдено", "Nothing found"),
                                    color = AegisColors.text,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    tr("Измените запрос или создайте новый чат.", "Try a different query or create a new chat."),
                                    color = AegisColors.muted,
                                    fontSize = 12.sp
                                )
                            }
                        } else {
                            LazyColumn(
                                modifier = Modifier.weight(1f),
                                contentPadding = PaddingValues(vertical = 4.dp)
                            ) {
                                itemsIndexed(bridge.chats) { actualIndex, chat ->
                                    if (!chatMatches(chat)) return@itemsIndexed
                                    val preview = if (chat.isLocked) {
                                        tr("Закрыто PIN-кодом", "Locked with PIN")
                                    } else {
                                        chat.messages.lastOrNull()?.text ?: tr("Нет сообщений", "No messages")
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
                            isRu = isRu,
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
                                toggleLanguage()
                            }) { Text(if (isRu) "Switch to English" else "Переключить на русский") }
                            TextButton(onClick = {
                                showMenu = false
                                go("PROFILE")
                            }) { Text(tr("Профиль", "Profile")) }
                            TextButton(onClick = {
                                showMenu = false
                                go("STEP_2_SERVERS")
                            }) { Text(tr("Серверы", "Servers")) }
                            TextButton(onClick = {
                                showMenu = false
                                showPanicConfirm = true
                            }) { Text(tr("Сброс данных", "Wipe data"), color = AegisColors.danger) }
                        }
                    },
                    confirmButton = {},
                    dismissButton = {
                        TextButton(onClick = { showMenu = false }) { Text(tr("Закрыть", "Close")) }
                    }
                )
            }

            if (showNewChatDialog) {
                AlertDialog(
                    onDismissRequest = { showNewChatDialog = false },
                    title = { Text(tr("Новый чат", "New chat")) },
                    text = {
                        Column {
                            Text(
                                tr(
                                    "Договоритесь с собеседником об общем коде канала.",
                                    "Agree on a shared channel code with your contact."
                                ),
                                color = AegisColors.muted,
                                fontSize = 12.sp
                            )
                            Spacer(Modifier.height(10.dp))
                            OutlinedTextField(
                                value = newChatPeerName,
                                onValueChange = { newChatPeerName = it },
                                label = { Text(tr("Имя собеседника", "Contact name")) },
                                singleLine = true,
                                keyboardOptions = incognitoKeyboardOptions,
                                modifier = Modifier.fillMaxWidth()
                            )
                            Spacer(Modifier.height(8.dp))
                            OutlinedTextField(
                                value = newChatChannelCode,
                                onValueChange = { newChatChannelCode = it },
                                label = { Text(tr("Код канала", "Channel code")) },
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
                                    applyStatus(tr("Чат создан.", "Chat created."))
                                }
                                .onFailure { error ->
                                    applyStatus(tr("Чат не создан: ${error.message}", "Chat not created: ${error.message}"))
                                }
                        }) { Text(tr("Создать", "Create")) }
                    },
                    dismissButton = {
                        TextButton(onClick = { showNewChatDialog = false }) { Text(tr("Отмена", "Cancel")) }
                    }
                )
            }

            if (showPanicConfirm) {
                AlertDialog(
                    onDismissRequest = { showPanicConfirm = false },
                    title = { Text(tr("Стереть все данные?", "Wipe all data?")) },
                    text = {
                        Text(
                            tr(
                                "Локальные профили и переписка в приложении будут очищены.",
                                "Local profiles and conversations in the app will be cleared."
                            ),
                            color = AegisColors.muted,
                            fontSize = 13.sp
                        )
                    },
                    confirmButton = {
                        TextButton(onClick = { runPanicWipe() }) {
                            Text(tr("Стереть", "Wipe"), color = AegisColors.danger, fontWeight = FontWeight.Bold)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showPanicConfirm = false }) { Text(tr("Отмена", "Cancel")) }
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
private fun WipedScreen(isRu: Boolean) {
    Column(
        modifier = Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("✓", fontSize = 44.sp, color = AegisColors.accent)
        Spacer(Modifier.height(12.dp))
        Text(
            if (isRu) "Данные удалены" else "Data wiped",
            color = AegisColors.text,
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )
        Spacer(Modifier.height(8.dp))
        Text(
            if (isRu) {
                "Локальные профили и переписка очищены."
            } else {
                "Local profiles and conversations have been cleared."
            },
            color = AegisColors.muted,
            fontSize = 13.sp,
            textAlign = TextAlign.Center,
            lineHeight = 19.sp
        )
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
    isRu: Boolean,
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
        BottomItem("💬", if (isRu) "Чаты" else "Chats", active == "chats", onChats, Modifier.weight(1f))
        BottomItem("🌐", if (isRu) "Серверы" else "Servers", active == "servers", onServers, Modifier.weight(1f))
        BottomItem("👤", if (isRu) "Профиль" else "Profile", active == "profile", onProfile, Modifier.weight(1f))
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
private fun MessageBubble(message: AegisRustBridge.ChatMessageUi, isRu: Boolean) {
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
                        "📷 ${attachment.filename}",
                        color = AegisColors.info,
                        fontSize = 11.sp
                    )
                }
                Spacer(Modifier.height(3.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    message.ttlSeconds?.let { ttl ->
                        val ttlLabel = if (isRu) {
                            if (ttl >= 3600) "${ttl / 3600} ч" else if (ttl >= 60) "${ttl / 60} мин" else "${ttl} с"
                        } else {
                            if (ttl >= 3600) "${ttl / 3600} h" else if (ttl >= 60) "${ttl / 60} min" else "${ttl} s"
                        }
                        Text(
                            ttlLabel,
                            color = AegisColors.muted,
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
    isRu: Boolean,
    draft: String,
    onDraftChange: (String) -> Unit,
    onSend: () -> Unit
) {
    Surface(color = AegisColors.panel) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = onDraftChange,
                placeholder = { Text(if (isRu) "Сообщение" else "Message") },
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
