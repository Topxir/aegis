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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.aegis.messenger.core.AegisRustBridge
import org.aegis.messenger.notify.AegisNotifications

@Composable
fun AegisComposeApp(
    bridge: AegisRustBridge,
    onPanicWipeTriggered: () -> Unit
) {
    var uiTick by remember { mutableStateOf(0) }
    val appContext = LocalContext.current
    var activeScreen by remember {
        mutableStateOf(if (bridge.isAuthenticated) "STEP_3_CHAT_LIST" else "STEP_1_ACCOUNT")
    }
    var authTabLogin by remember { mutableStateOf(bridge.accounts.isNotEmpty()) }
    var activeChatIndex by remember { mutableStateOf(0) }
    var draftText by remember { mutableStateOf("") }
    var statusBanner by remember { mutableStateOf("") }
    var pendingLeakWarning by remember { mutableStateOf<AegisRustBridge.LeakWarningUi?>(null) }
    var chatPinInput by remember { mutableStateOf("") }

    var generatedNickname by remember {
        mutableStateOf(bridge.accounts.lastOrNull()?.loginNickname ?: bridge.generateAnonymousNickname())
    }
    var displayNameInput by remember { mutableStateOf("Призрак Сети") }
    var onboardingPassword by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }

    var customStaticIpInput by remember { mutableStateOf("") }
    var blindRelayInput by remember { mutableStateOf(bridge.blindRelayEndpoint) }
    var socks5ProxyInput by remember { mutableStateOf(bridge.socks5ProxyEndpoint) }
    var showAdvancedNetwork by remember { mutableStateOf(false) }

    var showNewChatDialog by remember { mutableStateOf(false) }
    var newChatMode by remember { mutableStateOf("dm") }
    var newChatPeerName by remember { mutableStateOf("") }
    var newChatChannelCode by remember { mutableStateOf("") }
    var searchQuery by remember { mutableStateOf("") }
    var showMenu by remember { mutableStateOf(false) }
    var showChatMenu by remember { mutableStateOf(false) }
    var showPanicConfirm by remember { mutableStateOf(false) }
    var editNameInput by remember { mutableStateOf("") }
    var editMainUzInput by remember { mutableStateOf("") }
    var extraUzInput by remember { mutableStateOf("") }
    var lookupProfileUzInput by remember { mutableStateOf("") }
    var profileBioInput by remember { mutableStateOf("") }

    LaunchedEffect(bridge.isAuthenticated, activeScreen) {
        if (bridge.isAuthenticated) {
            bridge.searchServerDirectoryAsync("") { uiTick++ }
            bridge.checkForUpdatesAsync(false) { uiTick++ }
            while (bridge.isAuthenticated) {
                bridge.syncAllChatsAndInboxAsync { newCount, _ ->
                    if (newCount > 0 && bridge.pushNotificationsEnabled) {
                        bridge.lastPushToast?.let { (title, text) ->
                            AegisNotifications.showMessage(
                                appContext,
                                title,
                                text,
                                bridge.soundNotificationsEnabled
                            )
                        }
                    }
                    bridge.lastPushToast = null
                    uiTick++
                }
                kotlinx.coroutines.delay(1800L)
            }
        }
    }

    val currentTick = uiTick
    val isRu = bridge.locale == AegisRustBridge.AppLocale.RU
    val incognitoKeyboardOptions = KeyboardOptions(autoCorrect = false)

    fun tr(ru: String, en: String): String = if (bridge.locale == AegisRustBridge.AppLocale.RU) ru else en

    fun applyStatus(message: String) {
        statusBanner = message
        uiTick++
    }

    fun go(screen: String) {
        if (!bridge.isAuthenticated && screen != "STEP_1_ACCOUNT") {
            activeScreen = "STEP_1_ACCOUNT"
            statusBanner = tr(
                "Сначала зарегистрируйтесь или войдите в аккаунт.",
                "Please register or sign in to an account first."
            )
            uiTick++
            return
        }
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

    val baseDensity = LocalDensity.current
    val fontScaleMultiplier = when (bridge.fontScale) {
        "compact" -> 0.88f
        "large" -> 1.14f
        else -> 1f
    }
    val scaledDensity = Density(baseDensity.density, baseDensity.fontScale * fontScaleMultiplier)

    AegisTheme(mode = bridge.uiTheme) {
      CompositionLocalProvider(LocalDensity provides scaledDensity) {
        Surface(modifier = Modifier.fillMaxSize(), color = AegisColors.bg) {
            if (currentTick >= 0 && bridge.wipedByPanicOrDuress) {
                WipedScreen(
                    isRu = isRu,
                    onReset = {
                        bridge.resetAfterWipe()
                        authTabLogin = false
                        activeScreen = "STEP_1_ACCOUNT"
                        statusBanner = ""
                        uiTick++
                    }
                )
                return@Surface
            }

            val effectiveScreen = if (!bridge.isAuthenticated) "STEP_1_ACCOUNT" else activeScreen
            when (effectiveScreen) {
                "STEP_1_ACCOUNT" -> {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(horizontal = 16.dp, vertical = 24.dp)
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
                                    Text("Aegis", color = AegisColors.text, fontSize = 20.sp, fontWeight = FontWeight.Medium)
                                    Text(
                                        tr("Мессенджер", "Messenger"),
                                        color = AegisColors.muted,
                                        fontSize = 13.sp
                                    )
                                }
                            }
                            SmallChoice(if (isRu) "EN" else "RU") { toggleLanguage() }
                        }
                        Spacer(Modifier.height(24.dp))
                        Text(
                            tr("Вход без номера телефона и почты", "Sign in without a phone number or email"),
                            color = AegisColors.text,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Medium,
                            lineHeight = 26.sp
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            tr(
                                "Доступ к чатам и серверам открывается только после регистрации или входа в аккаунт.",
                                "Access to chats and servers requires registering or signing in to an account."
                            ),
                            color = AegisColors.muted,
                            fontSize = 15.sp,
                            lineHeight = 21.sp
                        )
                        Spacer(Modifier.height(16.dp))
                        StatusBanner(statusBanner)
                        Spacer(Modifier.height(12.dp))

                        AuthCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Button(
                                    onClick = {
                                        authTabLogin = false
                                        statusBanner = ""
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = if (!authTabLogin) AegisColors.accent else AegisColors.panel2
                                    ),
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(
                                        tr("Регистрация", "Register"),
                                        color = if (!authTabLogin) AegisColors.onAccent else AegisColors.text,
                                        fontWeight = FontWeight.Medium,
                                        fontSize = 13.sp
                                    )
                                }
                                Button(
                                    onClick = {
                                        authTabLogin = true
                                        statusBanner = ""
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = if (authTabLogin) AegisColors.accent else AegisColors.panel2
                                    ),
                                    shape = RoundedCornerShape(10.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text(
                                        tr("Вход", "Sign in"),
                                        color = if (authTabLogin) AegisColors.onAccent else AegisColors.text,
                                        fontWeight = FontWeight.Medium,
                                        fontSize = 13.sp
                                    )
                                }
                            }
                            Spacer(Modifier.height(16.dp))

                            if (authTabLogin) {
                                Text(
                                    tr("Вход в аккаунт", "Sign in to account"),
                                    color = AegisColors.text,
                                    fontSize = 17.sp,
                                    fontWeight = FontWeight.Medium
                                )
                                Spacer(Modifier.height(12.dp))
                                OutlinedTextField(
                                    value = generatedNickname,
                                    onValueChange = { generatedNickname = it },
                                    label = { Text(tr("Логин", "Username")) },
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
                                Spacer(Modifier.height(16.dp))
                                Button(
                                    onClick = {
                                        bridge.loginAccount(
                                            generatedNickname.trim(),
                                            onboardingPassword
                                        ).onSuccess { slot ->
                                            onboardingPassword = ""
                                            confirmPassword = ""
                                            activeScreen = "STEP_3_CHAT_LIST"
                                            applyStatus(
                                                tr(
                                                    "Вы вошли как ${slot.displayName} (@${slot.loginNickname}).",
                                                    "Signed in as ${slot.displayName} (@${slot.loginNickname})."
                                                )
                                            )
                                        }.onFailure { error ->
                                            applyStatus("${error.message}")
                                        }
                                    },
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Text(tr("Войти", "Sign in"), fontWeight = FontWeight.Medium)
                                }
                            } else {
                                Text(
                                    tr("Регистрация аккаунта", "Create account"),
                                    color = AegisColors.text,
                                    fontSize = 17.sp,
                                    fontWeight = FontWeight.Medium
                                )
                                Spacer(Modifier.height(12.dp))

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
                                        fontSize = 13.sp
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
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = confirmPassword,
                                    onValueChange = { confirmPassword = it },
                                    label = { Text(tr("Повторите пароль", "Confirm password")) },
                                    singleLine = true,
                                    visualTransformation = if (showPassword) {
                                        VisualTransformation.None
                                    } else {
                                        PasswordVisualTransformation()
                                    },
                                    keyboardOptions = incognitoKeyboardOptions,
                                    modifier = Modifier.fillMaxWidth()
                                )
                                Text(
                                    tr(
                                        "Пароль защищает ваш аккаунт (от 4 символов).",
                                        "Password protects your account (4+ characters)."
                                    ),
                                    color = AegisColors.muted,
                                    fontSize = 11.sp
                                )

                                Spacer(Modifier.height(16.dp))
                                Button(
                                    onClick = {
                                        bridge.registerAccount(
                                            generatedNickname.trim(),
                                            displayNameInput.ifBlank { tr("Основной профиль", "Main Profile") },
                                            onboardingPassword,
                                            confirmPassword
                                        ).onSuccess { slot ->
                                            onboardingPassword = ""
                                            confirmPassword = ""
                                            activeScreen = "STEP_3_CHAT_LIST"
                                            bridge.syncAllChatsAndInboxAsync { _, _ -> uiTick++ }
                                            applyStatus(
                                                tr(
                                                    "Вы вошли как ${slot.displayName} (@${slot.loginNickname}).",
                                                    "Signed in as ${slot.displayName} (@${slot.loginNickname})."
                                                )
                                            )
                                        }.onFailure { error ->
                                            applyStatus("${error.message}")
                                        }
                                    },
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Text(tr("Зарегистрироваться", "Create account"), fontWeight = FontWeight.Medium)
                                }
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
                                .padding(horizontal = 16.dp, vertical = 8.dp)
                        ) {
                            SectionLabel(tr("Доверенные серверы (активны)", "Trusted servers (online)"))
                            bridge.starterServers.forEachIndexed { index, server ->
                                val selected = index == bridge.activeServerIndex
                                Surface(
                                    color = if (selected) AegisColors.panel2 else AegisColors.panel,
                                    shape = RoundedCornerShape(10.dp),
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
                                        modifier = Modifier.padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                server.name,
                                                color = AegisColors.text,
                                                fontSize = 15.sp,
                                                fontWeight = FontWeight.Medium
                                            )
                                            Text(
                                                "${server.staticIpOrHost}:${server.port} · ${server.badge}",
                                                color = AegisColors.muted,
                                                fontSize = 11.sp
                                            )
                                        }
                                        Icon(
                                            imageVector = if (selected) AegisIcons.Check else AegisIcons.ArrowRight,
                                            contentDescription = null,
                                            tint = if (selected) AegisColors.accent else AegisColors.muted,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            }

                            SectionLabel(tr("Или подключите свой адрес", "Or connect a custom address"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(12.dp)) {
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
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            tr("Блокировка сети (Kill Switch)", "Network Lock (Kill Switch)"),
                                            color = AegisColors.text,
                                            fontSize = 15.sp,
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
                                            fontSize = 13.sp
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

                            Spacer(Modifier.height(16.dp))
                            Button(
                                onClick = { go("STEP_3_CHAT_LIST") },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Text(tr("Открыть чаты", "Open chats"), fontWeight = FontWeight.Medium)
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
                            subtitle = tr("@юз и настройки", "@username & settings"),
                            onMenu = { showMenu = true }
                        )
                        UpdateBanner(bridge = bridge, isRu = isRu) { uiTick++ }
                        StatusBanner(statusBanner)
                        Column(
                            modifier = Modifier
                                .weight(1f)
                                .verticalScroll(rememberScrollState())
                                .padding(horizontal = 16.dp, vertical = 8.dp)
                        ) {
                            bridge.viewedUserProfile?.let { (peerName, peerUz, peerExtras) ->
                                SectionLabel(tr("Профиль пользователя", "User Profile"))
                                Surface(
                                    color = AegisColors.panel,
                                    shape = RoundedCornerShape(12.dp),
                                    border = BorderStroke(1.dp, AegisColors.accent.copy(alpha = 0.5f)),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(Modifier.padding(16.dp)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Avatar(peerName, size = 56.dp)
                                            Spacer(Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    bridge.stripUsernameSuffix(peerName),
                                                    color = AegisColors.text,
                                                    fontSize = 17.sp,
                                                    fontWeight = FontWeight.Medium
                                                )
                                                Spacer(Modifier.height(4.dp))
                                                val allUzs = (listOf("@$peerUz") + peerExtras.map { "@$it" }).joinToString(" · ")
                                                Text(
                                                    "${tr("Юзернейм", "Username")}: $allUzs",
                                                    color = AegisColors.accent,
                                                    fontSize = 13.sp,
                                                    fontWeight = FontWeight.Medium
                                                )
                                            }
                                        }
                                        Spacer(Modifier.height(12.dp))
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            Button(
                                                onClick = {
                                                    bridge.openDmChat(peerUz, peerName).onSuccess { idx ->
                                                        bridge.viewedUserProfile = null
                                                        activeChatIndex = idx
                                                        activeScreen = "STEP_3_CONVERSATION"
                                                        uiTick++
                                                    }
                                                },
                                                shape = RoundedCornerShape(10.dp)
                                            ) {
                                                Icon(
                                                    imageVector = AegisIcons.Chat,
                                                    contentDescription = null,
                                                    modifier = Modifier.size(16.dp)
                                                )
                                                Spacer(Modifier.width(8.dp))
                                                Text(tr("Написать", "Message"), fontWeight = FontWeight.Medium)
                                            }
                                            TextButton(onClick = {
                                                bridge.viewedUserProfile = null
                                                uiTick++
                                            }) {
                                                Text(tr("Закрыть", "Close"), color = AegisColors.muted)
                                            }
                                        }
                                    }
                                }
                            }

                            val account = bridge.accounts.getOrNull(bridge.activeAccountIndex)
                            if (account != null) {
                                val cleanMyName = bridge.stripUsernameSuffix(account.displayName)
                                val myExtras = bridge.activeAccountExtraUsernames()
                                SectionLabel(tr("Мой профиль", "My Profile"))
                                Surface(
                                    color = AegisColors.panel,
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(Modifier.padding(16.dp)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Avatar(cleanMyName, size = 56.dp)
                                            Spacer(Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    cleanMyName,
                                                    color = AegisColors.text,
                                                    fontSize = 17.sp,
                                                    fontWeight = FontWeight.Medium
                                                )
                                                Text(
                                                    bridge.profileBio,
                                                    color = AegisColors.muted,
                                                    fontSize = 13.sp,
                                                    maxLines = 2,
                                                    overflow = TextOverflow.Ellipsis
                                                )
                                                Spacer(Modifier.height(4.dp))
                                                Text(
                                                    "${tr("Основной @юз", "Primary @username")}: @${account.loginNickname}",
                                                    color = AegisColors.accent,
                                                    fontSize = 13.sp,
                                                    fontWeight = FontWeight.Medium
                                                )
                                            }
                                        }
                                        if (myExtras.isNotEmpty()) {
                                            Spacer(Modifier.height(8.dp))
                                            Row(
                                                modifier = Modifier.horizontalScroll(rememberScrollState()),
                                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                                            ) {
                                                myExtras.forEach { ex ->
                                                    SmallChoice("@$ex ×") {
                                                        bridge.removeExtraUsername(ex)
                                                        uiTick++
                                                    }
                                                }
                                            }
                                        }
                                        Spacer(Modifier.height(12.dp))
                                        OutlinedTextField(
                                            value = editNameInput,
                                            onValueChange = { editNameInput = it },
                                            label = { Text(tr("Изменить ник (без @юза)", "Change display name")) },
                                            placeholder = { Text(cleanMyName) },
                                            singleLine = true,
                                            keyboardOptions = incognitoKeyboardOptions,
                                            modifier = Modifier.fillMaxWidth()
                                        )
                                        Spacer(Modifier.height(8.dp))
                                        SmallChoice(tr("Сохранить ник", "Save display name")) {
                                            bridge.setDisplayName(editNameInput.ifBlank { cleanMyName }).onSuccess {
                                                editNameInput = ""
                                                applyStatus(tr("Ник обновлён.", "Display name updated."))
                                            }.onFailure { applyStatus("${it.message}") }
                                        }

                                        Spacer(Modifier.height(12.dp))
                                        OutlinedTextField(
                                            value = editMainUzInput,
                                            onValueChange = { editMainUzInput = it },
                                            label = { Text(tr("Основной @юз (любой от 3 букв)", "Primary @username (3+ chars)")) },
                                            placeholder = { Text("@${account.loginNickname}") },
                                            singleLine = true,
                                            keyboardOptions = incognitoKeyboardOptions,
                                            modifier = Modifier.fillMaxWidth()
                                        )
                                        Spacer(Modifier.height(8.dp))
                                        SmallChoice(tr("Изменить основной @юз", "Update primary @username")) {
                                            bridge.setPrimaryUsername(editMainUzInput).onSuccess { newUz ->
                                                editMainUzInput = ""
                                                applyStatus(tr("Основной @юз: @$newUz", "Primary @username: @$newUz"))
                                            }.onFailure { applyStatus("${it.message}") }
                                        }

                                        if (bridge.isOwnerAccount()) {
                                            Spacer(Modifier.height(12.dp))
                                            OutlinedTextField(
                                                value = extraUzInput,
                                                onValueChange = { extraUzInput = it },
                                                label = { Text(tr("Дополнительный @юз (от 3 букв, можно несколько)", "Extra @username (3+ chars)")) },
                                                singleLine = true,
                                                keyboardOptions = incognitoKeyboardOptions,
                                                modifier = Modifier.fillMaxWidth()
                                            )
                                            Spacer(Modifier.height(8.dp))
                                            SmallChoice(tr("+ Добавить ещё @юз", "+ Add extra @username")) {
                                                bridge.addExtraUsername(extraUzInput).onSuccess { ex ->
                                                    extraUzInput = ""
                                                    applyStatus(tr("Добавлен @юз: @$ex", "Added @username: @$ex"))
                                                }.onFailure { applyStatus("${it.message}") }
                                            }
                                        } else {
                                            Spacer(Modifier.height(12.dp))
                                            Text(
                                                tr(
                                                    "Несколько @юзов доступны только владельцу (@owner).",
                                                    "Multiple @usernames are available only to the Owner (@owner)."
                                                ),
                                                color = AegisColors.muted,
                                                fontSize = 11.sp
                                            )
                                        }
                                    }
                                }
                            } else {
                                Text(tr("Профиль ещё не создан.", "No profile created yet."), color = AegisColors.muted)
                            }

                            SectionLabel(tr("Оформление", "Appearance"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(16.dp)) {
                                    Text(
                                        tr("Тема", "Theme"),
                                        color = AegisColors.muted,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        listOf(
                                            "system" to tr("Системная", "System"),
                                            "dark" to tr("Тёмная", "Dark"),
                                            "light" to tr("Светлая", "Light")
                                        ).forEach { (id, label) ->
                                            SmallChoice(label, selected = bridge.uiTheme == id) {
                                                bridge.uiTheme = id
                                                bridge.saveWorkspaceToPrefs()
                                                uiTick++
                                            }
                                        }
                                    }
                                    Spacer(Modifier.height(16.dp))
                                    Text(
                                        tr("Размер текста", "Font size"),
                                        color = AegisColors.muted,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Medium
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        listOf(
                                            "compact" to tr("Компактный", "Compact"),
                                            "normal" to tr("Обычный", "Normal"),
                                            "large" to tr("Крупный", "Large")
                                        ).forEach { (id, label) ->
                                            SmallChoice(label, selected = bridge.fontScale == id) {
                                                bridge.fontScale = id
                                                bridge.saveWorkspaceToPrefs()
                                                uiTick++
                                            }
                                        }
                                    }
                                    Spacer(Modifier.height(16.dp))
                                    OutlinedTextField(
                                        value = profileBioInput,
                                        onValueChange = { profileBioInput = it },
                                        label = { Text(tr("О себе / статус", "Bio / status")) },
                                        placeholder = { Text(bridge.profileBio) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    SmallChoice(tr("Сохранить статус", "Save status")) {
                                        val bio = profileBioInput.trim().take(80)
                                        if (bio.isNotEmpty()) {
                                            bridge.profileBio = bio
                                            bridge.saveWorkspaceToPrefs()
                                            profileBioInput = ""
                                            applyStatus(tr("Статус обновлён.", "Status updated."))
                                        }
                                    }
                                }
                            }

                            SectionLabel(tr("Открыть профиль по @юзу", "Open profile by @username"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(12.dp)) {
                                    OutlinedTextField(
                                        value = lookupProfileUzInput,
                                        onValueChange = { lookupProfileUzInput = it },
                                        label = { Text(tr("Введите @юз (напр. @alex)", "Enter @username (e.g. @alex)")) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Button(
                                        onClick = {
                                            val q = lookupProfileUzInput.trim()
                                            if (q.isNotEmpty()) {
                                                bridge.openProfileByUzAsync(q) {
                                                    lookupProfileUzInput = ""
                                                    uiTick++
                                                }
                                            }
                                        },
                                        shape = RoundedCornerShape(10.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(tr("Открыть профиль", "Open profile"))
                                    }
                                }
                            }

                            SectionLabel(tr("Аккаунты", "Accounts"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(12.dp)) {
                                    bridge.accounts.forEachIndexed { idx, slot ->
                                        val isCurrent = idx == bridge.activeAccountIndex
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .clickable {
                                                    bridge.activeAccountIndex = idx
                                                    bridge.saveWorkspaceToPrefs()
                                                    applyStatus(
                                                        tr(
                                                            "Активный профиль: ${bridge.stripUsernameSuffix(slot.displayName)}",
                                                            "Active profile: ${bridge.stripUsernameSuffix(slot.displayName)}"
                                                        )
                                                    )
                                                }
                                                .padding(vertical = 6.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Box(
                                                modifier = Modifier
                                                    .size(8.dp)
                                                    .background(
                                                        if (isCurrent) AegisColors.accent else AegisColors.muted,
                                                        CircleShape
                                                    )
                                            )
                                            Spacer(Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(bridge.stripUsernameSuffix(slot.displayName), color = AegisColors.text, fontSize = 13.sp)
                                            }
                                        }
                                    }
                                    Spacer(Modifier.height(8.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        SmallChoice(tr("+ Новый аккаунт", "+ New account")) {
                                            bridge.logout()
                                            authTabLogin = false
                                            activeScreen = "STEP_1_ACCOUNT"
                                            uiTick++
                                        }
                                        SmallChoice(tr("Выйти из аккаунта", "Log out"), danger = true) {
                                            bridge.logout()
                                            authTabLogin = true
                                            activeScreen = "STEP_1_ACCOUNT"
                                            applyStatus(tr("Вы вышли из аккаунта.", "Signed out of your account."))
                                        }
                                    }
                                }
                            }

                            SectionLabel(tr("Обновления и переключатели", "Updates & Toggles"))
                            Surface(
                                color = AegisColors.panel,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = AegisIcons.Bell,
                                            contentDescription = null,
                                            tint = AegisColors.muted,
                                            modifier = Modifier.size(18.dp)
                                        )
                                        Spacer(Modifier.width(12.dp))
                                        Text(
                                            tr("Пуш-уведомления", "Push notifications"),
                                            color = AegisColors.text,
                                            fontSize = 15.sp,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Switch(
                                            checked = bridge.pushNotificationsEnabled,
                                            onCheckedChange = { enabled ->
                                                bridge.pushNotificationsEnabled = enabled
                                                bridge.saveWorkspaceToPrefs()
                                                applyStatus(
                                                    if (enabled) tr("Пуш-уведомления включены.", "Push notifications enabled.")
                                                    else tr("Пуш-уведомления выключены.", "Push notifications disabled.")
                                                )
                                            }
                                        )
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = AegisIcons.Volume,
                                            contentDescription = null,
                                            tint = AegisColors.muted,
                                            modifier = Modifier.size(18.dp)
                                        )
                                        Spacer(Modifier.width(12.dp))
                                        Text(
                                            tr("Звук уведомлений", "Notification sound"),
                                            color = AegisColors.text,
                                            fontSize = 15.sp,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Switch(
                                            checked = bridge.soundNotificationsEnabled,
                                            onCheckedChange = { enabled ->
                                                bridge.soundNotificationsEnabled = enabled
                                                bridge.saveWorkspaceToPrefs()
                                                uiTick++
                                            }
                                        )
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = AegisIcons.Clock,
                                            contentDescription = null,
                                            tint = AegisColors.muted,
                                            modifier = Modifier.size(18.dp)
                                        )
                                        Spacer(Modifier.width(12.dp))
                                        Text(
                                            tr("Плавные анимации", "Smooth animations"),
                                            color = AegisColors.text,
                                            fontSize = 15.sp,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Switch(
                                            checked = bridge.animationsEnabled,
                                            onCheckedChange = { enabled ->
                                                bridge.animationsEnabled = enabled
                                                bridge.saveWorkspaceToPrefs()
                                                uiTick++
                                            }
                                        )
                                    }
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = AegisIcons.Refresh,
                                            contentDescription = null,
                                            tint = AegisColors.muted,
                                            modifier = Modifier.size(18.dp)
                                        )
                                        Spacer(Modifier.width(12.dp))
                                        Text(
                                            tr("Автоскачивание обновлений", "Auto-download updates"),
                                            color = AegisColors.text,
                                            fontSize = 15.sp,
                                            modifier = Modifier.weight(1f)
                                        )
                                        Switch(
                                            checked = bridge.autoDownloadUpdates,
                                            onCheckedChange = { enabled ->
                                                bridge.autoDownloadUpdates = enabled
                                                bridge.saveWorkspaceToPrefs()
                                                uiTick++
                                            }
                                        )
                                    }
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        SmallChoice(tr("Проверить обновления", "Check updates")) {
                                            bridge.checkForUpdatesAsync(true) { ver ->
                                                applyStatus(
                                                    if (ver != null) tr("Найдена версия v$ver", "Found version v$ver")
                                                    else tr("Установлена актуальная версия", "Up to date")
                                                )
                                            }
                                        }
                                        SmallChoice(tr("Скачать APK", "Download APK")) {
                                            val v = bridge.latestAvailableVersion ?: "0.2.1"
                                            bridge.downloadUpdateApkAsync(v) { path ->
                                                if (path != null) {
                                                    applyStatus(tr("Обновление скачано: $path", "Update downloaded: $path"))
                                                }
                                            }
                                        }
                                    }
                                    Spacer(Modifier.height(8.dp))
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
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(Modifier.padding(12.dp)) {
                                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                        SmallChoice(if (isRu) "English" else "Русский") { toggleLanguage() }
                                        SmallChoice(tr("Серверы", "Servers")) { go("STEP_2_SERVERS") }
                                    }
                                    Spacer(Modifier.height(12.dp))
                                    Button(
                                        onClick = { showPanicConfirm = true },
                                        colors = ButtonDefaults.buttonColors(containerColor = AegisColors.danger),
                                        shape = RoundedCornerShape(12.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(tr("Стереть все данные", "Wipe all data"), fontWeight = FontWeight.Medium)
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
                            Text(tr("Чат не найден", "Chat not found"), color = AegisColors.text, fontSize = 17.sp)
                            TextButton(onClick = { go("STEP_3_CHAT_LIST") }) {
                                Text(tr("Вернуться к чатам", "Back to chats"), color = AegisColors.info)
                            }
                        }
                    } else {
                        val chatSubtitle = when {
                            currentChat.isSavedNotes -> tr("Локальные заметки", "Local notes")
                            bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED ->
                                tr("Сеть заблокирована", "Network locked")
                            currentChat.queueTag.startsWith("group://") -> tr("Группа", "Group")
                            currentChat.queueTag.startsWith("channel://") -> tr("Публичный канал", "Public channel")
                            else -> tr("Личный чат", "Direct chat")
                        }
                        Column(
                            Modifier
                                .fillMaxSize()
                                .imePadding()
                                .background(AegisColors.bg)
                        ) {
                            AppTopBar(
                                title = bridge.stripUsernameSuffix(currentChat.title),
                                subtitle = chatSubtitle,
                                onBack = {
                                    pendingLeakWarning = null
                                    go("STEP_3_CHAT_LIST")
                                },
                                onMenu = {
                                    if (currentChat.queueTag.startsWith("dm://")) {
                                        val (myNick, _) = bridge.activeAccountIdentity()
                                        val peer = currentChat.queueTag.removePrefix("dm://").split(':').firstOrNull { it != myNick } ?: ""
                                        if (peer.isNotEmpty()) {
                                            bridge.openProfileByUzAsync(peer) {
                                                activeScreen = "PROFILE"
                                                uiTick++
                                            }
                                        } else {
                                            showChatMenu = true
                                        }
                                    } else {
                                        showChatMenu = true
                                    }
                                },
                                trailing = {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        PingBadge(
                                            pingMs = if (bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED) null else bridge.lastPingMs,
                                            isRu = isRu,
                                            onClick = {
                                                bridge.syncAllChatsAndInboxAsync { newCount, _ ->
                                                    if (newCount > 0) statusBanner = tr("Новых сообщений: $newCount", "New messages: $newCount")
                                                    uiTick++
                                                }
                                            }
                                        )
                                        Icon(
                                            imageVector = AegisIcons.Refresh,
                                            contentDescription = null,
                                            tint = AegisColors.info,
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
                                                .size(20.dp)
                                        )
                                    }
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
                                            fontWeight = FontWeight.Medium
                                        )
                                        Spacer(Modifier.height(8.dp))
                                        TextButton(onClick = {
                                            bridge.acknowledgeKeyChange(safeIndex)
                                            applyStatus(tr("Новый ключ подтверждён.", "New key approved."))
                                        }) {
                                            Text(tr("Подтвердить", "Approve"), color = AegisColors.warning, fontSize = 13.sp)
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
                                            fontWeight = FontWeight.Medium
                                        )
                                        Text(
                                            warning.maskedPreview,
                                            color = AegisColors.muted,
                                            fontSize = 11.sp,
                                            maxLines = 3,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        Spacer(Modifier.height(8.dp))
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
                                                Text(tr("Скрыть и отправить", "Mask & send"), color = AegisColors.accent, fontSize = 13.sp)
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
                                                Text(tr("Отправить как есть", "Send anyway"), color = AegisColors.danger, fontSize = 13.sp)
                                            }
                                            TextButton(onClick = { pendingLeakWarning = null }) {
                                                Text(tr("Отмена", "Cancel"), color = AegisColors.muted, fontSize = 13.sp)
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
                                    Icon(
                                        imageVector = AegisIcons.Lock,
                                        contentDescription = null,
                                        tint = AegisColors.muted,
                                        modifier = Modifier.size(40.dp)
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    Text(
                                        tr("Чат закрыт", "Chat is locked"),
                                        color = AegisColors.text,
                                        fontSize = 20.sp,
                                        fontWeight = FontWeight.Medium
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
                                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                                    verticalArrangement = Arrangement.spacedBy(2.dp)
                                ) {
                                    items(currentChat.messages) { message ->
                                        MessageBubble(message, isRu = isRu)
                                    }
                                }
                                if (currentChat.queueTag == "channel://owner" && !bridge.isOwnerAccount()) {
                                    Surface(color = AegisColors.panel) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                                            horizontalArrangement = Arrangement.Center,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Icon(
                                                imageVector = AegisIcons.Key,
                                                contentDescription = null,
                                                tint = AegisColors.muted,
                                                modifier = Modifier.size(16.dp)
                                            )
                                            Spacer(Modifier.width(8.dp))
                                            Text(
                                                tr(
                                                    "Канал Owner · писать сообщения может только владелец",
                                                    "Owner Channel · only the Owner can post messages"
                                                ),
                                                color = AegisColors.muted,
                                                fontSize = 13.sp,
                                                textAlign = TextAlign.Center
                                            )
                                        }
                                    }
                                } else ComposerBar(
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
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    PingBadge(
                                        pingMs = if (bridge.shieldState == AegisRustBridge.NetworkShieldState.KILL_SWITCH_BLOCKED) null else bridge.lastPingMs,
                                        isRu = isRu,
                                        onClick = {
                                            bridge.syncAllChatsAndInboxAsync { newCount, _ ->
                                                if (newCount > 0) statusBanner = tr("Новых сообщений: $newCount", "New messages: $newCount")
                                                uiTick++
                                            }
                                        }
                                    )
                                    Icon(
                                        imageVector = AegisIcons.Plus,
                                        contentDescription = null,
                                        tint = AegisColors.accent,
                                        modifier = Modifier
                                            .clickable {
                                                newChatMode = "dm"
                                                showNewChatDialog = true
                                            }
                                            .padding(8.dp)
                                            .size(20.dp)
                                    )
                                }
                            }
                        )
                        UpdateBanner(bridge = bridge, isRu = isRu) { uiTick++ }
                        StatusBanner(statusBanner)
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = {
                                searchQuery = it
                                bridge.searchServerDirectoryAsync(it) { uiTick++ }
                            },
                            placeholder = { Text(tr("Поиск: @юз, группа, канал...", "Search: @username, group, channel...")) },
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
                            SmallChoice(tr("Написать по @юзу", "Message @user")) {
                                newChatMode = "dm"
                                showNewChatDialog = true
                            }
                            SmallChoice(tr("Новая группа", "New group")) {
                                newChatMode = "group"
                                showNewChatDialog = true
                            }
                            SmallChoice(tr("Новый канал", "New channel")) {
                                newChatMode = "channel"
                                showNewChatDialog = true
                            }
                            SmallChoice(if (isRu) "EN" else "RU") { toggleLanguage() }
                        }

                        val filter = searchQuery.trim().lowercase()
                        val cleanFilter = filter.trimStart('@')
                        fun chatMatches(chat: AegisRustBridge.ChatItemUi): Boolean {
                            if (filter.isEmpty()) return true
                            return chat.title.lowercase().contains(filter) ||
                                chat.queueTag.lowercase().contains(cleanFilter) ||
                                (!chat.isLocked && chat.messages.any { it.text.lowercase().contains(filter) })
                        }
                        val dirMatches = if (cleanFilter.isNotEmpty()) {
                            bridge.directoryResults.filter {
                                it.slug.lowercase().contains(cleanFilter) || it.title.lowercase().contains(filter)
                            }
                        } else {
                            emptyList()
                        }

                        LazyColumn(
                            modifier = Modifier.weight(1f),
                            contentPadding = PaddingValues(vertical = 4.dp)
                        ) {
                            if (cleanFilter.isNotEmpty()) {
                                item {
                                    Surface(
                                        color = AegisColors.panel2.copy(alpha = 0.65f),
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                bridge.openProfileByUzAsync(cleanFilter) {
                                                    searchQuery = ""
                                                    activeScreen = "PROFILE"
                                                    uiTick++
                                                }
                                            }
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Avatar(cleanFilter, size = 40.dp)
                                            Spacer(Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    tr("Открыть профиль @$cleanFilter", "Open profile @$cleanFilter"),
                                                    color = AegisColors.info,
                                                    fontSize = 15.sp,
                                                    fontWeight = FontWeight.Medium
                                                )
                                                Text(
                                                    tr("Посмотреть профиль и написать", "View profile and message"),
                                                    color = AegisColors.muted,
                                                    fontSize = 13.sp
                                                )
                                            }
                                        }
                                    }
                                }
                                item {
                                    Surface(
                                        color = AegisColors.panel2.copy(alpha = 0.45f),
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                bridge.openDmChat(cleanFilter).onSuccess { idx ->
                                                    searchQuery = ""
                                                    activeChatIndex = idx
                                                    activeScreen = "STEP_3_CONVERSATION"
                                                    bridge.syncAllChatsAndInboxAsync { _, _ -> uiTick++ }
                                                    uiTick++
                                                }
                                            }
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Avatar(cleanFilter, size = 40.dp)
                                            Spacer(Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    tr("Написать @$cleanFilter", "Message @$cleanFilter"),
                                                    color = AegisColors.accent,
                                                    fontSize = 15.sp,
                                                    fontWeight = FontWeight.Medium
                                                )
                                                Text(
                                                    tr("Открыть личный чат по @юзу", "Open direct chat by @username"),
                                                    color = AegisColors.muted,
                                                    fontSize = 13.sp
                                                )
                                            }
                                        }
                                    }
                                }
                                items(dirMatches) { entry ->
                                    val cleanEntryTitle = bridge.stripUsernameSuffix(entry.title)
                                    val kindIcon = when (entry.kind) {
                                        "group" -> AegisIcons.Users
                                        "channel" -> AegisIcons.Channel
                                        else -> AegisIcons.User
                                    }
                                    val kindLabel = when (entry.kind) {
                                        "group" -> tr("Группа", "Group")
                                        "channel" -> tr("Канал", "Channel")
                                        else -> "${tr("Профиль", "Profile")} · @${entry.slug}"
                                    }
                                    Surface(
                                        color = Color.Transparent,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                if (entry.kind == "user") {
                                                    bridge.openProfileByUzAsync(entry.slug) {
                                                        searchQuery = ""
                                                        activeScreen = "PROFILE"
                                                        uiTick++
                                                    }
                                                } else {
                                                    bridge.openDirectoryItem(entry.kind, entry.slug, cleanEntryTitle).onSuccess { idx ->
                                                        searchQuery = ""
                                                        activeChatIndex = idx
                                                        activeScreen = "STEP_3_CONVERSATION"
                                                        bridge.syncAllChatsAndInboxAsync { _, _ -> uiTick++ }
                                                        uiTick++
                                                    }
                                                }
                                            }
                                    ) {
                                        Row(
                                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Avatar(cleanEntryTitle, size = 40.dp)
                                            Spacer(Modifier.width(12.dp))
                                            Column(modifier = Modifier.weight(1f)) {
                                                Row(verticalAlignment = Alignment.CenterVertically) {
                                                    Icon(
                                                        imageVector = kindIcon,
                                                        contentDescription = null,
                                                        tint = AegisColors.muted,
                                                        modifier = Modifier.size(16.dp)
                                                    )
                                                    Spacer(Modifier.width(8.dp))
                                                    Text(
                                                        cleanEntryTitle,
                                                        color = AegisColors.text,
                                                        fontSize = 15.sp,
                                                        fontWeight = FontWeight.Medium,
                                                        maxLines = 1,
                                                        overflow = TextOverflow.Ellipsis
                                                    )
                                                }
                                                Text(
                                                    kindLabel,
                                                    color = AegisColors.muted,
                                                    fontSize = 13.sp
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                            itemsIndexed(bridge.chats) { actualIndex, chat ->
                                if (!chatMatches(chat)) return@itemsIndexed
                                val cleanChatTitle = bridge.stripUsernameSuffix(chat.title)
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
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .heightIn(min = 64.dp)
                                            .padding(horizontal = 12.dp, vertical = 8.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Avatar(cleanChatTitle, size = 40.dp)
                                        Spacer(Modifier.width(12.dp))
                                        Column(modifier = Modifier.weight(1f)) {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Text(
                                                    cleanChatTitle,
                                                    color = AegisColors.text,
                                                    fontSize = 15.sp,
                                                    fontWeight = FontWeight.Medium,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis,
                                                    modifier = Modifier.weight(1f)
                                                )
                                                if (chat.isLocked) {
                                                    Icon(
                                                        imageVector = AegisIcons.Lock,
                                                        contentDescription = null,
                                                        tint = AegisColors.muted,
                                                        modifier = Modifier.size(14.dp)
                                                    )
                                                }
                                            }
                                            Text(
                                                preview,
                                                color = AegisColors.muted,
                                                fontSize = 13.sp,
                                                maxLines = 1,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }
                                }
                                Box(
                                    Modifier
                                        .fillMaxWidth()
                                        .padding(start = 64.dp)
                                        .height(1.dp)
                                        .background(AegisColors.line)
                                )
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
                    title = {
                        Text(
                            when (newChatMode) {
                                "group" -> tr("Создать группу", "Create group")
                                "channel" -> tr("Создать канал", "Create channel")
                                else -> tr("Написать человеку (@логин)", "New direct message (@username)")
                            }
                        )
                    },
                    text = {
                        Column {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                SmallChoice(tr("Чат", "Chat")) { newChatMode = "dm" }
                                SmallChoice(tr("Группа", "Group")) { newChatMode = "group" }
                                SmallChoice(tr("Канал", "Channel")) { newChatMode = "channel" }
                            }
                            Spacer(Modifier.height(12.dp))
                            when (newChatMode) {
                                "group" -> {
                                    OutlinedTextField(
                                        value = newChatPeerName,
                                        onValueChange = { newChatPeerName = it },
                                        label = { Text(tr("Название группы", "Group name")) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    OutlinedTextField(
                                        value = newChatChannelCode,
                                        onValueChange = { newChatChannelCode = it },
                                        label = { Text(tr("Участники (@user1, @user2)", "Members (@user1, @user2)")) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                                "channel" -> {
                                    OutlinedTextField(
                                        value = newChatPeerName,
                                        onValueChange = { newChatPeerName = it },
                                        label = { Text(tr("Название канала", "Channel title")) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                    Spacer(Modifier.height(8.dp))
                                    OutlinedTextField(
                                        value = newChatChannelCode,
                                        onValueChange = { newChatChannelCode = it },
                                        label = { Text(tr("@тег канала (напр. @news)", "@channel_tag (e.g. @news)")) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                                else -> {
                                    OutlinedTextField(
                                        value = newChatChannelCode,
                                        onValueChange = { newChatChannelCode = it },
                                        label = { Text(tr("@логин собеседника (напр. @alex)", "@username (e.g. @alex)")) },
                                        singleLine = true,
                                        keyboardOptions = incognitoKeyboardOptions,
                                        modifier = Modifier.fillMaxWidth()
                                    )
                                }
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            val res = when (newChatMode) {
                                "group" -> bridge.createGroupEasy(newChatPeerName, newChatChannelCode)
                                "channel" -> bridge.createChannelEasy(newChatPeerName, newChatChannelCode)
                                else -> bridge.openDmChat(newChatChannelCode.ifBlank { newChatPeerName })
                            }
                            res.onSuccess { index ->
                                newChatPeerName = ""
                                newChatChannelCode = ""
                                showNewChatDialog = false
                                activeChatIndex = index
                                activeScreen = "STEP_3_CONVERSATION"
                                bridge.syncAllChatsAndInboxAsync { _, _ -> uiTick++ }
                                applyStatus(tr("Готово.", "Ready."))
                            }.onFailure { error ->
                                applyStatus("${error.message}")
                            }
                        }) { Text(tr("Открыть", "Open")) }
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
                            Text(tr("Стереть", "Wipe"), color = AegisColors.danger, fontWeight = FontWeight.Medium)
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
}

@Composable
private fun WipedScreen(isRu: Boolean, onReset: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = AegisIcons.Shield,
            contentDescription = null,
            tint = AegisColors.accent,
            modifier = Modifier.size(40.dp)
        )
        Spacer(Modifier.height(12.dp))
        Text(
            if (isRu) "Данные удалены" else "Data wiped",
            color = AegisColors.text,
            fontSize = 20.sp,
            fontWeight = FontWeight.Medium
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
        Spacer(Modifier.height(20.dp))
        Button(
            onClick = onReset,
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                if (isRu) "Создать новый профиль" else "Create new profile",
                fontWeight = FontWeight.Medium
            )
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
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun AuthCard(content: @Composable ColumnScope.() -> Unit) {
    Surface(
        color = AegisColors.panel,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            content = content
        )
    }
}

@Composable
private fun UpdateBanner(
    bridge: AegisRustBridge,
    isRu: Boolean,
    onChanged: () -> Unit
) {
    val dlPath = bridge.downloadedUpdatePath
    val availVer = bridge.latestAvailableVersion
    if (dlPath != null) {
        Surface(
            color = AegisColors.accent.copy(alpha = 0.16f),
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, AegisColors.accent.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = AegisIcons.Check,
                    contentDescription = null,
                    tint = AegisColors.accent,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    if (isRu) "Обновление скачано автоматически" else "Update auto-downloaded",
                    color = AegisColors.accent,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.weight(1f)
                )
            }
        }
        return
    }
    if (availVer != null && availVer != AegisRustBridge.APP_VERSION) {
        Surface(
            color = AegisColors.info.copy(alpha = 0.16f),
            shape = RoundedCornerShape(10.dp),
            border = BorderStroke(1.dp, AegisColors.info.copy(alpha = 0.5f)),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = AegisIcons.Download,
                    contentDescription = null,
                    tint = AegisColors.info,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    if (isRu) "Доступно обновление Aegis v$availVer" else "Update Aegis v$availVer available",
                    color = AegisColors.info,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.weight(1f)
                )
                SmallChoice(if (isRu) "Скачать" else "Download") {
                    bridge.downloadUpdateApkAsync(availVer) { onChanged() }
                }
            }
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
    Column(modifier = Modifier.fillMaxWidth().background(AegisColors.panel)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (onBack != null) {
                Icon(
                    imageVector = AegisIcons.ArrowLeft,
                    contentDescription = null,
                    tint = AegisColors.text,
                    modifier = Modifier
                        .clickable { onBack() }
                        .padding(8.dp)
                        .size(20.dp)
                )
            } else {
                Spacer(Modifier.width(4.dp))
                Avatar(title, size = 36.dp)
                Spacer(Modifier.width(12.dp))
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    color = AegisColors.text,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
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
            Icon(
                imageVector = AegisIcons.More,
                contentDescription = null,
                tint = AegisColors.muted,
                modifier = Modifier
                    .clickable(onClick = onMenu)
                    .padding(8.dp)
                    .size(20.dp)
            )
        }
        HorizontalDivider(color = AegisColors.line, thickness = 1.dp)
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
    Column(modifier = Modifier.fillMaxWidth().background(AegisColors.panel)) {
        HorizontalDivider(color = AegisColors.line, thickness = 1.dp)
        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            BottomItem(AegisIcons.Chat, if (isRu) "Чаты" else "Chats", active == "chats", onChats, Modifier.weight(1f))
            BottomItem(AegisIcons.Server, if (isRu) "Серверы" else "Servers", active == "servers", onServers, Modifier.weight(1f))
            BottomItem(AegisIcons.User, if (isRu) "Профиль" else "Profile", active == "profile", onProfile, Modifier.weight(1f))
        }
    }
}

@Composable
private fun BottomItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier
) {
    Column(
        modifier = modifier.clickable(onClick = onClick).padding(vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (selected) AegisColors.accent else AegisColors.muted,
            modifier = Modifier.size(20.dp)
        )
        Spacer(Modifier.height(4.dp))
        Text(
            label,
            color = if (selected) AegisColors.accent else AegisColors.muted,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun Avatar(name: String, size: Dp) {
    Box(
        modifier = Modifier.size(size).background(AegisColors.panel3, CircleShape),
        contentAlignment = Alignment.Center
    ) {
        Text(
            name.trim().firstOrNull()?.uppercase() ?: "A",
            color = AegisColors.muted,
            fontSize = (size.value * 0.34f).sp,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        color = AegisColors.muted,
        fontSize = 11.sp,
        fontWeight = FontWeight.Medium,
        modifier = Modifier.padding(top = 14.dp, bottom = 6.dp)
    )
}

@Composable
private fun PingBadge(pingMs: Int?, isRu: Boolean, onClick: () -> Unit) {
    val dotColor = when {
        pingMs == null -> AegisColors.danger
        pingMs < 180 -> AegisColors.accent
        else -> AegisColors.warning
    }
    val label = when {
        pingMs == null -> if (isRu) "Офлайн" else "Offline"
        isRu -> "$pingMs мс"
        else -> "$pingMs ms"
    }
    Row(
        modifier = Modifier
            .clickable(onClick = onClick)
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(modifier = Modifier.size(6.dp).background(dotColor, CircleShape))
        Spacer(Modifier.width(6.dp))
        Text(label, color = AegisColors.muted, fontSize = 11.sp)
    }
}

@Composable
private fun SmallChoice(
    label: String,
    danger: Boolean = false,
    selected: Boolean = false,
    onClick: () -> Unit
) {
    val tint = when {
        danger -> AegisColors.danger
        selected -> AegisColors.accent
        else -> AegisColors.text
    }
    Surface(
        color = Color.Transparent,
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(
            1.dp,
            when {
                danger -> AegisColors.danger.copy(alpha = 0.5f)
                selected -> AegisColors.accent.copy(alpha = 0.5f)
                else -> AegisColors.line
            }
        ),
        modifier = Modifier.clickable(onClick = onClick)
    ) {
        Text(
            label,
            color = tint,
            fontSize = 13.sp,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
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
                topStart = 10.dp,
                topEnd = 10.dp,
                bottomStart = if (message.outgoing) 10.dp else 4.dp,
                bottomEnd = if (message.outgoing) 4.dp else 10.dp
            ),
            modifier = Modifier.widthIn(max = 320.dp)
        ) {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text(
                    message.text,
                    color = AegisColors.text,
                    fontSize = 15.sp,
                    lineHeight = 21.sp
                )
                message.attachment?.let { attachment ->
                    Spacer(Modifier.height(4.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = AegisIcons.Image,
                            contentDescription = null,
                            tint = AegisColors.muted,
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            attachment.filename,
                            color = AegisColors.muted,
                            fontSize = 11.sp
                        )
                    }
                }
                message.ttlSeconds?.let { ttl ->
                    Spacer(Modifier.height(4.dp))
                    Text(
                        if (isRu) {
                            if (ttl >= 3600) "${ttl / 3600} ч" else if (ttl >= 60) "${ttl / 60} мин" else "${ttl} с"
                        } else {
                            if (ttl >= 3600) "${ttl / 3600} h" else if (ttl >= 60) "${ttl / 60} min" else "${ttl} s"
                        },
                        color = AegisColors.muted,
                        fontSize = 11.sp,
                        textAlign = TextAlign.End,
                        modifier = Modifier.fillMaxWidth()
                    )
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
    Column(modifier = Modifier.fillMaxWidth().background(AegisColors.panel)) {
        HorizontalDivider(color = AegisColors.line, thickness = 1.dp)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            OutlinedTextField(
                value = draft,
                onValueChange = onDraftChange,
                placeholder = { Text(if (isRu) "Сообщение" else "Message", fontSize = 15.sp) },
                maxLines = 4,
                shape = RoundedCornerShape(10.dp),
                modifier = Modifier.weight(1f)
            )
            Box(
                modifier = Modifier
                    .clickable(onClick = onSend)
                    .padding(horizontal = 8.dp, vertical = 8.dp)
            ) {
                Icon(
                    imageVector = AegisIcons.Send,
                    contentDescription = null,
                    tint = AegisColors.accent,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}
