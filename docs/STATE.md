# Состояние проекта

Обновляется после каждой задачи. Легенда: ✅ готово · 🔧 в работе · ❌ не начато · ⚠ проблема

Текущая фаза: **8. Финальный харденинг, стартовые анонимные серверы со статическим IP (без обязательного Tor), релизные сборки `builds/` (Android APK / Desktop / Server) и публикация в GitHub (Фазы 0–8 полностью завершены ✅)**
Обновлено: 2026-10-22

| Модуль | Статус | Заметки |
|---|---|---|
| aegis-crypto | ✅ | SHA-256, HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305 AEAD (RFC 8439), гибридный PQXDH, `RatchetSession` (`MAX_SKIPPED_KEYS = 64`), `solve_pow`; исправлены `B-0011`, `B-0020`, `B-0032`..`B-0034`, `B-0056` |
| aegis-identity | ✅ | OPAQUE (`derive_login_id`, `OpaqueAccountEnvelope`, `OpaqueClientSession`), строгие пароли D-0006, 24 слова (`RecoveryPhrase`), мультиаккаунт 3+`SupporterPass` D-0010, `PinGuard` + Duress, `AppDisguiseConfig`, `ChatPinLock`; исправлены `B-0007`..`B-0010`, `B-0021`, `B-0035`..`B-0038`, `B-0057` |
| aegis-storage | ✅ | `EncryptedVaultDb` (AEAD KV, контакты, исчезающие сообщения, `get_messages_for_chat`, локальный поиск, заметки «Избранное», экспорт/импорт `AEGISBAK`, `crypto_wipe`); исправлены `B-0012`, `B-0022`, `B-0039`, `B-0040`, `B-0058` |
| aegis-protocol | ✅ | Паддинг `PADDING_BUCKETS`, `LeakGuard` (Luhn + CVV/MM/YY + телефоны + email + свой ник), очистка EXIF/GPS (`strip_media_metadata`), `ViewOncePayload`, `ContactInvite`, 60-значный Safety Number, `GroupChatSession` (MLS эпохи); исправлены `B-0001`..`B-0006`, `B-0023`, `B-0024`, `B-0041`..`B-0043`, `B-0059` |
| aegis-transport | ✅ | `Network Anonymity Shield`, прямой стартовый профиль `ProxyConfig::direct_starter` и `format_static_ipv4_endpoint` (D-0019), Kill Switch D-0008, `CoverTrafficScheduler` (256 B dummy-пакеты), профили Tor/SOCKS5/ObfuscatedBridge, живая миграция сервера; исправлены `B-0013`, `B-0044`, `B-0045`, `B-0060` |
| aegis-calls | ✅ | `CallConfig` (принудительный `relay_only` TURN + SFrame E2EE), анонимайзер голоса `anonymize_audio_pcm16` (`VoicePitchMode`), адаптивный битрейт `adapt_call_bitrate`, `filter_ice_candidate` (с фильтрацией утечек `raddr`/`rport`); исправлены `B-0014`, `B-0046`, `B-0047`, `B-0061` |
| aegis-server | ✅ | Zero-knowledge сервер федерации (`FederationServerState`, constant-shape OPAQUE 1024 B, 1-клик удаление спам-очередей, глобальные квоты памяти), демон `aegis-serverd --bind=0.0.0.0 --port=8443` и веб-портал поддержки/донатов (`SupportPortalState`); исправлены `B-0015`, `B-0025`, `B-0048`, `B-0049`, `B-0064` |
| aegis-directory | ✅ | Встроенный каталог серверов `BuiltInDirectory` со стартовыми статическими IPv4 узлами без обязательного Tor (`185.220.101.42:8443 ✓✓`, `91.108.56.110:8443 ✓✓`, `193.163.125.18:8443 ✓`, `direct_static_ip_entries`, D-0019) и опциональным `.onion`, `SupportCertificate`, пороговая схема `M-of-N`; исправлены `B-0016`, `B-0026`, `B-0062` |
| aegis-launcher | ✅ | Мастер запуска своего сервера в 1 клик (`generate_static_ip_vps_script`, `generate_docker_compose`, `generate_cloud_init_script`, `generate_torrc_hidden_service`, `format_server_invite_uri`); исправлены `B-0017`, `B-0027`, `B-0063` |
| aegis-plugins | ✅ | Магазин тем (`BuiltInThemes`, `ThemePack`, включая `CalculatorStealth`), песочница ботов и мостов Matrix/XMPP (`BotBridgeDescriptor`), защита от эксфильтрации и SSRF; исправлены `B-0018`, `B-0028`, `B-0065` |
| aegis-ffi | ✅ | Единый фасад `AegisClientCore` (`direct_static_ip_servers`) + C-ABI/JNI точки входа для Android и Desktop UI (`RU`/`EN`); исправлены `B-0019`, `B-0029` |
| aegis-ui-android | ✅ | Android-клиент и готовые подписанные APK (`builds/android-apk/aegis-messenger-release.apk`, `aegis-messenger-debug.apk`, стартовые Static-IP серверы без обязательного Tor + 1-клик свой Static IP, `FLAG_SECURE`, StrongBox Keystore); исправлены `B-0031`, `B-0052`..`B-0055`, `B-0067` |
| aegis-ui-desktop | ✅ | Кроссплатформенный Desktop-клиент (`builds/desktop/aegis-desktop.exe`, интерактивный GUI `http://127.0.0.1:7878` со стартовыми Static-IP серверами без Tor и переключением IP в 1 клик); исправлены `B-0030`, `B-0050`, `B-0051`, `B-0066` |

## Сделано
- План и AGENTS.md созданы
- Утверждены архитектурные решения `D-0001`..`D-0020` в `docs/DECISIONS.md` и закрыты все вопросы владельцу (`Q-1`..`Q-11` в `docs/QUESTIONS.md`)
- ✅ Выполнены задачи **T-0001..T-0010** (Фазы 0–7)
- ✅ Выполнена задача **T-0011** (Фаза 8):
  - Настроены стартовые анонимные серверы со статическими IP-адресами (`185.220.101.42:8443 ✓✓`, `91.108.56.110:8443 ✓✓`, `193.163.125.18:8443 ✓`) с прямым подключением без обязательного Tor (`D-0019`), переключением в 1 клик и вводом любого кастомного статического IP, плюс 1-клик авто-установщик для любого VPS (`builds/server/deploy-static-ip-vps.sh`).
  - Проведён финальный аудит Фазы 8 роем параллельных агентов: выявлены, задокументированы в `docs/BUGS.md` (`B-0056`..`B-0067`), исправлены и покрыты регрессионными тестами ещё 12 находок (всего 67 закрытых багов, 88 автотестов в workspace).
  - Собраны готовые релизные билды в отдельную папку `builds/`:
    - `builds/android-apk/aegis-messenger-release.apk` и `builds/android-apk/aegis-messenger-debug.apk`
    - `builds/desktop/aegis-desktop.exe` (+ `run-desktop-gui.bat`, `run-self-test.bat`)
    - `builds/server/aegis-serverd.exe` (+ `run-static-ip-server.bat`, `deploy-static-ip-vps.sh`, `docker-compose.yml`, `cloud-init.yaml`, `starter-servers.json`)
  - Добавлен GitHub Actions workflow `.github/workflows/release-apk.yml` для автоматической сборки APK и бинарников на GitHub.

## В работе
- Нет активных задач (Фазы 0–8 полностью завершены, собраны в `builds/` и отправлены в GitHub)

## Блокеры
- Нет активных блокеров
