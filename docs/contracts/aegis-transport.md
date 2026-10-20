# Контракт: aegis-transport
Версия контракта: 0.1

## Ответственность
Управляет защищёнными сетевыми соединениями клиент↔сервер и сетевой анонимностью клиента (PLAN.md §6.4, §7.3, §8, D-0007, D-0008):
- Постоянные мультиплексированные соединения `TLS 1.3` / `QUIC` со строгим пиннингом публичного ключа сервера (`ServerKeyPin`);
- Встроенный модуль **`Network Anonymity Shield`**:
  - Маршрутизация через `Tor` (`Arti` / Orbot / `.onion`), `SOCKS5`-прокси или системный `VPN`;
  - Локальная диагностика маршрута и сверка публичного выходного узла через зашифрованный эхо-ответ целевого сервера Aegis (**без обращения к сторонним IP-чекерам**);
  - Индикация текущего статуса защиты (`TorOnion`, `VpnOrProxy`, `DirectExposedWarning`);
  - Режим **Kill Switch** (мгновенная блокировка сокетов при падении VPN/прокси/Tor и защита от DNS-утечек);
- Прозрачное решение адаптивных пазлов **`BLAKE3 Proof-of-Work`** при получении ответа `PowRequired` от сервера;
- Разделение транспортных каналов: запросы к анонимным очередям никогда не мультиплексируются в один аутентифицированный контекст с запросами `OPAQUE AccountVault` (при использовании Tor — разные изолированные цепочки `StreamIsolation`).

## Публичное API (функции, типы, ошибки)

### Типы
- `RoutePrivacyLevel`:
  - `TorOnion` — 🔒 соединение через Tor или к `.onion`-адресу;
  - `VpnOrProxy` — 🛡 активен туннель VPN или SOCKS5-прокси, реальный IP скрыт;
  - `DirectExposedWarning` — ⚠ прямое соединение, внешний IP виден серверу.
- `NetworkShieldStatus { privacy_level: RoutePrivacyLevel, kill_switch_enabled: bool, dns_leak_protected: bool, relay_only_calls_enforced: bool, route_summary: String }`
- `TransportConfig { proxy_mode: ProxyMode, kill_switch: bool, pinned_server_keys: Vec<ServerKeyPin>, connect_timeout_ms: u64 }`
- `IsolatedCircuitTag` — метка изоляции потока (`VaultSyncCircuit`, `QueueReadCircuit([u8; 16])`, `DirectWriteCircuit([u8; 16])`).

### Основные функции
- `init_transport(config: TransportConfig) -> Result<TransportHandle, TransportError>`
- `inspect_network_shield(handle: &TransportHandle, target_server: &str) -> Result<NetworkShieldStatus, TransportError>`
- `send_direct_queue_packet(handle: &TransportHandle, queue_addr: &QueueAddress, envelope: &SealedEnvelope, pow: Option<PowSolution>) -> Result<DeliveryAck, TransportError>`
- `subscribe_unidirectional_queue(handle: &TransportHandle, queue_id: &[u8; 32], read_auth_sig: &Ed25519Signature) -> Result<QueueStream, TransportError>`
- `sync_opaque_vault(handle: &TransportHandle, server: &str, req: &OpaqueSyncRequest) -> Result<OpaqueSyncResponse, TransportError>`

### Ошибки (`TransportError`)
- `KillSwitchEngaged` — прокси или VPN-туннель недоступен; прямой выход в сеть заблокирован политикой Kill Switch.
- `ServerKeyPinMismatch` — публичный ключ TLS/QUIC сервера не совпадает с ожидаемым пином из `aegis-directory` или инвайта (**Fail Closed**).
- `PowChallengeRequired(PowChallenge)` — сервер запросил решение пазла Anti-DDoS повышенной сложности.
- `ProxyConnectionFailed` / `TorBootstrapFailed` — не удалось установить соединение с локальным/встроенным прокси или сетью Tor.
- `TimeoutOrDisconnected` — обрыв связи (инициируется экспоненциальный backoff с джиттером).

## Гарантии
1. **Никаких сторонних сетевых запросов (AGENTS.md §2 п.2, D-0008):** `inspect_network_shield` проверяет IP/маршрут исключительно через локальные интерфейсы ОС и зашифрованный эхо-ответ выбранного сервера Aegis. Ни один пакет не уходит на сторонние серверы (`google`, `cloudflare`, `ipify`).
2. **Строгий Kill Switch и защита DNS:** если пользователь включил режим `Tor` или `SOCKS5` с `kill_switch = true`, ни один байт (включая DNS-запросы A/AAAA) не отправляется через системный прямой интерфейс при обрыве туннеля.
3. **Изоляция метаданных соединения:** отправка сообщений в чужую очередь (`DirectWriteCircuit`) и синхронизация своего `AccountVault` (`VaultSyncCircuit`) используют раздельные криптографические сессии и разные изолированные потоки Tor, чтобы сервер не мог связать `login_id` с отправляемыми сообщениями.

## Запрещено вызывающему
- Запрещено отключать проверку `ServerKeyPin` (флагов вида `accept_invalid_certs` в публичном API не существует).
- Запрещено выполнять прямые HTTP/TCP-запросы из UI или других модулей в обход `aegis-transport`.

## Зависимости
- Внутренние модули: `aegis-crypto`, `aegis-protocol`.

## История изменений
- `0.1` (2026-10-20, T-0002): Первичная спецификация контракта.
