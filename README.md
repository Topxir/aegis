# Aegis

A small end-to-end encrypted messenger for Windows and Android. Accounts are a username and a
password; no phone number or e-mail. Status: **alpha, no external audit.**

[Русский](#русский) · [Protocol](docs/PROTOCOL.md) · [Security](SECURITY.md)

## What it does

- Direct messages, groups and channels, end-to-end encrypted (X25519, Ed25519, ChaCha20-Poly1305,
  HKDF; audited Rust crates, BouncyCastle on Android). Direct chats use X3DH and a Double Ratchet,
  so a stolen device key does not open earlier messages; groups and channels use sender keys
  ([protocol](docs/PROTOCOL.md), sections 27 and 28).
- Sealed transport: the server cannot see who sent a direct message. It stores only encrypted,
  padded frames for a limited time and keeps no IP log. Optional cover traffic.
- Contacts are added by exact username or by a one-time invite link or QR code. The first key
  seen is pinned; a changed key blocks messages until you accept it. Safety numbers let you
  verify a contact in person. A profile can be hidden.
- Photos and videos are sanitized before sending (metadata removed).
- Disappearing messages per chat, app lock with PIN, private notifications, screenshot shield.
- Everything on the device is kept in one file encrypted with a key derived from your password
  (Argon2id). The same file is used to move an account to another device.
- Tor is built in and on by default, with bridge support; an optional SOCKS5 proxy is also
  available. Updates are signed and verified before installing.
- Russian and English interface.

## Current state

The `redesign` branch carries the new black interface and an appearance section in the settings.
In progress: visual effects over the screen (rain, snow) and a photo wallpaper for chats or the
whole interface. These are not finished.

Version 0.3.1: after the app is minimized or the phone is locked, an account with a PIN opens
to the PIN keypad instead of the sign-in tabs. The official Aegis channel accepts posts from
`@owner` only, signed with the owner key built into the app.

Version 0.3.0 delivers messages faster. While the app is open, Android checks for new messages
about every 2.5 s (it was 22–45 s) and Windows every 1.5–3 s (it was 5–10 s). Cover traffic now
averages one request every 6–8 s at the Normal level and 3–4 s at Strong. The release also adds a
new launcher and window icon, richer notifications, a lock when the app is minimized, and the 3D
scene on phones.

## Security review

This is an internal review done by the developers. It is **not** an independent or third-party
audit, and the project has had no external audit.

What was done:

- Two rounds of adversarial review of the core, the relay server and both clients. The findings
  were fixed (commits "Fix audit findings across core, server, desktop and Android" and
  "Close remaining audit gaps"). Examples: replay and proof-of-work window, name rules, limits on
  sender-key chains, memory rollback, requests without a timestamp.
- A later review of the invite, update and Tor changes, with fixes for invite id re-creation,
  unverified names from invites and Tor checks without bridges ("Fix review findings in invites
  and the Tor test").
- Regression tests for fixed issues in `crates/aegis-core/tests/` (`regress_*.rs`, `security.rs`),
  and shared test vectors in [docs/test-vectors.json](docs/test-vectors.json) that the Kotlin
  implementation is checked against.
- Known limits and the reporting channel: [SECURITY.md](SECURITY.md). The protocol, including
  what the server can still see, is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

Some low-risk findings from the last review are still open. Do not rely on Aegis where a
compromise would put someone at risk.

## What it does not do

- The server sees which queue receives messages and when, and the username to key directory.
- With Tor switched off and the default server (`freeoasis.space`), Cloudflare terminates TLS
  and sees your IP address and traffic timing, not message contents. Keep Tor on, or use a proxy
  or your own server.
- No calls and no message history sync between devices.

## Layout

| Path | |
|---|---|
| `crates/aegis-core` | Protocol v2: keys, sealed messages, groups, vault, proof of work, client |
| `crates/aegis-ui-desktop` | Windows client (WebView2) |
| `apps/aegis-android` | Android client (Kotlin, Compose) |
| `builds/` | Prebuilt binaries |

## Building

Rust (Windows): `cargo build --release -p aegis-ui-desktop`, tests:
`cargo test --workspace`.

Android (JDK 17, Android SDK 34): `cd apps/aegis-android && ./gradlew testDebugUnitTest assembleRelease`.
The unit tests check the Kotlin implementation against `docs/test-vectors.json` produced by the
Rust core.

## Server

The relay server is not part of this repository. What a server has to do is specified in
[docs/PROTOCOL.md](docs/PROTOCOL.md). Clients refuse `http://` to anything but loopback and
`.onion`.

## License

AGPL-3.0-or-later.

---

## Русский

Небольшой мессенджер со сквозным шифрованием для Windows и Android. Аккаунт — это ник и пароль,
без телефона и почты. Статус: **альфа, внешнего аудита не было.**

**Что умеет**

- Личные сообщения, группы и каналы со сквозным шифрованием (X25519, Ed25519,
  ChaCha20-Poly1305, HKDF). В личных чатах X3DH и двойной храповик: украденный ключ устройства
  не раскрывает прошлые сообщения; в группах и каналах sender keys
  ([протокол](docs/PROTOCOL.md), разделы 27 и 28).
- Запечатанный транспорт: сервер не знает, кто отправил личное сообщение, хранит только
  зашифрованные кадры одинаковых размеров ограниченное время и не пишет IP-адреса. Есть
  необязательный cover-трафик.
- Контакт добавляется по точному нику или по одноразовой ссылке-приглашению или QR. Первый
  увиденный ключ запоминается; если ключ сменился, сообщения блокируются, пока вы не
  подтвердите. Код безопасности можно сверить лично. Профиль можно скрыть.
- Фото и видео перед отправкой очищаются от метаданных.
- Исчезающие сообщения для каждого чата, блокировка приложения PIN-кодом, приватные
  уведомления, защита от скриншотов.
- Все данные на устройстве — в одном файле, зашифрованном ключом из пароля (Argon2id). Этот же
  файл служит для переноса аккаунта.
- Встроенный Tor (включён по умолчанию, есть мосты), SOCKS5-прокси по желанию. Обновления
  подписаны и проверяются перед установкой.
- Интерфейс на русском и английском.

**Текущее состояние**

В ветке `redesign` новый чёрный интерфейс и раздел настроек внешнего вида. В работе: визуальные
эффекты поверх экрана (дождь, снег) и фото-обои для чатов или всего интерфейса. Это ещё не готово.

В версии 0.3.1 после сворачивания приложения или блокировки телефона аккаунт с PIN-кодом
открывается на клавиатуре PIN, а не на вкладках входа. В официальный канал Aegis может писать
только `@owner`: посты подписаны ключом владельца, вшитым в приложение.

В версии 0.3.0 сообщения доходят быстрее. Пока приложение открыто, Android проверяет новые
сообщения примерно раз в 2,5 с (было 22–45 с), Windows раз в 1,5–3 с (было 5–10 с). Маскирующий
трафик теперь в среднем делает запрос раз в 6–8 с на обычном уровне и раз в 3–4 с на усиленном.
Также новая иконка приложения и окна, более информативные уведомления, блокировка при сворачивании
и 3D-сцена на телефонах.

**Аудит безопасности**

Это внутренняя проверка силами разработчиков. Это **не** независимый и не сторонний аудит;
внешнего аудита проекта не было.

Что сделано:

- Два круга состязательной проверки ядра, сервера и обоих клиентов, найденные проблемы
  исправлены (коммиты «Fix audit findings across core, server, desktop and Android» и «Close
  remaining audit gaps»). Среди них: окно повторов и proof-of-work, правила имён, лимиты цепочек
  sender keys, откат памяти, запросы без времени.
- Последующая проверка приглашений, обновлений и Tor: исправлены повторное создание id
  приглашения, непроверенное имя из приглашения и проверка Tor без мостов («Fix review findings
  in invites and the Tor test»).
- Регрессионные тесты для исправленных проблем в `crates/aegis-core/tests/` (`regress_*.rs`,
  `security.rs`) и общие тестовые векторы [docs/test-vectors.json](docs/test-vectors.json), по
  которым сверяется Kotlin-реализация.
- Известные ограничения и способ сообщить об уязвимости: [SECURITY.md](SECURITY.md). Протокол и
  то, что сервер всё ещё видит: [docs/PROTOCOL.md](docs/PROTOCOL.md).

Часть находок с низким риском последней проверки пока не закрыта. Не полагайтесь на Aegis там,
где компрометация опасна для человека.

**Чего не умеет**

- Сервер видит, в какую очередь и когда приходят сообщения, и каталог «ник → ключ».
- При выключенном Tor и сервере по умолчанию (`freeoasis.space`) TLS заканчивается у
  Cloudflare: он видит ваш IP и время трафика, но не содержимое. Держите Tor включённым или
  используйте прокси или свой сервер.
- Нет звонков и синхронизации истории между устройствами.
