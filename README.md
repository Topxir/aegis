# Aegis

A small end-to-end encrypted messenger for Windows and Android. Accounts are a username and a
password; no phone number or e-mail. Status: **alpha, not externally audited.**

[Русский](#русский) · [Protocol](docs/PROTOCOL.md) · [Security](SECURITY.md)

## What it does

- Direct messages and groups of up to 20 people, end-to-end encrypted (X25519, Ed25519,
  ChaCha20-Poly1305, HKDF from audited Rust crates and BouncyCastle on Android).
- The server cannot see who sent a direct message; it stores only encrypted, padded frames for
  14 days and keeps no IP log.
- Contacts are added by exact username. The first key seen is pinned; a changed key blocks
  messages until you accept it. Safety numbers let you verify a contact in person.
- Disappearing messages per chat.
- Everything on the device is kept in one file encrypted with a key derived from your password
  (Argon2id). The same file is used to move an account to another device.
- Optional SOCKS5 proxy (for example Tor) with names resolved by the proxy.
- Russian and English interface.

## What it does not do

- No forward secrecy: a stolen device key decrypts previously captured messages.
- The server sees which queue receives messages and when, and the username → key directory.
- With the default server (`freeoasis.space`), Cloudflare terminates TLS and sees your IP address
  and traffic timing, not message contents. Use a proxy or your own server if that matters.
- No calls, attachments or message history sync between devices.

## Layout

| Path | |
|---|---|
| `crates/aegis-core` | Protocol v2: keys, sealed messages, groups, vault, proof of work, client |
| `crates/aegis-server` | Directory and message queues (`aegis-serverd`) |
| `crates/aegis-ui-desktop` | Windows client (WebView2) |
| `apps/aegis-android` | Android client (Kotlin, Compose) |
| `builds/` | Prebuilt binaries and server scripts |

## Building

Rust (Windows): `cargo build --release -p aegis-ui-desktop -p aegis-server`, tests:
`cargo test --workspace`.

Android (JDK 17, Android SDK 34): `cd apps/aegis-android && ./gradlew testDebugUnitTest assembleRelease`.
The unit tests check the Kotlin implementation against `docs/test-vectors.json` produced by the
Rust core.

## Running a server

`aegis-serverd --bind 127.0.0.1 --port 8443 --data-dir <dir> [--blob-quota-mib 4096]`. It speaks plain HTTP and must be
put behind a TLS terminator (Cloudflare Tunnel, Caddy, nginx) if it is reachable from outside;
clients refuse `http://` to anything but loopback and `.onion`. See `builds/server/`.

## License

AGPL-3.0-or-later.

---

## Русский

Небольшой мессенджер со сквозным шифрованием для Windows и Android. Аккаунт — это ник и пароль,
без телефона и почты. Статус: **альфа, внешнего аудита не было.**

**Что умеет**

- Личные сообщения и группы до 20 человек со сквозным шифрованием (X25519, Ed25519,
  ChaCha20-Poly1305, HKDF из проверенных библиотек).
- Сервер не знает, кто отправил личное сообщение; он хранит только зашифрованные кадры
  одинаковых размеров 14 дней и не пишет IP-адреса.
- Контакт добавляется по точному нику. Первый увиденный ключ запоминается; если ключ сменился,
  сообщения блокируются, пока вы не подтвердите. Код безопасности можно сверить лично.
- Исчезающие сообщения для каждого чата.
- Все данные на устройстве — в одном файле, зашифрованном ключом из пароля (Argon2id). Этот же
  файл служит для переноса аккаунта.
- SOCKS5-прокси по желанию (например, Tor), имена разрешает прокси.
- Интерфейс на русском и английском.

**Чего не умеет**

- Нет прямой секретности (forward secrecy): украденный ключ устройства раскрывает ранее
  перехваченные сообщения.
- Сервер видит, в какую очередь и когда приходят сообщения, и каталог «ник → ключ».
- С сервером по умолчанию (`freeoasis.space`) TLS заканчивается у Cloudflare: он видит ваш IP и
  время трафика, но не содержимое. Если это важно — прокси или свой сервер.
- Нет звонков, вложений и синхронизации истории между устройствами.
