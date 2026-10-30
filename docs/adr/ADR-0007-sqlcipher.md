# ADR-0007 — SQLCipher через rusqlite для локальной БД

- Статус: **ПРИНЯТО**
- Дата: 2026-10-30
- Компонент: `aegis-core::storage`
- Связанные решения: `D-0024`, `D-0026`

## Контекст

Локальная БД хранит сообщения, контакты, group state и настройки. Она
должна быть зашифрована at rest, ключ — в Android Keystore/StrongBox или
OS keyring. Прототип использовал самописный формат и AEAD; для v2 нужен
проверенный SQL-движок с шифрованием.

## Решение

Использовать SQLCipher через `rusqlite`:

- `rusqlite 0.41.1` (MIT, MSRV 1.89);
- `libsqlite3-sys 0.39.0`;
- `sqlcipher-src 419.0.6` = SQLCipher **4.19.0**, SQLite **3.53.4**,
  libtomcrypt **1.18.2**;
- SQLCipher: BSD-3-Clause; `sqlcipher-src`: MIT AND BSD-3-Clause AND
  blessing AND WTFPL (permissive; проверить юридически перед релизом);
- feature `bundled-sqlcipher-vendored-openssl` для воспроизводимой сборки
  на Windows/Desktop;
- на Android проверить `bundled-sqlcipher` (libtomcrypt) и размер APK;
  выбор фиксируется в Phase 1 spike;
- ключ БД: 32 случайных байта из OS CSPRNG, хранится в Keystore/keyring,
  не выводится из пароля;
- SQLCipher открывается raw key (`PRAGMA key = "x'...'"`), без пароля в
  строке и без логов;
- `PRAGMA cipher_memory_security = ON`;
- `PRAGMA cipher_page_size = 4096`;
- `PRAGMA foreign_keys = ON`;
- миграции — версионированные, с проверкой `schema_version`;
- wipe — удаление файла БД + `cipher_wipe`/перезапись ключа; для SSD
  честно документировать residual risk.

## Почему SQLCipher

- Зрелый SQL-движок с шифрованием страниц.
- `rusqlite` — безопасная Rust-обёртка, широко используется.
- Позволяет не писать свой формат БД и AEAD-слой.
- Лицензии совместимы с AGPL-3.0-or-later.

## Альтернативы

| Вариант | Почему не выбран |
|---|---|
| SQLite + свой слой шифрования | Самописная криптография/формат; запрещено |
| `redb`/`sled` | Нет SQL/зрелой экосистемы; меньше проверены |
| `libsql` | Новее, меньше истории; SQLCipher более проверен |
| Plain SQLite | Нет encryption at rest |

## Лицензия и AGPL

- `rusqlite`: MIT.
- SQLCipher: BSD-3-Clause.
- `sqlcipher-src`: MIT AND BSD-3-Clause AND blessing AND WTFPL.
- Все permissive; совместимы с AGPL-3.0-or-later. Сохранить
  `THIRD_PARTY_LICENSES` и уведомления SQLCipher/SQLite/libtomcrypt/OpenSSL.

## Аудит и происхождение

- SQLCipher используется широко; публичный аудит конкретной версии 4.19.0
  не подтверждён.
- `rusqlite` — обёртка, не криптография; аудит SQLCipher и выбранного
  crypto provider обязателен.
- Внешний аудит схемы, key management и wipe — до 1.0.
- При пине проверить OSV/RustSec и SQLCipher advisories.

## Известные CVE

На 2026-10-30 OSV не возвращает известных уязвимостей для
`rusqlite 0.41.1`. Для SQLCipher 4.19.0 проверить отдельно (OSV не всегда
покрывает C-компоненты). При каждом обновлении — changelog SQLCipher.

## Риски и ограничения

| Риск | Смягчение |
|---|---|
| Ключ БД в памяти | Keystore/keyring; zeroize; запрет логов |
| SQLCipher C-код/OpenSSL | Пин; SBOM; аудит; обновления |
| Wipe на SSD не гарантирован | Документировать residual risk; crypto-erase ключа |
| Миграции ломают данные | Версионирование; тесты; backup только явный экспорт |
| Размер APK | Замер; выбрать libtomcrypt/OpenSSL вариант |
| Нет аудита версии | Внешний аудит до 1.0 |

## План проверки

1. Открыть/закрыть БД с raw key; неверный ключ → отказ.
2. Проверить, что файл БД не читается без ключа.
3. Миграции с/без данных; откат.
4. Wipe: ключ уничтожен, БД не открывается.
5. Проверить отсутствие ключа/plaintext в логах и дампах.
6. Сборка Android/Windows; замер размера.
7. Фаззинг парсеров миграций/импорта.

## Открытые вопросы

1. `bundled-sqlcipher` (libtomcrypt) или
   `bundled-sqlcipher-vendored-openssl`? Решение после сборки.
2. Нужен ли отдельный ключ на каждую БД/профиль? Предварительно да, для
   multi-account.
