# ADR-0010 — ed25519-dalek только для инфраструктурных подписей

- Статус: **ПРИНЯТО**
- Дата: 2026-10-30
- Компоненты: `aegis-directory`, `aegis-account`, `aegis-relay`,
  `aegis-core::identity` (только проверка инфраструктурных подписей)
- Связанные решения: `D-0024`, `D-0025`, `D-0026`

## Контекст

Пользовательская идентичность — libsignal XEd25519 (Curve25519 + XEdDSA).
Ed25519 нельзя использовать для PQXDH identity key или сообщений: это
создало бы несовместимость с libsignal и потребовало бы самописного
клея. Но инфраструктуре нужны подписи: directory descriptors, account
service descriptors, release manifests, relay config.

## Решение

Использовать `ed25519-dalek` **только** для инфраструктурных подписей:

- crate: `ed25519-dalek`;
- версия: `3.0.0`;
- лицензия: BSD-3-Clause;
- MSRV: 1.85;
- репозиторий: `https://github.com/dalek-cryptography/curve25519-dalek`;
- strict verification (`verify_strict`), отказ при small-order/malleability;
- `zeroize` feature для ключей;
- доменное разделение: каждый тип подписи имеет свой context/prefix;
- M-of-N для directory; ключи ротации и revocation;
- **не использовать** для: identity key пользователя, PQXDH, Double
  Ratchet, сообщений, invite-подписи устройства (там XEdDSA).

## Почему ed25519-dalek

- Чистый Rust, широко используется.
- Strict verification.
- BSD-3-Clause совместим с AGPL-3.0-or-later.
- Не тянет C/asm, проще сборка на Android/Windows.

## Альтернативы

| Вариант | Почему не выбран |
|---|---|
| `ed25519-compact` | Меньше экосистема; допустимая альтернатива |
| `ring`/`aws-lc-rs` | C/asm; уже могут быть провайдером TLS, но для инфраструктурных подписей dalek проще |
| libsignal XEdDSA для инфраструктуры | Смешивает пользовательскую и инфраструктурную идентичность; не нужно |
| Своя Ed25519 | Запрещено |

## Лицензия и AGPL

BSD-3-Clause. Совместимо с AGPL-3.0-or-later. Сохранить уведомления
dalek/curve25519-dalek.

## Аудит и происхождение

- Публичный аудит конкретной версии `3.0.0` не подтверждён.
- `curve25519-dalek` широко используется; strict verification важно.
- Внешний аудит key management/revocation — до 1.0.
- При пине проверить OSV/RustSec.

## Известные CVE

На 2026-10-30 OSV не возвращает известных уязвимостей для
`ed25519-dalek 3.0.0`. Проверять при каждом обновлении.

## Риски и ограничения

| Риск | Смягчение |
|---|---|
| Смешение с пользовательской identity | Явный запрет в API/контракте; тесты |
| Malleability | `verify_strict`; тесты |
| Компрометация инфраструктурного ключа | Offline root; M-of-N; rotation/revocation |
| Ключ в памяти | `zeroize`; запрет логов |
| Нет аудита версии | Внешний аудит до 1.0 |

## План проверки

1. RFC 8032 test vectors.
2. Strict verification: malleable/small-order signature → отказ.
3. M-of-N descriptor: порог, ротация, отзыв.
4. Проверить, что identity/PQXDH не используют Ed25519.
5. Проверить, что ключи не попадают в логи.

## Открытые вопросы

1. Формат descriptor: JSON + canonical encoding или protobuf? Решение —
   в Phase 1/2; подпись считается по каноническим байтам.
2. Нужен ли threshold-подписант (FROST) или M-of-N независимых подписей?
   Предварительно M-of-N независимых Ed25519 подписей; FROST — после
   отдельного ADR.
