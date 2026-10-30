# ADR — Architecture Decision Records

Статус: ведутся с 2026-10-30 после утверждения security reset rev.2
(`D-0026`). ADR фиксируют решения по зависимостям и протоколу до написания
кода. ADR не заменяет внешний аудит.

## Правила

- Один ADR — одно решение.
- Статусы: `ПРИНЯТО` · `ПРЕДЛОЖЕНО` · `ОТКЛОНЕНО`.
- Для каждой зависимости обязательны: зачем, лицензия, аудит/происхождение,
  альтернативы, версия и пин (commit/hash), известные CVE, риски, план
  обновления.
- Версия в ADR — кандидат на пин. Окончательный пин фиксируется в
  `Cargo.toml`/`Cargo.lock` и проверяется в Phase 1 spike. Смена пина —
  обновление ADR, а не молчаливый `cargo update`.
- `ПРИНЯТО` означает выбор библиотеки, а не заявление «библиотека
  безопасна». Публичный аудит конкретной версии проверяется отдельно.
- Новые зависимости без ADR не добавляются (`AGENTS.md §2.8`).

## Индекс

| ID | Решение | Статус | Кандидат на пин |
|---|---|---|---|
| [ADR-0001](ADR-0001-libsignal.md) | libsignal: PQXDH, Double Ratchet, XEdDSA | ПРИНЯТО | `v0.106.1`, commit `904c8dc8216073b078a5f2f5090e3da8382e6a92` |
| [ADR-0002](ADR-0002-openmls.md) | OpenMLS для групп MLS | ПРИНЯТО | `openmls 0.9.2` |
| [ADR-0003](ADR-0003-rustls.md) | rustls для TLS 1.3 | ПРИНЯТО | `rustls 0.23.46` |
| [ADR-0004](ADR-0004-arti-client.md) | arti-client для встроенного Tor | ПРИНЯТО | `arti-client 0.47.0` |
| [ADR-0005](ADR-0005-opaque-ke.md) | opaque-ke для OPAQUE RFC 9807 | ПРИНЯТО | `opaque-ke 4.0.1` |
| [ADR-0006](ADR-0006-argon2.md) | Argon2id для OPAQUE/экспорта | ПРИНЯТО | `argon2 0.6.0` |
| [ADR-0007](ADR-0007-sqlcipher.md) | SQLCipher через rusqlite | ПРИНЯТО | `rusqlite 0.41.1`, SQLCipher 4.19.0 |
| [ADR-0008](ADR-0008-ohttp.md) | OHTTP RFC 9458 | ПРИНЯТО | `ohttp 0.8.0` |
| [ADR-0009](ADR-0009-voprf.md) | VOPRF RFC 9497 для blind tokens | ПРИНЯТО | `voprf 0.5.0` |
| [ADR-0010](ADR-0010-ed25519-dalek.md) | Ed25519 только для инфраструктуры | ПРИНЯТО | `ed25519-dalek 3.0.0` |

## Toolchain

Максимальный MSRV среди кандидатов — **1.92** (`arti-client 0.47.0`).
Зафиксировать Rust toolchain в `rust-toolchain.toml` и CI; обновление —
через ADR/PR, а не «последний stable» молча.

## Что ещё не решено

- libsignal: vendored subtree или git dependency с `rev` (см. ADR-0001).
- Криптопровайдер rustls: `ring` или `aws-lc-rs` (см. ADR-0003).
- Точные параметры Argon2id после замеров на слабом Android (см. ADR-0006).
- Вариант сборки SQLCipher под Windows/Android (см. ADR-0007).
- Ciphersuite VOPRF (см. ADR-0009).

Эти вопросы не блокируют утверждение плана, но должны быть закрыты до
соответствующей Phase 1/2/4 задачи.
