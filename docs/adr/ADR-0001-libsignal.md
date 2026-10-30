# ADR-0001 — libsignal как источник PQXDH, Double Ratchet и XEdDSA

- Статус: **ПРИНЯТО** (выбор библиотеки); способ подключения — **ПРЕДЛОЖЕНО**
- Дата: 2026-10-30
- Компоненты: `aegis-core::crypto`, `aegis-core::protocol`, `aegis-core::identity`
- Связанные решения: `D-0024`, `D-0025`, `D-0026`

## Контекст

1:1-протокол Aegis v2 должен использовать опубликованные PQXDH и Double
Ratchet, а не самописный комбинатор. Пользовательская идентичность —
libsignal XEd25519: один Curve25519 identity key для DH и подписей. Отдельная
пара Ed25519 + X25519 для PQXDH отклонена (`D-0025`), потому что libsignal
PQXDH ожидает именно XEd25519 identity key.

Своя реализация PQXDH/Double Ratchet/XEdDSA запрещена (`AGENTS.md §2.1`).

## Решение

Использовать `libsignal` из репозитория Signal:

- репозиторий: `https://github.com/signalapp/libsignal`;
- тег: `v0.106.1`;
- commit: `904c8dc8216073b078a5f2f5090e3da8382e6a92`;
- дата релиза: 2026-10-28;
- Rust-часть: workspace `rust/` (`libsignal-protocol`, `libsignal-core` и
  зависимости);
- параметр ML-KEM берётся из libsignal; не подменять 768/1024 и не
  смешивать параметры в одном протоколе;
- XEdDSA, PQXDH, Double Ratchet, prekeys и session state — только через
  публичное API libsignal. Свои обёртки не должны менять transcript,
  порядок DH-шагов или формат ключей.

### Способ подключения

Предпочтительно **vendored subtree** в `vendor/libsignal/` на теге
`v0.106.1`:

- commit SHA уже является пином;
- SHA-256 архива исходников фиксируется в `docs/adr/ADR-0001-libsignal.md`
  при вендоринге;
- сборка не зависит от доступности GitHub;
- AGPL-3.0 соблюдается явно.

Допустимая альтернатива — git dependency с `rev = "904c8dc..."` и
`Cargo.lock` в git. Она проще в обновлении, но не даёт checksum исходников.
Окончательный выбор фиксируется в Phase 1 spike после проверки сборки под
Android/Windows. Если vendoring невозможен, это оформляется отдельным
обновлением ADR, а не молчаливой сменой зависимости.

## Почему libsignal

- Это референсная реализация Signal Protocol, используемая в Signal.
- Поддерживает XEd25519, PQXDH, Double Ratchet и prekey bundles.
- Позволяет не писать свой PQXDH-комбинатор и не изобретать формат
  identity key.
- AGPL-3.0 совместим с лицензией проекта AGPL-3.0-or-later.

## Альтернативы

| Вариант | Почему не выбран |
|---|---|
| Своя реализация PQXDH/Double Ratchet | Запрещено `AGENTS.md §2.1`; нет аудита и side-channel гарантий |
| `vodozemac` (Matrix Olm/Megolm) | Другая модель identity и сессий; нет PQXDH в нужном виде |
| `mls-rs` / OpenMLS для 1:1 | MLS предназначен для групп; 1:1 через MLS меняет модель и усложняет multi-device |
| Старый libsignal без PQXDH | Не даёт пост-квантовой защиты; свой PQXDH-клей запрещён |
| `ring`/`aws-lc-rs` напрямую | Примитивы есть, но нет готового PQXDH/Double Ratchet/XEdDSA протокола |

## Лицензия и AGPL

- libsignal: **AGPL-3.0**.
- Aegis: **AGPL-3.0-or-later**.
- Клиентское приложение распространяется под AGPL-3.0; исходники libsignal
  и Aegis доступны. Сетевые серверы Aegis не линкуют libsignal, поэтому
  AGPL network clause не превращает relay/account service в обязанность
  отдавать их исходники сверх уже открытого AGPL-кода.
- Если серверная часть когда-либо начнёт линковать libsignal, это потребует
  отдельного юридического review и, возможно, раскрытия серверного кода.

## Аудит и происхождение

- Публичного полного аудита именно коммита `v0.106.1` не подтверждено.
- libsignal используется Signal; протокол PQXDH/Double Ratchet имеет
  академический анализ и публичные спецификации. Это **не** заменяет
  внешний аудит кода.
- До 1.0 libsignal должен входить в периметр внешнего аудита. До этого
  нельзя называть ядро «audited».
- При пине проверить GitHub Security Advisories и `cargo audit`/OSV для
  Rust-зависимостей libsignal.

## Известные CVE

На 2026-10-30 публичных OSV-записей для выбранного коммита не найдено.
Это не гарантия: перед Phase 1 и при каждом обновлении пина проверять
GitHub Advisories, RustSec/OSV и changelog libsignal.

## Риски и ограничения

| Риск | Смягчение |
|---|---|
| Большой объём и сложная сборка (Rust + FFI + Android) | Phase 1 spike; vendored subtree; отдельная CI-сборка aarch64 |
| AGPL-3.0 | Проект уже AGPL; серверы не линкуют libsignal |
| API/ABI churn | Пин на тег; обновление только через ADR и тесты |
| Скрытые зависимости с C/asm | `cargo deny`, SBOM, аудит зависимостей |
| Нет аудита конкретного коммита | Внешний аудит до 1.0; не заявлять «audited» раньше |
| ML-KEM параметр может измениться | Брать параметр из libsignal; не хардкодить свой |

## План проверки

1. Собрать `libsignal-protocol` под Windows GNU и Android aarch64.
2. Прогнать штатные тесты libsignal и его XEdDSA/PQXDH/Double Ratchet
   векторы.
3. Проверить, что Aegis не добавляет свои поля в transcript и не меняет
   порядок DH-шагов.
4. Проверить, что identity key — XEd25519, а Ed25519 используется только
   для инфраструктурных подписей.
5. Зафиксировать `Cargo.lock`, SHA-256 vendored-архива и SBOM.
6. Провести внутренний red team: MITM, replay, nonce reuse, downgrade,
   malformed prekey bundle.

## Открытые вопросы

1. Vendored subtree или git dependency с `rev`? Решение — в Phase 1 spike.
2. Нужен ли отдельный wrapper-крейт `aegis-libsignal` для ограничения API?
   Предварительно да, чтобы UI/протокол не трогали session state напрямую.
