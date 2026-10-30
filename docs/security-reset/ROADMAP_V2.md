# Aegis Roadmap v2 — соло, без бюджета (APPROVED rev.2)

**Статус: УТВЕРЖДЕНО владельцем 2026-10-30. Дата: 2026-10-30.**

Честная оценка: соло-разработчик без бюджета может сделать сильный
open-source прототип и пройти внутренний аудит. Называть его «самым
защищённым в мире» до внешнего аудита нельзя. Сроки ниже — ориентир, а не
обещание.

Ревизия 2: public alpha после внутреннего red team; внешний аудит — до 1.0;
P2P после MVP; группы ≤ 20; OPAQUE opt-in; только явный экспорт.

## Phase 0 — документы и решения (2–4 недели)

**Цель:** зафиксировать модель угроз, протокол, архитектуру и зависимости.
Код не пишем.

- [x] Утвердить `THREAT_MODEL_V2.md`, `PROTOCOL_V2.md`,
      `ARCHITECTURE_V2.md`, `ROADMAP_V2.md` (2026-10-30).
- [x] ADR на каждую зависимость: libsignal, OpenMLS, rustls, arti,
      opaque-ke, argon2, sqlcipher, ohttp, voprf, ed25519-dalek (инфра).
- [x] Проверить лицензии и совместимость с AGPL; зафиксировать commit/hash
      libsignal (кандидат `v0.106.1`, `904c8dc...`).
- [ ] Решить: libsignal vendored или git dependency.
- [x] Решить: ML-KEM параметр — брать из libsignal, не подменять.
- [ ] Решить: стабильный inbox ID или per-contact.
- [ ] Решить: формат Android push (UnifiedPush/ntfy/WebSocket).
- [ ] Решить: оператор account service и OHTTP gateway.
- [x] Создать ветку `security/t0017-plan` только с документами.
- [x] Обновить `STATE.md`, `DECISIONS.md`, `QUESTIONS.md`.
- [ ] Начать заявки на грант (NLnet/OTF/Prototype Fund), не дожидаясь кода.

**Выход:** владелец утвердил документы; нет открытых критических вопросов.

## Phase 1 — аудированное ядро 1:1 (8–12 недель)

**Цель:** два CLI-клиента обмениваются 1:1 текстом; сервер не видит
открытый текст и отправителя.

- [ ] `aegis-core` skeleton; `#![forbid(unsafe_code)]`.
- [ ] Identity: seed, BIP-39, `AIK`/`DIK` libsignal XEdDSA, ML-KEM,
      invite v2, safety number.
- [ ] PQXDH + Double Ratchet через libsignal; никакого своего комбинатора.
- [ ] Blind envelope + padding; sender cert; routing binding.
- [ ] Inbox: `inbox_id = H(read_token)`; no registration; read auth.
- [ ] SQLCipher storage; key hierarchy; duress wipe.
- [ ] CLI: invite, send, receive, verify.
- [ ] RFC/NIST vectors; libsignal vectors; property tests; fuzzing парсеров.
- [ ] `cargo deny`, `cargo audit`, `cargo vet`; SBOM.
- [ ] Внутренний red-team: MITM, replay, nonce reuse, downgrade, malformed
      input.

**Выход:** E2E 1:1 текст; нет самописных примитивов; тесты зелёные.

## Phase 2 — транспорт, доставка и opt-in OPAQUE (8–12 недель)

**Цель:** 1:1 текст + файл через Tor/OHTTP и 2–3 relay; опциональное
восстановление через OPAQUE.

- [ ] `rustls` TLS 1.3; pinning; никакого plain HTTP.
- [ ] `arti-client` встроенный Tor; профилирование батареи на Android.
- [ ] OHTTP gateway + relay endpoint.
- [ ] Blind tokens (VOPRF) + PoW (min 16 bits); TTL; RAM-only; no logs.
- [ ] Blob store: XChaCha20-Poly1305, chunks, padding, 3 replicas.
- [ ] Federation: 2–3 relay; descriptor signatures; failover.
- [ ] Account service: OPAQUE RFC 9807 + Argon2id; encrypted seed-backup;
      signed device list; отдельно от relay.
- [ ] Seed-only режим работает без account service.
- [ ] E2E тест: текст + файл между двумя CLI через Tor.
- [ ] Тест: relay не видит sender/content; логи пустые; account service не
      видит seed/сообщения.

**Выход:** E2E текст + файл; relay слепой; Tor по умолчанию; OPAQUE opt-in.

## Phase 3 — Android/Desktop MVP (8–12 недель)

**Цель:** обычный пользователь ставит APK/desktop, сканирует QR, пишет
1:1 и отправляет файлы.

- [ ] `aegis-ffi` UniFFI; Kotlin/Swift bindings.
- [ ] Android Compose UI: onboarding, QR, chats, files, settings.
- [ ] Desktop native GUI (slint/iced/egui; без webview).
- [ ] Keystore/StrongBox; OS keyring; auto-lock; FLAG_SECURE.
- [ ] UnifiedPush/ntfy через Tor; generic payload; topic rotation.
- [ ] Duress PIN, panic wipe.
- [ ] **Только явный зашифрованный экспорт**; автоматического cloud backup
      нет. OPAQUE seed-backup — не история чата.
- [ ] 7-дневный soak test на реальных устройствах.
- [ ] Сборка release APK/exe; checksums; reproducible build script.

**Выход:** MVP 1:1 + файлы; стабильно 7 дней; нет утечек в логи.

## Phase 4 — группы beta и multi-device (8–12 недель)

**Цель:** группы ≤ 20 через MLS; несколько устройств.

- [ ] `openmls`; group create/add/remove/epoch.
- [ ] Pairwise wrap для сокрытия группы от relay.
- [ ] Group files.
- [ ] Device list, подписанный `AIK`; encrypt-to-device.
- [ ] OPAQUE device list sync (opt-in).
- [ ] Key change warnings; safety number для устройств.
- [ ] Фаззинг; формальный анализ; внутренний red team.
- [ ] Beta с ограниченным кругом.

**Выход:** группы beta; multi-device; известные ограничения описаны.

## Phase 5 — внутренний red team и public alpha (4–8 недель)

**Цель:** публичный alpha после внутреннего аудита, без ложных заявлений.

- [ ] Формальный анализ протокола (ProVerif/Tamarin).
- [ ] Внутренний red team: крипто, протокол, клиент, сервер, supply chain.
- [ ] Закрыть critical/high.
- [ ] Reproducible builds; независимый сборщик; binary transparency.
- [ ] SBOM, `cargo vet`, подписанные релизы.
- [ ] Public alpha с честным статусом «unaudited/alpha».
- [ ] iOS — после стабилизации ядра.
- [ ] Не заявлять «secure» до внешнего аудита.

**Выход:** внутренний аудит опубликован; critical/high закрыты; public
alpha с меткой «unaudited».

## Phase 6 — внешний аудит и 1.0 (после финансирования)

**Цель:** независимый аудит и стабильный релиз.

- [ ] Найти финансирование: NLnet, OTF, Prototype Fund, GitHub Sponsors.
- [ ] Внешний аудит криптографии/протокола/клиента/сервера.
- [ ] Закрыть critical/high.
- [ ] Bug bounty (минимальный).
- [ ] Убрать метку «unaudited» только после публикации аудита.
- [ ] 1.0; iOS — по готовности.

**Выход:** аудит опубликован; critical/high закрыты; 1.0.

## Сроки и ресурсы

| Сценарий | Срок | Реалистичность |
|---|---|---|
| Соло, 10–15 ч/нед | 12–24 месяца до public alpha | Средняя; риск выгорания |
| Соло, full-time | 9–15 месяцев | Высокая нагрузка |
| 2–3 человека | 6–10 месяцев | Нужен бюджет/грант |
| С внешним аудитом | +2–4 месяца | Нужно $50k–$250k |

Без бюджета:
- серверы: 2–3 дешёвых VPS + Tor onion (можно начать с одного);
- аудит: отложен; public alpha после внутреннего red team с
  предупреждением; внешний аудит — до 1.0;
- iOS: отложен;
- звонки: не делаем.

## Что не делаем

- Не добавляем функции поверх самописной криптографии.
- Не обещаем «100% анонимность» и «невозможно взломать».
- Не используем блокчейн/IPFS для сообщений.
- Не делаем серверное сканирование контента.
- Не публикуем релиз до внутреннего red team.
- Не называем public alpha «secure» до внешнего аудита.
- Не храним IP-логи, историю, контактный граф.
- Не используем сторонние SDK/аналитику/FCM по умолчанию.
- Не делаем автоматический cloud backup.
- Не делаем P2P в MVP.
- Не обещаем криптографическую one-time гарантию инвайта.
- Не пишем свой message franking.

## Риски и смягчение

| Риск | Вероятность | Смягчение |
|---|---|---|
| Выгорание соло | Высокая | Жёсткие phase gates; MVP 1:1+файлы; пауза вместо расползания |
| libsignal сложно собрать | Средняя | Spike в Phase 1; pinned commit; fallback на audited эквивалент + ADR |
| Arti на Android жрёт батарею | Средняя | Профилирование; relay fallback; P2P только foreground |
| App Store откажет | Высокая | APK/F-Droid; iOS позже; честная политика |
| Нет денег на аудит | Высокая | Гранты; public alpha после внутреннего red team; внешний аудит до 1.0 |
| Account service коррелирует с relay | Средняя | Отдельный оператор/сервер; OHTTP; минимум данных; residual risk в UI |
| OPAQUE offline guessing | Средняя | Argon2id; сильный пароль; rate limit; честное предупреждение |
| Юридические претензии | Средняя | Юрисдикция; no logs; abuse policy; юридическая консультация |
| Supply chain атака | Средняя | cargo vet/deny; pinned deps; reproducible builds; 2-person review |

## Критерии «не начинать следующую фазу»

- Есть открытый critical/high баг.
- Нет тестов на новый протокол.
- Нет ADR на новую зависимость.
- Документация противоречит коду.
- Не пройден внутренний red team.
- Нет ответа на вопрос по безопасности от владельца.
- Нет плана отката/миграции для изменения формата.
