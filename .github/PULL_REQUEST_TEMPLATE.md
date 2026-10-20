## Задача
- Номер задачи: `T-XXXX`
- Затрагиваемые модули: `aegis-...`
- Тип изменения: `feature` | `bugfix` | `contract-change` | `security`

## Что сделано
- ...

## Чек-лист приёмки (AGENTS.md §6 — Definition of Done)
- [ ] Критерии приёмки из `docs/tasks/T-XXXX.md` выполнены и проверены тестами
- [ ] Покрыты граничные случаи: пустые данные, огромные данные, обрыв сети, повтор, переупорядочивание, повреждённый ввод
- [ ] Нет `unwrap` / `expect` / `panic` на внешних данных; все ошибки типизированы (`#[forbid(unsafe_code)]`)
- [ ] Парсеры внешних данных прошли фаззинг (или заведена задача на это)
- [ ] Нет секретов и личных данных в логах, коде и git-метаданных (`./scripts/check-secrets.sh`)
- [ ] CI зелёный: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo audit`, `cargo deny check`
- [ ] Контракт `docs/contracts/<модуль>.md` и `docs/DECISIONS.md` обновлены (при изменении API/зависимостей)
- [ ] Отчёт написан в `docs/reports/YYYY-MM-DD_T-XXXX.md`, `docs/STATE.md` обновлён
- [ ] Известные баги записаны в `docs/BUGS.md` (ничего не скрыто)
