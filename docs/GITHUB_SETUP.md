# Настройка GitHub для анонимного проекта

## 1. Аккаунт
- Отдельный аккаунт/организация для проекта, отдельная почта, без личных фото и данных.
- Settings → Emails: включить **Keep my email addresses private** и **Block command line pushes that expose my email**.
- Скопировать noreply-адрес вида `ID+имя@users.noreply.github.com`.
- Включить двухфакторную аутентификацию (приложение-TOTP или ключ, не SMS).

## 2. Git локально
```
git config user.name "aegis-project"
git config user.email "ID+имя@users.noreply.github.com"
```
Только `user.*` внутри репозитория (без `--global`), чтобы не смешивать с личным.

## 3. Первая заливка
```
git init
git add .
git commit -m "T-0000: initial plan and AGENTS.md"
git branch -M main
git remote add origin https://github.com/ВАШ_АККАУНТ/aegis.git
git push -u origin main
```
В `.github/ISSUE_TEMPLATE/config.yml` замените `OWNER` на имя аккаунта.

## 4. Настройки репозитория
- Settings → Security → включить **Private vulnerability reporting**, **Dependabot alerts**, **Secret scanning**.
- Settings → Branches → защита ветки `main`: требовать PR, проверки CI, запретить force-push.
- Settings → General → отключить Wiki и Projects, если не нужны.
- Issues оставить включёнными, Discussions по желанию.

## 5. Когда делать публичным
Чеклист: в истории нет личных данных и секретов (`git log --format='%an %ae' | sort -u`), LICENSE выбран, README готов. Только после этого Settings → Danger Zone → Change visibility → Public.

## 6. Подпись коммитов (рекомендуется)
Проектный ключ SSH/GPG, отдельный от личных. Релизы подписываются проектным ключом.
