# Aegis Android (`apps/aegis-android`)

Android-клиент мессенджера **Aegis** на Jetpack Compose (`v0.1.0-alpha`, неаудированный прототип).

## Что реализовано в приложении
- **Без сторонних аналитических SDK и Google Play Services:** только стандартные библиотеки AndroidX и Jetpack Compose, 0 разрешений на микрофон и камеру.
- **Защита окна и ввода:** `FLAG_SECURE` (запрет скриншотов и превью в списке недавних задач), `excludeFromRecents="true"`, `android:allowBackup="false"`, флаг инкогнито-клавиатуры `IME_FLAG_NO_PERSONALIZED_LEARNING`.
- **Функции клиента:**
  - Полное переключение языка интерфейса `RU / EN`.
  - Подключение к серверу `aegis-serverd` по `host:port`, настройка `SOCKS5h` прокси и релея, переключатель блокировки сети (`Kill Switch`).
  - Создание чатов по общему коду канала, локальный фильтр поиска, PIN-код на чат, таймер исчезающих сообщений и проверка текста перед отправкой (`LeakGuard`).

## Сборка APK
```bash
./gradlew assembleRelease
```
