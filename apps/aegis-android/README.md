# Aegis Android (`apps/aegis-android`)

Нативный Android-клиент анонимного мессенджера **Aegis** (Jetpack Compose + Rust `aegis-ffi` + Android StrongBox Keystore).

## Архитектура безопасности (Zero-Telemetry / Zero-GMS)
- **Никаких сервисов Google / Firebase / Analytics (`AGENTS.md §2.2`):** доставка зашифрованных капсул в фоне работает через `AegisBackgroundService` (чистая чат-крепость без звонков и без доступа к микрофону/камере, `D-0021`).
- **Блокировка скриншотов и записи экрана (`FLAG_SECURE`):** включена по умолчанию в `MainActivity.kt`, скрывает содержимое чатов в меню недавних приложений.
- **Инкогнито-клавиатура (`IME_FLAG_NO_PERSONALIZED_LEARNING`):** запрещает клавиатуре сохранять вводимые слова и ники в пользовательский словарь.
- **Запрет облачных бэкапов (`android:allowBackup="false"`):** ключи и база SQLCipher никогда не выгружаются в Google Drive или через `adb backup`.
- **Аппаратная защита PIN (`AndroidKeyStore` StrongBox / TEE):** локальный ключ базы данных оборачивается аппаратным ключом устройства.
- **Маскировка иконки под «Калькулятор» (`CalculatorDisguiseAlias`):** переключение иконки в лаунчере Android и вход в реальный профиль по секретному PIN-коду в калькуляторе.

## Сборка APK
1. Соберите нативную библиотеку `aegis-ffi` под Android NDK (`arm64-v8a`, `x86_64`):
   ```bash
   cargo build --release -p aegis-ffi
   ```
2. Откройте каталог `apps/aegis-android` в Android Studio или соберите из командной строки:
   ```bash
   ./gradlew assembleRelease
   ```
