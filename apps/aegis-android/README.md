# Aegis for Android

Kotlin and Jetpack Compose client for protocol v2 (`docs/PROTOCOL.md`). Unaudited alpha.

- `core/` pure Kotlin protocol and crypto on the BouncyCastle lightweight API; verified against `docs/test-vectors.json`.
- `net/` HTTPS client, endpoint rules, SOCKS5 with remote DNS.
- `data/` vault model and its JSON codec; `app/` session, service, notifications; `ui/` Compose screens.

Build and test:

    JAVA_HOME=<jdk17> ./gradlew testDebugUnitTest assembleRelease

The release build is signed with the debug key; replace it before distributing.
