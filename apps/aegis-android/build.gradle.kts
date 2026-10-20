// Top-level Gradle build configuration for Aegis Android (Zero-Telemetry, Reproducible APK)
// Strictly NO Google Play Services, NO Firebase, NO Analytics SDKs (AGENTS.md §2.2).
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
