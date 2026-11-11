import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing material lives outside the repository. Without it the release APK is unsigned.
val keystoreProps: Properties? = (System.getenv("AEGIS_KEYSTORE_PROPERTIES")
    ?: "${System.getProperty("user.home")}/.aegis-release/keystore.properties")
    .let { file(it) }
    .takeIf { it.isFile }
    ?.let { f -> Properties().apply { f.inputStream().use { load(it) } } }

android {
    namespace = "org.aegis.messenger"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.aegis.messenger"
        minSdk = 28
        targetSdk = 34
        versionCode = 5
        versionName = "0.2.7"

        // tor-android ships one native library per ABI; 32-bit x86 devices are not worth the extra size.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    signingConfigs {
        if (keystoreProps != null) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.findByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    testOptions {
        unitTests.all {
            it.systemProperty(
                "aegis.vectors",
                rootProject.file("../../docs/test-vectors.json").absolutePath
            )
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "/META-INF/versions/**"
            excludes += "/META-INF/*.version"
            excludes += "/META-INF/DEPENDENCIES"
            excludes += "/META-INF/INDEX.LIST"
            excludes += "/org/bouncycastle/pqc/crypto/picnic/**"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

dependencies {
    // Pure AndroidX & Jetpack Compose UI — ZERO Google Play Services / Firebase / Crashlytics
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    implementation("androidx.compose.ui:ui:1.6.8")
    implementation("androidx.compose.foundation:foundation:1.6.8")
    implementation("androidx.compose.material3:material3:1.2.1")
    implementation("androidx.compose.ui:ui-tooling-preview:1.6.8")
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("info.guardianproject:tor-android:0.4.8.21") { exclude(group = "org.jetbrains.kotlin") }
    implementation("info.guardianproject:jtorctl:0.4.5.7")
    implementation("com.netzarchitekten:IPtProxy:5.7.0")

    testImplementation("junit:junit:4.13.2")
}
