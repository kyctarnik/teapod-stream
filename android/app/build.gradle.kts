plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.teapodstream.teapodstream"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    defaultConfig {
        applicationId = "com.teapodstream.teapodstream"
        minSdk = 29  // Required by teapod-tun2socks AAR (getConnectionOwnerUid)
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // Restrict ABI to the target platform (default: arm64-v8a)
        val targetPlatform = project.findProperty("target-platform") as String?
        val targetAbi = when (targetPlatform) {
            "android-arm64" -> "arm64-v8a"
            "android-x64" -> "x86_64"
            else -> "arm64-v8a"
        }
        ndk {
            abiFilters.clear()
            abiFilters.add(targetAbi)
        }
    }

    packaging {
        jniLibs {
            val targetPlatform = project.findProperty("target-platform") as String?
            // Default to arm64-v8a when no platform is specified
            val targetAbi = when (targetPlatform) {
                "android-arm64" -> "arm64-v8a"
                "android-x64" -> "x86_64"
                else -> "arm64-v8a"
            }
            listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64").forEach { abi ->
                if (abi != targetAbi) {
                    excludes.add("lib/$abi/**")
                }
            }
        }
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
            
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    // Динамический выбор AAR в зависимости от целевой архитектуры
    val targetPlatform = project.findProperty("target-platform") as String?
    val abi = when (targetPlatform) {
        "android-arm64" -> "arm64-v8a"
        "android-x64" -> "x86_64"
        else -> null
    }

    if (abi != null) {
        implementation(files("libs/teapod-tun2socks-$abi.aar"))
    } else {
        // No target platform specified — default to arm64-v8a to avoid duplicate-class
        // errors that occur when both AARs are on the classpath simultaneously.
        implementation(files("libs/teapod-tun2socks-arm64-v8a.aar"))
    }
}

flutter {
    source = "../.."
}
