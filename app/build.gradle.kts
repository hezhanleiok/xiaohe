plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.aether.ther"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.aether.ther"
        minSdk = 26
        targetSdk = 35
        versionCode = 30
        versionName = "0.1.29"

        ndk {
            // engine.aar 目前只编了 arm64（真机都是 arm64）。armeabi-v7a 需要
            // 另外跑一次 gomobile bind -target=android/arm，缺库时装上会直接崩。
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/DEPENDENCIES")
        jniLibs {
            // Aether 核心与赛风客户端是**可执行 ELF**，不是共享库：放在 assets 里
            // 解出来再 exec 会被 targetSdk>=29 的 W^X 规则挡住（Android 10 起禁止
            // 执行应用数据目录里的文件）。伪装成 lib*.so 放进 nativeLibraryDir 才
            // 是唯一合法位置——那里由系统解包、应用不可写、允许 exec。
            // useLegacyPackaging=true 让 APK 里的 .so 在安装时被解出来（默认的
            // 直接 mmap 方式拿不到可执行文件路径）。
            useLegacyPackaging = true
            // 别让 AGP 拿去 strip：这两个是完整的可执行文件，strip 只会带来风险。
            keepDebugSymbols += setOf("**/libaether.so", "**/libpsiphon.so")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    // Go 引擎（gomobile bind 产物）：wireguard-go + AWG junk + WARP 注册。
    // 用 engine/build-engine.ps1 重新生成，不入库。
    implementation(files("libs/engine.aar"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.documentfile:documentfile:1.0.1")

    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
