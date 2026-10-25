plugins {
    id("com.android.application")
}

android {
    namespace = "org.gommage.tv"
    // tor-android 0.4.9.14 requires 37.1+
    compileSdk { version = release(37) { minorApiLevel = 2 } }

    defaultConfig {
        applicationId = "org.gommage.tv"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
        // TVs are ARM; `-Pabis=x86_64` builds for the emulator
        ndk { abiFilters += (project.findProperty("abis") as String? ?: "arm64-v8a,armeabi-v7a").split(",") }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // tor-android loads libtor.so as a library; keep native libs extracted like Orbot does
    packaging { jniLibs { useLegacyPackaging = true } }
}

dependencies {
    implementation("info.guardianproject:tor-android:0.4.9.14")
    implementation("info.guardianproject:jtorctl:0.4.5.7")
    implementation("com.netzarchitekten:IPtProxy:5.7.0")
    // tun -> SOCKS5, prebuilt from github.com/heiher/hev-socks5-tunnel releases (2.19.1)
    implementation(files("libs/hev-socks5-tunnel.aar"))
    testImplementation("junit:junit:4.13.2")
}
