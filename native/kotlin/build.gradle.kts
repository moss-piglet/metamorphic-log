// Minimal Gradle project that compiles and runs the Kotlin/JVM verification
// smoke (`../smoke/Smoke.kt`) against the CI-generated UniFFI bindings
// (`../../bindings/kotlin`, gitignored) and the built desktop JVM shared
// library. This is the dry-run gate that closes #73's outstanding Kotlin
// round-trip smoke; the release AAR/JVM-jar packaging + Maven publish is a
// separate concern in release-native.yml.
//
// The native library directory is passed via the MOSS_NATIVE_LIB_DIR env var
// (absolute path to the dir containing libmetamorphic_log.so) so JNA can load
// it; the repo root is passed as the program argument so the smoke can read the
// locked vectors.

plugins {
    kotlin("jvm") version "2.0.21"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // JNA: UniFFI's Kotlin backend loads the cdylib through it.
    implementation("net.java.dev.jna:jna:5.14.0")
    // Tiny JSON reader for the shared locked-vectors fixture.
    implementation("org.json:json:20240303")
}

sourceSets {
    main {
        kotlin.srcDirs("../smoke", "../../bindings/kotlin")
    }
}

application {
    // `fun main(args)` in the default package of Smoke.kt -> `SmokeKt`.
    mainClass.set("SmokeKt")
    val libDir = System.getenv("MOSS_NATIVE_LIB_DIR") ?: "${rootDir}/../../target/debug"
    applicationDefaultJvmArgs = listOf("-Djna.library.path=$libDir")
}
