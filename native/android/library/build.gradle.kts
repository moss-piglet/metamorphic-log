// Android AAR: io.github.moss-piglet:metamorphic-log
//
// Wraps the CI-generated UniFFI Kotlin bindings (../../../bindings/kotlin) and
// the cargo-ndk jniLibs staged under src/main/jniLibs by release-native.yml.

// Versions are declared once at the root build.gradle.kts (apply false); here we
// only apply the plugins.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
    id("signing")
    id("com.gradleup.nmcp")
}

android {
    namespace = "io.github.mosspiglet.metamorphiclog"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
    }

    // Pin the Java bytecode target so it matches the Kotlin jvmTarget below;
    // without this AGP defaults javac to 1.8 while Kotlin targets the toolchain
    // JDK (21 on the runner), failing with "Inconsistent JVM-target".
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            // UniFFI-generated Kotlin (gitignored, produced in CI).
            kotlin.srcDir("../../../bindings/kotlin")
            // jniLibs/<abi>/libmetamorphic_log.so populated by cargo-ndk.
            jniLibs.srcDir("src/main/jniLibs")
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

// Match the Kotlin JVM target to compileOptions (17) so the Kotlin and Java
// compile tasks agree.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // UniFFI's Kotlin backend loads the cdylib through JNA.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "metamorphic-log"
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("metamorphic-log (Android)")
                description.set("Verification-only Android bindings for metamorphic-log transparency checkpoints, signed notes, and commitments.")
                url.set("https://github.com/moss-piglet/metamorphic-log")
                licenses {
                    license { name.set("Apache-2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0") }
                    license { name.set("MIT"); url.set("https://opensource.org/licenses/MIT") }
                }
                developers { developer { id.set("moss-piglet"); name.set("moss-piglet") } }
                scm {
                    url.set("https://github.com/moss-piglet/metamorphic-log")
                    connection.set("scm:git:https://github.com/moss-piglet/metamorphic-log.git")
                }
            }
        }
    }
}

signing {
    val key = System.getenv("ORG_GRADLE_PROJECT_signingKey")
    val pass = System.getenv("ORG_GRADLE_PROJECT_signingPassword")
    if (!key.isNullOrBlank()) {
        useInMemoryPgpKeys(key, pass)
        sign(publishing.publications)
    }
}
