// Android AAR: io.github.moss-piglet:metamorphic-log
//
// Wraps the CI-generated UniFFI Kotlin bindings (../../../bindings/kotlin) and
// the cargo-ndk jniLibs staged under src/main/jniLibs by release-native.yml.

plugins {
    id("com.android.library") version "8.5.2"
    id("org.jetbrains.kotlin.android") version "2.0.21"
    id("maven-publish")
    id("signing")
    id("com.gradleup.nmcp") version "1.6.1"
}

android {
    namespace = "io.github.mosspiglet.metamorphiclog"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
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
