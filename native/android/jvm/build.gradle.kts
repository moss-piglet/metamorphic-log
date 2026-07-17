// Desktop JVM jar: io.github.moss-piglet:metamorphic-log-jvm
//
// Wraps the CI-generated UniFFI Kotlin bindings (../../../bindings/kotlin) and
// bundles the desktop shared libraries under JNA resource paths
// (src/main/resources/<jna-platform>/) staged by release-native.yml.

// Versions are declared once at the root build.gradle.kts (apply false); here we
// only apply the plugins.
plugins {
    id("org.jetbrains.kotlin.jvm")
    id("java-library")
    id("maven-publish")
    id("signing")
    id("com.gradleup.nmcp")
}

java {
    withSourcesJar()
    withJavadocJar()
    toolchain { languageVersion.set(JavaLanguageVersion.of(21)) }
}

sourceSets {
    named("main") {
        // UniFFI-generated Kotlin (gitignored, produced in CI).
        kotlin.srcDir("../../../bindings/kotlin")
        // Desktop libs are staged under the DEFAULT main resources dir
        // (src/main/resources/<jna-platform>/<libname>) in release-native.yml,
        // so JNA extracts + loads them at runtime. Do not re-add that dir as a
        // resources srcDir: it is already the default, and declaring it twice
        // makes every entry a duplicate (processResources then fails).
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.14.0")
}

publishing {
    publications {
        register<MavenPublication>("jvm") {
            artifactId = "metamorphic-log-jvm"
            from(components["java"])
            pom {
                name.set("metamorphic-log (JVM)")
                description.set("Verification-only desktop JVM bindings for metamorphic-log transparency checkpoints, signed notes, and commitments.")
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
