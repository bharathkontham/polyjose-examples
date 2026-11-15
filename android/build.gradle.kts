// polyjose-examples-android. AGP 9 compiles Kotlin itself, so only the application plugin is
// applied. The app's only library dependency is dev.polyjose:polyjose (which brings JNA).
//
// Gradle properties (all optional):
//   polyjoseVersion  the dev.polyjose:polyjose version (default: `polyjoseVersion` below, or with
//                    polyjoseSrc the version in the checkout's Cargo.toml)
//   polyjoseSrc      a local polyjose checkout, also POLYJOSE_SRC (see settings.gradle.kts)

plugins {
    id("com.android.application") version "9.5.1"
    // AGP 9 compiles Kotlin with the Kotlin Gradle plugin on the build class path. This pins it to
    // the Kotlin that dev.polyjose:polyjose 0.2.0 is built with, so the compiler can read the
    // kotlin-stdlib that the AAR brings.
    id("org.jetbrains.kotlin.android") version "2.4.21" apply false
}

/** The polyjose release these examples are written and checked against. The one version pin. */
val polyjoseVersion = "0.2.0"

val polyjoseSrc: String? = providers.gradleProperty("polyjoseSrc").orNull
    ?: providers.environmentVariable("POLYJOSE_SRC").orNull

/** The workspace version in a checkout's Cargo.toml: the version its local AAR is published as. */
fun checkoutVersion(checkout: File): String {
    val manifest = checkout.resolve("Cargo.toml")
    if (!manifest.isFile) throw GradleException("polyjoseSrc: no Cargo.toml in $checkout")
    return Regex("""(?m)^version\s*=\s*"([^"]+)"""").find(manifest.readText())?.groupValues?.get(1)
        ?: throw GradleException("polyjoseSrc: no version in $manifest; pass -PpolyjoseVersion")
}

val resolvedPolyjoseVersion: String = providers.gradleProperty("polyjoseVersion").orNull
    ?: polyjoseSrc?.let { checkoutVersion(file(it)) }
    ?: polyjoseVersion

android {
    namespace = "dev.polyjose.examples"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.polyjose.examples"
        minSdk = 23 // the polyjose AAR's minSdk
        targetSdk = 36
        versionCode = 1
        versionName = "1"
        val source = if (polyjoseSrc != null) "local checkout" else "Maven Central"
        buildConfigField("String", "POLYJOSE_SOURCE", "\"$source\"")
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("dev.polyjose:polyjose:$resolvedPolyjoseVersion")
}
