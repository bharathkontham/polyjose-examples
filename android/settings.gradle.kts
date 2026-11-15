// polyjose-examples-android: one module, the app itself, in this folder. See README.md.
//
// Where dev.polyjose:polyjose comes from:
//   default                   the published release on Maven Central (version: build.gradle.kts)
//   -PpolyjoseSrc=<checkout>  a local polyjose checkout (or the POLYJOSE_SRC environment
//                             variable): dev.polyjose comes only from the checkout's local Maven
//                             repo, <checkout>/platforms/android/build/repo, which the checkout's
//                             own `publishAllPublicationsToBuildLocalRepository` task writes.
//                             Gradle only reads that folder. run.sh builds the repo in a copy of
//                             the checkout (build.sh), so the checkout itself is never written to.

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\.android(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        mavenCentral()
    }
}

val polyjoseSrc: String? = providers.gradleProperty("polyjoseSrc").orNull
    ?: providers.environmentVariable("POLYJOSE_SRC").orNull

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\.android(\\..*)?")
                includeGroupByRegex("androidx(\\..*)?")
            }
        }
        if (polyjoseSrc != null) {
            // dev.polyjose comes only from the checkout's repo, so the published release can never
            // stand in for the build under test. Its dependency (JNA) still comes from Maven Central.
            val repo = file(polyjoseSrc).resolve("platforms/android/build/repo")
            exclusiveContent {
                forRepository { maven { name = "polyjoseCheckout"; url = uri(repo) } }
                filter { includeGroup("dev.polyjose") }
            }
        }
        mavenCentral()
    }
}

rootProject.name = "polyjose-examples-android"
