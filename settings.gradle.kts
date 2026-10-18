// 仓库顺序：国内镜像优先、官方源兜底。
// 这台机器直连 github.com / services.gradle.org 会超时（2026-10-17 实测跨境
// 只有 ~2 Mbps），所以 Gradle 发行包走腾讯镜像、依赖走阿里云镜像。
pluginManagement {
    repositories {
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // 本地 AAR（gomobile 产物）：AGP 不认 implementation(files("*.aar"))，
        // 必须走 flatDir + implementation(name=, ext=)。
        flatDir { dirs("app/libs") }
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
    }
}

rootProject.name = "ther"
include(":app")
