plugins {
    id("java-library")
    id("maven-publish")
    alias(libs.plugins.springboot)
    alias(libs.plugins.spotless)
}

group = "com.app"
version = "1.0.0-SNAPSHOT"

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }
    withSourcesJar()
}

dependencies {
    api(platform(libs.sb.bom))
    api(platform(libs.sc.bom))
    api(platform(libs.jjwt.bom))

    implementation("com.app:shared-common:1.0.0-SNAPSHOT")
    
    api(libs.sb.starter.security)
    api(libs.sb.starter.oauth2.resource.server)
    
    // Explicitly add what's used in shared-security
    compileOnly(libs.sb.starter.web)
    compileOnly(libs.sb.starter.webflux)
    compileOnly(libs.sb.starter.data.jpa)
    compileOnly(libs.sb.starter.data.redis)
    compileOnly(libs.sc.starter.gateway)
    
    api(libs.jjwt.api)
    runtimeOnly(libs.jjwt.impl)
    runtimeOnly(libs.jjwt.jackson)

    compileOnly(libs.sb.autoconfigure)
    compileOnly(libs.lombok)
    annotationProcessor(platform(libs.sb.bom))
    annotationProcessor(libs.lombok)
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}

spotless { java { googleJavaFormat("1.27.0") } }


tasks.bootJar { enabled = false }
tasks.jar { enabled = true }

tasks.build { dependsOn("publishToMavenLocal") }
