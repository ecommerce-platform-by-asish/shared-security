plugins {
    `java-library`
    id("io.spring.dependency-management") version "1.1.7"
    `maven-publish`
    id("com.diffplug.spotless") version "8.4.0"
}

group = "com.ecommerce"
version = "1.0.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
    withSourcesJar()
}

repositories {
    mavenCentral()
    maven { url = uri("https://repo.spring.io/milestone") }
}

spotless {
    java {
        googleJavaFormat()
    }
}

val springBootVersion = "4.0.5"
val springDocVersion = "2.8.6"

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:$springBootVersion")
    }
}

dependencies {
    api("org.springframework.boot:spring-boot-starter-security")
    api("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
    testCompileOnly("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
        }
    }
}

tasks.named("build") {
    finalizedBy("publishToMavenLocal")
}

tasks.named("check") {
    dependsOn("spotlessCheck")
}
