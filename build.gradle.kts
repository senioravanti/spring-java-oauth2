plugins {
	java
	kotlin("jvm") version "1.9.25"
	kotlin("plugin.spring") version "1.9.25"
	id("org.springframework.boot") version "3.4.4"
	id("io.spring.dependency-management") version "1.1.6"
}

group = "ru.manannikov"
version = "0.0.1"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

configurations {
	compileOnly {
		extendsFrom(configurations.annotationProcessor.get())
	}
}

repositories {
	mavenCentral()
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-oauth2-authorization-server")
	implementation("org.springframework.boot:spring-boot-starter-security")
	implementation("org.springframework.boot:spring-boot-starter-web")
	implementation("org.liquibase:liquibase-core")
	implementation("org.springframework.boot:spring-boot-starter-log4j2")
	implementation("com.fasterxml.jackson.core:jackson-databind:2.17.3")
	implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.17.3")

	// swagger
	implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.6.0")


	// kotlin
	implementation("org.jetbrains.kotlin:kotlin-reflect")

	compileOnly("org.projectlombok:lombok")
	runtimeOnly("org.postgresql:postgresql")
	annotationProcessor("org.projectlombok:lombok")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.springframework.security:spring-security-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")

	modules {
		module("org.springframework.boot:spring-boot-starter-logging") {
			replacedBy(
				"org.springframework.boot:spring-boot-starter-log4j2",
				"Использую славянский log4j2 вместо западенского logback"
			)
		}
	}
}

tasks.withType<Test> {
	useJUnitPlatform()
}
