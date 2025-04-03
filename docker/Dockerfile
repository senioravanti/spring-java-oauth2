FROM gradle:jdk21-corretto AS build

WORKDIR /usr/local/src/oauth2-authorization-server/
COPY ./src/ ./src/
COPY ./lombok.config ./build.gradle.kts ./
RUN gradle clean assemble

# Второй этап
FROM eclipse-temurin:21-jre-noble

COPY --from=build "/usr/local/src/oauth2-authorization-server/build/libs/*.jar" /opt/oauth2-authorization-server.jar

ENTRYPOINT ["java","-jar","/opt/oauth2-authorization-server.jar" ]