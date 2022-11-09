FROM openjdk:17-ea-16-jdk
ARG JAR_FILE=build/libs/*jar
COPY ./build/libs/auth-server-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
