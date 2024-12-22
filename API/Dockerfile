FROM gradle:jdk21 as builder
WORKDIR /home/app
ADD build.gradle /home/app/build.gradle
ADD settings.gradle /home/app/settings.gradle
ADD src /home/app/src
RUN gradle build

FROM eclipse-temurin:21-jre-alpine
EXPOSE 8000
COPY --from=builder /home/app/build/libs/*-SNAPSHOT.jar app.jar
ENTRYPOINT ["java","-jar","/app.jar"]