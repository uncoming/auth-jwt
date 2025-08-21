FROM eclipse-temurin:21

WORKDIR /app

COPY target/auth-jwt-0.0.1-SNAPSHOT.jar /app/auth-jwt-0.0.1-SNAPSHOT.jar

EXPOSE 5000

CMD [ "java", "-jar", "auth-jwt-0.0.1-SNAPSHOT.jar" ]