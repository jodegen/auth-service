FROM eclipse-temurin:17-jdk AS builder

ARG GITHUB_TOKEN

WORKDIR /app
COPY . .

RUN mkdir -p ~/.m2 && \
    printf '<settings>\n\
  <servers>\n\
    <server>\n\
      <id>github-other</id>\n\
      <username>jodegen</username>\n\
      <password>%s</password>\n\
    </server>\n\
  </servers>\n\
</settings>\n' "${GITHUB_TOKEN}" > ~/.m2/settings.xml

RUN chmod +x mvnw
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar", "--spring.profiles.active=prod"]