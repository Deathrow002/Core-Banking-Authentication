# Build Stage
FROM maven:3.9.9-eclipse-temurin-21 AS builder

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git curl && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG GITHUB_TOKEN

# Install the parent POM so the cloned module can resolve com:core-bank:1.0-SNAPSHOT
RUN curl -fsSL https://raw.githubusercontent.com/Deathrow002/Core-Banking/master/pom.xml -o /app/pom.xml
RUN mvn clean install -N

# Clone the Authentication service from GitHub
RUN git clone --branch main --single-branch https://${GITHUB_TOKEN}@github.com/Deathrow002/Core-Banking-Authentication.git Authentication

# Build the Authentication service (parent POM is now in local Maven repo)
RUN mkdir -p Authentication/src/main/avro Authentication/src/test/avro
RUN mvn clean package -DskipTests -f Authentication/pom.xml

# Runtime Stage
FROM eclipse-temurin:21-jre-jammy

# Install wget and curl
RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wget curl && \
	apt-get upgrade -y && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built JAR from the builder stage
COPY --from=builder /app/Authentication/target/*.jar authentication-service.jar

EXPOSE 8084

ENTRYPOINT ["java", "-jar", "authentication-service.jar"]