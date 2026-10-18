# Build Stage
FROM maven:3.9.9-eclipse-temurin-21 AS builder

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git curl && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pom.xml /app/pom.xml
RUN mvn install -N -DskipTests

COPY Authentication /app/Authentication

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