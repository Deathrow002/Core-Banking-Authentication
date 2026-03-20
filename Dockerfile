# Build Stage
FROM maven:3.9.9-eclipse-temurin-21 AS builder

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Clone the Authentication service from GitHub
RUN git clone --branch main --single-branch https://github.com/Deathrow002/Core-Banking-Authentication.git .

# Build the Authentication service
RUN mvn clean package -DskipTests

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
COPY --from=builder /app/target/*.jar authentication-service.jar

EXPOSE 8084

ENTRYPOINT ["java", "-jar", "authentication-service.jar"]