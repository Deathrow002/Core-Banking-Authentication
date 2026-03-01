# Core-Banking-Authentication

Authentication microservice for the Core Banking system. Handles user registration, login, and JWT token management.

## Features

- User registration with role assignment
- JWT-based authentication
- Role-based access control (ADMIN, MANAGER, USER)
- Secure password encoding
- Admin user management

## Tech Stack

- Java 17+ with Spring Boot
- Spring Security with JWT
- PostgreSQL database
- Eureka for service discovery

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/login` | User login | No |
| POST | `/api/v1/auth/register` | Register new user | Yes (Bearer token) |
| GET | `/api/v1/auth/getAllUsers` | List all users | ADMIN only |

## Configuration

Default port: `8080`

```properties
spring.application.name=authentication-service
eureka.client.service-url.defaultZone=http://discovery-service:8761/eureka
```

## Running Locally

```bash
./mvnw spring-boot:run
```

## Docker

```bash
docker build -t authentication-service .
docker run -p 8080:8080 authentication-service
```