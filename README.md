# Core-Banking-Authentication

Authentication microservice for the Core Banking system. Handles user registration, login and
server-side sessions shared by all Core Banking services.

## Features

- Session-based authentication backed by Spring Session + Redis
- HttpOnly `SESSION` cookie (no tokens are exposed to the browser)
- CSRF protection (Spring Security SPA mode: `XSRF-TOKEN` cookie / `X-XSRF-TOKEN` header)
- Session fixation protection (session id rotated on login)
- Role-based access control (ADMIN, MANAGER, USER)
- Secure password encoding
- Admin user management

## Tech Stack

- Java 21+ with Spring Boot 4
- Spring Security 7 + Spring Session Data Redis
- PostgreSQL database
- Eureka for service discovery

## How sessions work

1. `GET /api/v1/auth/csrf` issues the `XSRF-TOKEN` cookie.
2. `POST /api/v1/auth/login` (form fields `email`, `password`, header `X-XSRF-TOKEN`) authenticates the
   user and stores the security context in Redis under `core-banking:session:sessions:<id>`.
   The response sets the `SESSION` cookie and returns `{ "username", "customerId", "roles" }`.
3. Every other service (Account, Customer, Transaction, Loan) reads the same Redis session using the
   `SESSION` cookie, so the browser just keeps sending its cookies. Write requests must include the
   `X-XSRF-TOKEN` header.
4. `POST /api/v1/auth/logout` invalidates the session in Redis and clears the cookie.

The stored principal is a plain username string with details `{username, customerId, role}`, so any
service can deserialize it without depending on this module's classes.

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/auth/csrf` | Issue `XSRF-TOKEN` cookie (204) | No |
| POST | `/api/v1/auth/login` | Log in, create session | No (CSRF required) |
| GET | `/api/v1/auth/me` | Current session user | Session |
| POST | `/api/v1/auth/logout` | Invalidate session (204) | Session + CSRF |
| POST | `/api/v1/auth/register` | Register new user | Session + CSRF |
| GET | `/api/v1/auth/getAllUsers` | List all users | ADMIN only |

Unauthenticated requests receive `401` JSON; a missing/invalid CSRF token yields `403`.

## Configuration

Default port: `8084`

```properties
spring.application.name=authentication-service
eureka.client.service-url.defaultZone=http://discovery-service:8761/eureka

spring.data.redis.host=redis
spring.data.redis.port=6379
spring.session.data.redis.namespace=core-banking:session
spring.session.data.redis.flush-mode=immediate
spring.session.timeout=30m

# Set secure=true when served over HTTPS; use SameSite=None only for cross-site frontends (requires secure=true)
app.session.cookie.secure=false
app.session.cookie.same-site=Lax
```

All services must share the same Redis instance and `spring.session.data.redis.namespace`.

## Example (curl)

```bash
curl -c jar -b jar http://localhost:8084/api/v1/auth/csrf
XSRF=$(awk '/XSRF-TOKEN/ {print $7}' jar)
curl -c jar -b jar -H "X-XSRF-TOKEN: $XSRF" \
     -d "email=admin@bank.com" -d "password=secret" http://localhost:8084/api/v1/auth/login
curl -b jar http://localhost:8084/api/v1/auth/me
curl -b jar -c jar -X POST -H "X-XSRF-TOKEN: $XSRF" http://localhost:8084/api/v1/auth/logout
```

## Running Locally

Requires Redis and PostgreSQL.

```bash
./mvnw spring-boot:run
```

## Docker

```bash
docker build -t authentication-service .
docker run -p 8084:8084 authentication-service
```
