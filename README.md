# Core-Banking-Authentication

Authentication microservice for the Core Banking system. Handles user registration, login and
server-side sessions shared by all Core Banking services.

## Mobile OAuth/OIDC (Phase 1)

Web login remains session-based; mobile uses Spring Authorization Server with Authorization Code + **S256 PKCE** in the system browser. Both load the same `user_auth` accounts and BCrypt hashes.

| Setting | Development value |
|---------|-------------------|
| Issuer | `http://localhost:8080` |
| Client ID | `core-banking-mobile` |
| Client authentication | None (public native client; no client secret) |
| Exact redirect URI | `com.corebanking.mobile:/oauth2/callback` |
| Scopes | `openid profile banking transactions.write` |
| API audience | `core-banking-api` |
| Access token lifetime | 5 minutes |
| Authorization code lifetime | 2 minutes |

Start authorization at `/oauth2/authorize` with `response_type=code`, `client_id`, `redirect_uri`, requested `scope`, unpredictable `state`, and `code_challenge` / `code_challenge_method=S256`. For OIDC also generate and verify a `nonce`. Create a fresh high-entropy verifier per request and validate the returned state.

The authorization flow uses a dedicated `/oauth/login` page, separate from Angular's `/login`. Exchange the returned code at `/oauth2/token` using form fields `grant_type=authorization_code`, `client_id`, `redirect_uri`, `code`, and `code_verifier`. Never put a client secret in the mobile app. Use a maintained native OAuth/OIDC SDK to validate ID tokens and handle redirects; do not implement the protocol manually in the app.

Discovery is available at `/.well-known/openid-configuration` and public signing keys at `/oauth2/jwks`. Access tokens carry `sub` (existing email/username), `customerId`, `role` (`ROLE_ADMIN`, `ROLE_MANAGER`, or `ROLE_CUSTOMER`), `permissions` (the role's `PERM_ADD` / `PERM_EDIT` / `PERM_DELETE`), audience and granted scopes.

Public PKCE clients do **not** receive refresh tokens in this implementation. Reauthorize through the system browser when the access token expires. An existing browser authorization session can avoid another password prompt. Do not add a static mobile client secret to work around this restriction.

### Mobile API boundaries

Mobile paths are `/api/mobile` followed by the original service path, for example `/api/mobile/accounts/getAccount`. These endpoints ignore browser session authentication, do not create sessions, validate the token signature/issuer/audience/expiry, and require the `banking` scope plus the original business role checks. Existing non-mobile paths continue to require sessions and CSRF; bearer tokens do not authenticate those paths.

- `GET /api/mobile/api/v1/auth/me`: current mobile identity.
- `POST /api/mobile/api/v1/auth/register` and `GET /api/mobile/api/v1/auth/getAllUsers`: reuse the existing controller and role checks; user listing still requires ADMIN.
- `POST /api/mobile/api/v1/auth/logout`: deletes the matching OAuth authorization grant (204). Discard tokens in the app too. This does **not** immediately invalidate an already signed JWT in other resource servers: it can remain valid for its remaining five-minute lifetime, plus the validators' clock skew allowance. Browser sessions are independent; use OIDC browser logout if the system-browser login session must also end.

**Phase 1 limitation:** mobile deposit, withdrawal, and transfer routes require both `banking` and `transactions.write`. Without them, requests return 403. With them, requests return 503 before business logic or persistence. They are intentionally not enabled by merely forwarding a user credential through Kafka. Existing web money workflows are unchanged.

Account's mobile balance updates, nonzero opening balances and deletion are gated the same way to prevent bypassing that restriction. Zero-balance account creation and read-only access remain available under the existing role checks.

**Phase 2 (not implemented):** replace session-dependent Kafka authorization with backend-signed command envelopes, signature/expiry checks, durable transaction/nonce idempotency and a transactional outbox. Neither reusable access tokens nor unsigned scope headers should authorize Kafka consumers.

### Persistence and deployment

The service creates the framework OAuth client, authorization and consent tables idempotently in PostgreSQL, plus `oauth2_signing_key`. The RSA private JWK is generated once and stored there, so keys and outstanding authorizations survive service restarts. Only the public key is served by JWKS. Restrict database privileges, encrypt database storage/backups, and plan managed key storage, key rotation and retention before production. No private key is committed to source.

The first-party mobile registration is synchronized on startup; updating its configured redirect URI updates the persisted registration. Back up OAuth tables with the user database. Schema creation requires DDL permissions; production deployments should manage the schema through controlled migrations.

Override `OAUTH_ISSUER` and `OAUTH_MOBILE_REDIRECT_URI` when deploying. Resource servers use `app.oauth.issuer` and `app.oauth.jwk-set-uri`; Compose uses the public issuer but fetches keys internally from `http://authentication-service:8084/oauth2/jwks`.

`localhost` is for desktop development only: a physical phone must use a reachable issuer hostname, configured consistently in the server and resource servers. Production requires HTTPS and secure session cookies. Prefer verified HTTPS app links over private-use schemes for production callbacks.

The gateway forwards the original host (including its port) through `X-Forwarded-Host`; Authentication uses framework forwarded-header support so login redirects stay on the public origin. Restrict direct backend access to trusted proxies when enabling forwarded headers.

## Features

- Session-based authentication backed by Spring Session + Redis
- HttpOnly `SESSION` cookie (no tokens are exposed to the browser)
- CSRF protection (Spring Security SPA mode: `XSRF-TOKEN` cookie / `X-XSRF-TOKEN` header)
- Session fixation protection (session id rotated on login)
- Role-based access control (ADMIN, MANAGER, CUSTOMER); roles are rows in the `roles` table, not a Java enum
- Per-role add / edit / delete permissions (see [Role permissions](#role-permissions))
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
   The response sets the `SESSION` cookie and returns `{ "username", "customerId", "roles", "permissions" }`.
3. Every other service (Account, Customer, Transaction, Loan) reads the same Redis session using the
   `SESSION` cookie, so the browser just keeps sending its cookies. Write requests must include the
   `X-XSRF-TOKEN` header.
4. `POST /api/v1/auth/logout` invalidates the session in Redis and clears the cookie.

The stored principal is a plain username string with details `{username, customerId, role}`, so any
service can deserialize it without depending on this module's classes. Its authorities are the
`ROLE_*` authority plus the role's `PERM_*` permissions, so any service can use
`hasAuthority('PERM_DELETE')` and similar checks.

### Role permissions

Each row in the `roles` table has `can_add`, `can_edit` and `can_delete` flags. They are published as
the `PERM_ADD`, `PERM_EDIT` and `PERM_DELETE` authorities in the session and in the mobile access
token's `permissions` claim. `schema.sql` seeds:

| Role | `can_add` | `can_edit` | `can_delete` |
|------|-----------|------------|--------------|
| ADMIN | ✓ | ✓ | ✓ |
| MANAGER | ✓ | ✓ | |
| CUSTOMER | | | |

On an existing database the columns are added once with these values; later startups do not
overwrite changes made in the table. Permissions are copied into the session at login, so a user
must sign in again to pick up a change (sessions created before this feature have no `PERM_*`
authorities).

OAuth request caching stores only a relative authorization URL, not servlet request/cookie objects, because reactive services deserialize the same session. Sessions created by an intermediate build that cached servlet objects must be replaced by signing out and starting a new session; do not flush unrelated Redis sessions.

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/auth/csrf` | Issue `XSRF-TOKEN` cookie (204) | No |
| POST | `/api/v1/auth/login` | Log in, create session | No (CSRF required) |
| GET | `/api/v1/auth/me` | Current session user | Session |
| POST | `/api/v1/auth/logout` | Invalidate session (204) | Session + CSRF |
| POST | `/api/v1/auth/register` | Create a login for an existing customer; ADMIN or MANAGER with `PERM_ADD`; validates customer and password policy (8–72 chars) | Session (ADMIN/MANAGER + `PERM_ADD`) + CSRF |
| GET | `/api/v1/auth/getAllUsers` | List all users | ADMIN only |
| GET | `/api/v1/auth/users?page=0&size=20` | Paged list of login accounts (`content`, `page`, `size`, `totalElements`, `totalPages`); size 1–100 | ADMIN or MANAGER |
| GET | `/api/v1/auth/users/roles` | Role names from the `roles` table, sorted (e.g. `["ADMIN","CUSTOMER","MANAGER"]`) | ADMIN or MANAGER |
| GET | `/api/v1/auth/users/{id}` | View one login account | ADMIN or MANAGER |
| POST | `/api/v1/auth/users` | Create a login for an existing customer; role defaults to CUSTOMER | ADMIN or MANAGER with `PERM_ADD` + CSRF |
| PUT | `/api/v1/auth/users/{id}` | Update email, password (optional), role, and enabled; `customerId` is immutable | ADMIN or MANAGER with `PERM_EDIT` + CSRF |
| DELETE | `/api/v1/auth/users/{id}` | Permanently delete a login account (204) | ADMIN or MANAGER with `PERM_DELETE` + CSRF |

Staff without the required permission get `403`. With the seeded permissions, MANAGER cannot delete logins.
MANAGER cannot view, create, update, delete, or assign the ADMIN role; those requests return `403`. Users cannot delete, disable, or change the role of their own account (`400`), and the last enabled ADMIN cannot be removed or demoted (`400`).

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
docker build -t authentication-service -f Authentication/Dockerfile .
docker run -p 8084:8084 authentication-service
```

Build from the parent repository root. The image uses working-tree sources, not remote `main`. For the complete local stack, run `docker compose up -d --build frontend-gateway` from that root.
