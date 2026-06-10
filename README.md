# OIDC Provider

A custom OpenID Connect (OIDC) Identity Provider (IdP) built from scratch. It does not rely on heavy third-party authentication platforms (like Auth0) or off-the-shelf packages (like the `oidc-provider` npm package); instead, it manually implements the core OIDC specifications—specifically the **Authorization Code Flow with PKCE**.

## Why This Exists

Most authentication solutions are used as black boxes. This project implements the core OIDC specification manually — authorization endpoint, token exchange, PKCE verification, refresh token lifecycle, and JWKS-based key discovery — to make every cryptographic and protocol decision explicit and auditable.

## What It Does

- Validates authorization requests per the OIDC spec (client registration, redirect URI matching, scope enforcement)
- Authenticates users with bcrypt-hashed passwords
- Generates authorization codes stored as SHA-256 hashes (raw code never touches the database)
- Exchanges codes for signed JWTs (RS256) with PKCE S256 verification
- Issues refresh tokens with rotation and family-based reuse detection
- Serves a `/userinfo` endpoint that filters claims based on the access token's scope
- Exposes `/.well-known/openid-configuration` and `/.well-known/jwks.json` for discovery
- Includes a demo client that runs the full flow end-to-end in the browser

## Tech Stack

| Layer         | Choice                                              |
| ------------- | --------------------------------------------------- |
| Runtime       | Node.js with TypeScript (ESM)                       |
| Framework     | Express 5                                           |
| Database      | PostgreSQL 17 (Docker)                              |
| ORM           | Drizzle ORM                                         |
| Signing       | RS256 via `jsonwebtoken`                            |
| JWKS          | `node-jose` for JWK conversion                      |
| Hashing       | `bcrypt` (cost 12) for passwords and client secrets |
| Rate Limiting | `express-rate-limit`                                |

## Architecture

```
Browser                    OIDC Provider (:8080)                  Database
  │                              │                                   │
  │  GET /authorize              │                                   │
  │─────────────────────────────>│  validate client_id,               │
  │  302 → /login.html           │  redirect_uri, scope              │
  │<─────────────────────────────│                                   │
  │                              │                                   │
  │  POST /authorize/callback    │                                   │
  │─────────────────────────────>│  bcrypt.compare(password)         │
  │  { session }                 │─────────────────────────────────>│
  │<─────────────────────────────│                                   │
  │                              │                                   │
  │  POST /authorize/consent     │                                   │
  │─────────────────────────────>│  SHA-256(random) → store hash     │
  │  { redirect → ?code=X }     │─────────────────────────────────>│
  │<─────────────────────────────│                                   │
  │                              │                                   │
  │  POST /token                 │                                   │
  │─────────────────────────────>│  verify code hash, PKCE,          │
  │  { access_token, id_token,   │  mark used, issue JWT (RS256)     │
  │    refresh_token }           │─────────────────────────────────>│
  │<─────────────────────────────│                                   │
  │                              │                                   │
  │  GET /userinfo               │                                   │
  │─────────────────────────────>│  verify JWT, filter by scope      │
  │  { sub, email, name, ... }   │─────────────────────────────────>│
  │<─────────────────────────────│                                   │
```

### Token Security Model

| Artifact           | Storage                            | Lifetime                        |
| ------------------ | ---------------------------------- | ------------------------------- |
| Authorization code | SHA-256 hash in DB                 | 10 minutes, single-use          |
| Access token       | Signed JWT (RS256), not stored     | 1 hour                          |
| Refresh token      | SHA-256 hash in DB, family-tracked | 7 days, single-use per rotation |
| ID token           | Signed JWT (RS256), not stored     | 1 hour                          |
| Passwords          | bcrypt hash (cost 12)              | Permanent                       |
| Client secrets     | bcrypt hash (cost 12)              | Permanent                       |

### Refresh Token Rotation

Each refresh token belongs to a `family_id`. On use, the current token is revoked and a new one is issued with the same family. If a revoked token is replayed, the entire family is invalidated — forcing the user to re-authenticate. This detects token theft.

## Setup

### Prerequisites

- Node.js ≥ 18
- pnpm
- Docker

### Steps

```bash
# 1. Clone and install
git clone https://github.com/ghushitkumarchutia/oidc-provider
cd oidc-provider
pnpm install

# 2. Generate RSA keys
chmod +x key-gen.sh
./key-gen.sh

# 3. Configure environment
cp .env.example .env

# 4. Start PostgreSQL
docker compose up -d

# 5. Run migrations
pnpm db:migrate

# 6. Seed demo data
pnpm seed
```

## Environment Variables

| Variable       | Description                  | Default                                                 |
| -------------- | ---------------------------- | ------------------------------------------------------- |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://admin:admin@localhost:5434/oidc_provider` |
| `PORT`         | Server port                  | `8080`                                                  |

Both are defined in `.env`. The database runs on port **5434** (host) to avoid conflicts with any local PostgreSQL on 5432.

## Usage

### Start the Provider

```bash
pnpm dev
```

Runs on `http://localhost:8080`. Uses `tsc-watch` for live recompilation.

### Start the Demo Client

```bash
pnpm demo:client
```

Runs on `http://localhost:3000`. Open it in a browser to walk through the full OIDC flow.

### Demo Credentials

| Type   | ID / Email         | Secret / Password |
| ------ | ------------------ | ----------------- |
| Client | `demo-app`         | `demo-secret`     |
| User   | `john@example.com` | `password123`     |

### Available Endpoints

| Method | Path                                | Purpose                                 |
| ------ | ----------------------------------- | --------------------------------------- |
| `GET`  | `/.well-known/openid-configuration` | Discovery document                      |
| `GET`  | `/.well-known/jwks.json`            | Public key in JWK format                |
| `GET`  | `/authorize`                        | Start authorization flow                |
| `POST` | `/authorize/callback`               | Authenticate user credentials           |
| `POST` | `/authorize/consent`                | Approve or deny consent                 |
| `POST` | `/signup`                           | Register a new user                     |
| `POST` | `/token`                            | Exchange code or refresh token          |
| `GET`  | `/userinfo`                         | Get user claims (Bearer token required) |
| `GET`  | `/health`                           | Health check                            |

### Client Authentication

The `/token` endpoint supports two methods:

**client_secret_post** — credentials in the request body:

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...&client_id=demo-app&client_secret=demo-secret
```

**client_secret_basic** — credentials in the Authorization header:

```
POST /token
Authorization: Basic base64(demo-app:demo-secret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...
```

## Project Structure

```
oidc-provider/
├── cert/                          # RSA key pair (gitignored)
│   ├── private-key.pem
│   └── public-key.pub
├── demo-client/                   # Standalone browser client for testing
│   ├── index.html                 #   Landing page — generates PKCE, redirects to /authorize
│   ├── callback.html              #   Handles code exchange, displays tokens and userinfo
│   └── serve.json                 #   Clean URL config for static server
├── public/                        # Provider UI pages (served as static files)
│   ├── login.html                 #   Login form
│   ├── signup.html                #   Registration form
│   └── consent.html               #   Scope approval screen
├── src/
│   ├── common/
│   │   ├── cert.ts                #   Loads RSA keys from disk
│   │   ├── token.ts               #   JWT sign/verify helpers (RS256)
│   │   └── middleware.ts          #   Rate limiter, global error handler
│   ├── db/
│   │   ├── schema.ts              #   Drizzle table definitions
│   │   └── index.ts               #   Database connection
│   ├── modules/
│   │   ├── discovery/
│   │   │   └── discovery.routes.ts
│   │   ├── auth/
│   │   │   ├── auth.routes.ts     #   /authorize, /authorize/callback, /authorize/consent, /signup
│   │   │   └── auth.service.ts    #   Validation, consent sessions, code generation
│   │   ├── token/
│   │   │   ├── token.routes.ts    #   POST /token
│   │   │   └── token.service.ts   #   Code exchange, PKCE, refresh rotation
│   │   └── userinfo/
│   │       └── userinfo.routes.ts #   GET /userinfo
│   └── index.ts                   #   Express app entry point
├── docker-compose.yml             #   PostgreSQL 17
├── drizzle.config.js              #   Drizzle Kit config
├── key-gen.sh                     #   RSA key generation script
├── seed.ts                        #   Seeds demo client and user
├── tsconfig.json
└── package.json
```

## Testing

### Manual Tests

```bash
# Discovery
curl http://localhost:8080/.well-known/openid-configuration

# Health
curl http://localhost:8080/health

# Signup
curl -X POST http://localhost:8080/signup \
  -H "Content-Type: application/json" \
  -d '{"firstName":"Jane","email":"jane@test.com","password":"password123"}'

# UserInfo (with a valid access_token)
curl -H "Authorization: Bearer <access_token>" http://localhost:8080/userinfo
```

### End-to-End via Demo Client

Start both the provider (`pnpm dev`) and the demo client (`pnpm demo:client`), then open `http://localhost:3000` in a browser and walk through the full flow: PKCE generation → login → consent → token exchange → userinfo display → token refresh.

## Scripts

| Command            | Description                          |
| ------------------ | ------------------------------------ |
| `pnpm dev`         | Start provider with live reload      |
| `pnpm seed`        | Seed demo client and user            |
| `pnpm demo:client` | Serve demo client on port 3000       |
| `pnpm db:generate` | Generate migration files from schema |
| `pnpm db:migrate`  | Apply pending migrations             |
| `pnpm db:studio`   | Open Drizzle Studio (database GUI)   |

## Limitations

- **In-memory consent sessions.** Consent sessions are stored in a `Map` and lost on server restart. In production, use Redis with TTL-based expiration.
- **Single-instance only.** No shared session store, so horizontal scaling requires a distributed cache.
- **No HTTPS.** Runs over HTTP for local development. Production requires TLS termination.
- **No account recovery.** No password reset or email verification flow.
- **Static RSA key.** A single key pair is used. Production systems rotate keys and support multiple `kid` values in JWKS.
- **Demo client exposes client_secret.** The demo client uses `client_secret_post` from the browser for demonstration purposes. In production, browser-based clients are public clients using only PKCE, with token exchange handled by a backend-for-frontend.

## License

This project is licensed under the [MIT License](LICENSE).
