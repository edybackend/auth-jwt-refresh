# 002 · Tokens: signing, refresh rotation and reuse detection

## Context
Access tokens must be cheap to validate anywhere, and short-lived. Refresh tokens are long-lived, so they must be revocable, rotated on every use, and a stolen one must be detected.

## Behavior
- Access tokens are JWTs signed with **ES256**. The public key is published at `/.well-known/jwks.json` with a `kid`, so other services can validate tokens without sharing a secret. Claims: `sub`, `email`, `role`, `sid` (session), `iat`, `exp`, `iss`, `aud`.
- Refresh tokens are 256-bit random values. Only their SHA-256 hash is stored, with a **family** (one per login session).
- `POST /api/auth/refresh` (cookie) returns a new access token and **rotates** the refresh token: the old one is marked used, the new one belongs to the same family.
- **Reuse detection:** presenting a refresh token that was already used revokes its whole family (the session) and answers `401`. Either the attacker or the user used it first; both lose the session.
- `POST /api/auth/logout` revokes the current session; `POST /api/auth/logout-all` revokes every session of the user; `GET /api/auth/sessions` lists the active ones.
- Refresh sessions expire after 7 days of inactivity.

## Acceptance criteria
- The refresh cookie is `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api/auth`; it is never readable by JavaScript.
- The access token is kept in memory by the SPA (not `localStorage`).
- A tampered token, a token signed with another key, an expired token, or a token for another audience → `401`.
- Access tokens of a revoked session stop working at the next refresh (within 5 minutes). Instant revocation of access tokens is out of scope.

## Out of scope
Key rotation with several active keys (the JWKS format supports it), token introspection, OAuth 2.0 flows for third parties.
