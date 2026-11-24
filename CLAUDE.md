# Engineering rules for AI agents

This file is loaded by Claude Code in every session. It defines how changes are made in this repository.
Hooks in `.claude/settings.json` enforce the parts that can be automated.

## Workflow
1. **Spec first.** A new behavior starts as a spec in `specs/NNN-name.md` (context, behavior, acceptance criteria, out of scope).
2. **Small steps.** One concern per commit, [Conventional Commits](https://www.conventionalcommits.org/) (`feat(tokens): ...`, `fix(spa): ...`).
3. **Definition of done** = the CI gates pass locally: `dotnet build` (warnings are errors), `dotnet test`, `dotnet format --verify-no-changes`, and in `web/` `npm run lint && npm run build`. The Stop hook blocks finishing while they are red.

## Layout
- `src/Auth.Api/Accounts`: users, password hashing and policy, lockout.
- `src/Auth.Api/Tokens`: signing key and JWKS, access tokens, refresh sessions (rotation, reuse detection).
- `src/Auth.Api/Endpoints`: HTTP only; the refresh cookie is set and cleared only here.
- `web/`: React SPA, built into `src/Auth.Api/wwwroot` (same origin as the API).

## Security rules
- **Never weaken token validation**: issuer, audience, lifetime and signature are always checked, only `ES256` is accepted. A hook blocks `Validate…= false`, `none` and similar.
- **The refresh cookie stays `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/api/auth`.** A hook blocks changes to those flags.
- **Refresh tokens are stored hashed** (SHA-256) and rotated on every use; a reused token revokes its session. Rotation runs in a `BEGIN IMMEDIATE` transaction.
- **The SPA keeps the access token in memory** and never in `localStorage`/`sessionStorage` (hook). Refreshes are single-flight: two parallel refreshes would trigger reuse detection.
- **Passwords**: PBKDF2-SHA256 with the iteration count stored in the hash; verification in constant time; unknown emails cost the same as wrong passwords.
- **Never log passwords or tokens** (hook). Log user ids and session ids.
- The signing key (`data/signing-key.pem`) is created at first start and never committed.

## C# conventions
- Classes `sealed` by default; file-scoped namespaces; `TimeProvider` everywhere time matters (token lifetime, lockout, session expiry) so tests can move the clock.
- Logging with `[LoggerMessage]`. No MediatR/AutoMapper.

## Never
- Edit the SQLite files or key files by hand. Blocked by hook.
- Read or write secrets (`.env`, keys). Blocked by permissions and hook.
- Disable an analyzer or a test to make the build pass.
- Add a dependency without a reason stated in the commit message.
