# 001 · Accounts and login

## Context
A single-page app needs to sign users in and call protected APIs. Passwords must be stored safely, and guessing them must be slow and noisy.

## Behavior
- `POST /api/auth/register` with `email` and `password` creates a `user`.
- `POST /api/auth/login` returns a short-lived **access token** (JWT, 5 minutes) in the body and sets a **refresh token** cookie.
- `GET /api/me` returns the caller's id, email and roles. `GET /api/admin/users` requires the `admin` role.
- Sample accounts: `admin@example.com` (admin) and `user@example.com` (user), both with the password `correct-horse-battery`.

## Acceptance criteria
- Passwords are hashed with PBKDF2-SHA256, 600,000 iterations and a random salt per user; the hash records its parameters so they can be raised later.
- Password policy: at least 12 characters and not in a list of common passwords (`400` with the reason).
- Duplicate email (case-insensitive) → `409`.
- Wrong email or wrong password give the same `401` and take about the same time (no account enumeration).
- After 5 failed logins in 15 minutes an account is locked for 15 minutes (`423`), even with the right password.
- Missing or invalid token → `401`; valid token without the role → `403`.

## Out of scope
Email confirmation, password reset, MFA, social login.
