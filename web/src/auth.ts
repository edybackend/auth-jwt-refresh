// The access token lives only in this module's memory: not in localStorage, where any injected script could read it.
// The refresh token is an HttpOnly cookie the browser sends to /api/auth only; this code never sees it.

export type User = { id: string; email: string; roles: string[] }

type TokenResponse = { accessToken: string; expiresIn: number; user: User }

let accessToken: string | null = null
let expiresAt = 0
let refreshing: Promise<User | null> | null = null

export const currentToken = () => accessToken
export const tokenExpiresAt = () => expiresAt

function store(response: TokenResponse): User {
  accessToken = response.accessToken
  expiresAt = Date.now() + response.expiresIn * 1000
  return response.user
}

export function forget() {
  accessToken = null
  expiresAt = 0
}

async function problem(res: Response): Promise<string> {
  try {
    const body = await res.json()
    if (body.errors) return Object.values(body.errors).flat().join(' ')
    return body.detail ?? body.title ?? `HTTP ${res.status}`
  } catch {
    return `HTTP ${res.status}`
  }
}

export async function login(email: string, password: string): Promise<User> {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) throw new Error(await problem(res))
  return store(await res.json())
}

export async function register(email: string, password: string): Promise<void> {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) throw new Error(await problem(res))
}

/**
 * One refresh at a time. Two parallel refreshes would send the same refresh token twice, and the server would
 * (correctly) treat the second one as a stolen token and revoke the session.
 */
export function refresh(): Promise<User | null> {
  refreshing ??= (async () => {
    try {
      const res = await fetch('/api/auth/refresh', { method: 'POST' })
      if (!res.ok) {
        forget()
        return null
      }
      return store(await res.json())
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

/** fetch with the access token; on 401 it refreshes once and retries. */
export async function api(url: string, init: RequestInit = {}): Promise<Response> {
  const send = () =>
    fetch(url, { ...init, headers: { ...init.headers, ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) } })
  let res = await send()
  if (res.status === 401 && (await refresh())) {
    res = await send()
  }
  return res
}

export async function logout(everywhere = false): Promise<void> {
  if (everywhere) await api('/api/auth/logout-all', { method: 'POST' })
  await fetch('/api/auth/logout', { method: 'POST' })
  forget()
}

/** The token's header and payload, for display. The signature is checked by the server, never here. */
export function decode(token: string): { header: unknown; payload: Record<string, unknown> } {
  const part = (i: number) => JSON.parse(atob(token.split('.')[i].replace(/-/g, '+').replace(/_/g, '/')))
  return { header: part(0), payload: part(1) }
}
