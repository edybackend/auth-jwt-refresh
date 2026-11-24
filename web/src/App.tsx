import { useEffect, useState } from 'react'
import { type User, api, currentToken, decode, login, logout, refresh, register, tokenExpiresAt } from './auth.ts'

type Session = { id: string; userAgent: string; createdAt: string; lastUsedAt: string; current: boolean }
type Call = { label: string; status: number; body: string }

export function App() {
  const [user, setUser] = useState<User | null>(null)
  const [ready, setReady] = useState(false)

  // A reload keeps the user signed in: the refresh cookie survives it, the in-memory access token does not.
  useEffect(() => {
    let active = true
    refresh().then((u) => {
      if (active) {
        setUser(u)
        setReady(true)
      }
    })
    return () => {
      active = false
    }
  }, [])

  if (!ready) return <main className="center">Loading…</main>
  return (
    <main>
      <header>
        <h1>Auth · JWT + refresh rotation</h1>
        <p>
          Access token (5 min, ES256) in memory, refresh token in an <code>HttpOnly</code> cookie, rotated on every use.
        </p>
      </header>
      {user ? <Home user={user} onSignOut={() => setUser(null)} /> : <SignIn onSignedIn={setUser} />}
    </main>
  )
}

function SignIn({ onSignedIn }: { onSignedIn: (u: User) => void }) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('user@example.com')
  const [password, setPassword] = useState('correct-horse-battery')
  const [message, setMessage] = useState<string>()

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setMessage(undefined)
    try {
      if (mode === 'register') {
        await register(email, password)
      }
      onSignedIn(await login(email, password))
    } catch (err) {
      setMessage((err as Error).message)
    }
  }

  return (
    <form className="card narrow" onSubmit={submit}>
      <div className="tabs">
        <button type="button" className={mode === 'login' ? 'active' : ''} onClick={() => setMode('login')}>
          Sign in
        </button>
        <button type="button" className={mode === 'register' ? 'active' : ''} onClick={() => setMode('register')}>
          Create account
        </button>
      </div>
      <label>
        Email
        <input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
      </label>
      <label>
        Password
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
        />
      </label>
      {message && <p className="error">{message}</p>}
      <button type="submit">{mode === 'login' ? 'Sign in' : 'Create and sign in'}</button>
      <p className="hint">
        Demo accounts: <code>user@example.com</code> and <code>admin@example.com</code>, password{' '}
        <code>correct-horse-battery</code>. Five wrong passwords lock the account for 15 minutes.
      </p>
    </form>
  )
}

function Home({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [calls, setCalls] = useState<Call[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [now, setNow] = useState(() => Date.now())

  async function loadSessions() {
    const res = await api('/api/auth/sessions')
    if (res.ok) setSessions(await res.json())
  }

  useEffect(() => {
    let active = true
    api('/api/auth/sessions').then(async (res) => {
      if (active && res.ok) setSessions(await res.json())
    })
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [])

  async function call(label: string, url: string, init?: RequestInit) {
    const res = await api(url, init)
    const text = await res.text()
    setCalls((previous) => [{ label, status: res.status, body: text }, ...previous].slice(0, 6))
    if (res.status === 401) onSignOut()
  }

  async function revoke(id: string) {
    await api(`/api/auth/sessions/${id}`, { method: 'DELETE' })
    await loadSessions()
  }

  const token = currentToken()
  const claims = token ? decode(token) : null
  const seconds = Math.max(0, Math.round((tokenExpiresAt() - now) / 1000))

  return (
    <>
      <section className="grid">
        <div className="card">
          <h2>{user.email}</h2>
          <p>
            Roles: <strong>{user.roles.join(', ')}</strong>
          </p>
          <p>
            Access token expires in <strong>{seconds}s</strong>; the next API call after that refreshes it silently.
          </p>
          <div className="actions">
            <button onClick={() => call('GET /api/me', '/api/me')}>Call /api/me</button>
            <button onClick={() => call('GET /api/admin/users', '/api/admin/users')}>Call admin endpoint</button>
            <button
              className="secondary"
              onClick={async () => {
                await refresh()
                await loadSessions()
              }}
            >
              Refresh now
            </button>
          </div>
          <div className="actions">
            <button className="secondary" onClick={async () => { await logout(); onSignOut() }}>
              Sign out
            </button>
            <button className="secondary" onClick={async () => { await logout(true); onSignOut() }}>
              Sign out everywhere
            </button>
          </div>
        </div>
        <div className="card">
          <h2>Access token</h2>
          <pre>{claims ? JSON.stringify(claims, null, 2) : '—'}</pre>
        </div>
      </section>

      <section className="card">
        <h2>API calls</h2>
        <table>
          <tbody>
            {calls.map((c, i) => (
              <tr key={i}>
                <td>{c.label}</td>
                <td className={c.status < 300 ? 'ok' : 'bad'}>{c.status}</td>
                <td>
                  <code>{c.body.slice(0, 140)}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Active sessions</h2>
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Signed in</th>
              <th>Last refresh</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td>
                  {s.userAgent.slice(0, 60) || 'unknown'} {s.current && <strong>(this one)</strong>}
                </td>
                <td>{new Date(s.createdAt).toLocaleString()}</td>
                <td>{new Date(s.lastUsedAt).toLocaleString()}</td>
                <td>{!s.current && <button className="secondary" onClick={() => revoke(s.id)}>Revoke</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  )
}
