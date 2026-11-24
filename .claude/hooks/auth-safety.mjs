// PreToolUse hook: changes that quietly break authentication are blocked, with the reason.
import { readFileSync } from 'node:fs'

const input = JSON.parse(readFileSync(0, 'utf8'))
const filePath = (input.tool_input?.file_path ?? '').replaceAll('\\', '/')
if (/\/tests\//.test(filePath)) process.exit(0) // tests forge bad tokens on purpose

// Comments may mention the forbidden things ("not in localStorage"): only code is checked.
const written = (input.tool_input?.new_string ?? input.tool_input?.content ?? '')
  .split('\n')
  .map((line) => line.replace(/\/\/.*$/, ''))
  .join('\n')
const rules = [
  {
    files: /\.cs$/,
    pattern: /Validate(Lifetime|Issuer|Audience|IssuerSigningKey)\s*=\s*false|RequireSignedTokens\s*=\s*false|RequireExpirationTime\s*=\s*false|SecurityAlgorithms\.None|"none"/,
    why: 'it weakens token validation (lifetime, issuer, audience, signature or algorithm)',
  },
  {
    files: /\.cs$/,
    pattern: /HttpOnly\s*=\s*false|Secure\s*=\s*false|SameSiteMode\.None/,
    why: 'the refresh cookie must stay HttpOnly, Secure and SameSite=Strict',
  },
  {
    files: /\.cs$/,
    // A logging call that passes a password or token, or a [LoggerMessage] template with such a placeholder.
    pattern: /\.Log(Trace|Debug|Information|Warning|Error|Critical)\([^;]*\b(password|accessToken|refreshToken|token)\b|\{(Password|Token|AccessToken|RefreshToken)\}/i,
    why: 'it logs a password or a token',
  },
  {
    files: /\/web\/src\/.*\.(ts|tsx)$/,
    pattern: /localStorage|sessionStorage|document\.cookie/,
    why: 'tokens stay in memory (access) or in an HttpOnly cookie (refresh); web storage is readable by any injected script',
  },
]
const hit = rules.find((rule) => rule.files.test(filePath) && rule.pattern.test(written))
if (hit) {
  console.error(`Blocked: ${filePath} — ${hit.why}. See CLAUDE.md, "Security rules".`)
  process.exit(2)
}
