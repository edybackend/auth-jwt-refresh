using System.Security.Cryptography;
using System.Text;
using Auth.Api.Data;
using Dapper;
using Microsoft.Extensions.Options;

namespace Auth.Api.Tokens;

public enum RefreshStatus
{
    Rotated,

    /// <summary>Unknown token, or its session was revoked or expired.</summary>
    Invalid,

    /// <summary>A token that was already used came back: someone else has a copy. The whole session is revoked.</summary>
    ReuseDetected,
}

public sealed record RefreshResult(RefreshStatus Status, string? NewToken = null, string? UserId = null, string? SessionId = null);

public sealed record SessionView(string Id, string UserAgent, DateTimeOffset CreatedAt, DateTimeOffset LastUsedAt, bool Current);

/// <summary>
/// Refresh tokens with rotation and reuse detection. A login starts a session (the token family); every refresh
/// replaces the token; presenting a replaced token revokes the session. Only SHA-256 hashes are stored.
/// </summary>
public sealed partial class RefreshSessions(AuthDatabase database, TimeProvider clock, IOptions<AuthOptions> options, ILogger<RefreshSessions> logger)
{
    private readonly AuthOptions _options = options.Value;

    public async Task<(string Token, string SessionId)> StartAsync(string userId, string userAgent, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var sessionId = Guid.CreateVersion7(now).ToString();
        var token = NewToken();
        await using var db = await database.OpenAsync(ct);
        await using var tx = db.BeginTransaction();
        await db.ExecuteAsync(
            "INSERT INTO sessions (id, user_id, user_agent, created_at, last_used_at, expires_at) VALUES (@sessionId, @userId, @userAgent, @now, @now, @expires)",
            new { sessionId, userId, userAgent = Truncate(userAgent), now = now.ToUnixTimeMilliseconds(), expires = (now + _options.SessionIdleLifetime).ToUnixTimeMilliseconds() },
            tx);
        await db.ExecuteAsync(
            "INSERT INTO refresh_tokens (token_hash, session_id, created_at) VALUES (@hash, @sessionId, @now)",
            new { hash = Hash(token), sessionId, now = now.ToUnixTimeMilliseconds() },
            tx);
        tx.Commit();
        return (token, sessionId);
    }

    public async Task<RefreshResult> RotateAsync(string? token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token))
        {
            return new RefreshResult(RefreshStatus.Invalid);
        }

        var now = clock.GetUtcNow().ToUnixTimeMilliseconds();
        await using var db = await database.OpenAsync(ct);
        await using var tx = db.BeginTransaction(deferred: false); // BEGIN IMMEDIATE: two refreshes of one token cannot both win
        var row = await db.QuerySingleOrDefaultAsync<TokenRow>(
            """
            SELECT t.session_id AS SessionId, t.used_at AS UsedAt, s.user_id AS UserId, s.revoked_at AS RevokedAt, s.expires_at AS ExpiresAt
            FROM refresh_tokens t JOIN sessions s ON s.id = t.session_id WHERE t.token_hash = @hash
            """,
            new { hash = Hash(token) },
            tx);

        if (row is null || row.RevokedAt is not null || row.ExpiresAt <= now)
        {
            return new RefreshResult(RefreshStatus.Invalid);
        }

        if (row.UsedAt is not null)
        {
            await db.ExecuteAsync(
                "UPDATE sessions SET revoked_at = @now, revoke_reason = 'refresh token reuse' WHERE id = @SessionId",
                new { now, row.SessionId },
                tx);
            tx.Commit();
            LogReuse(row.UserId, row.SessionId);
            return new RefreshResult(RefreshStatus.ReuseDetected, UserId: row.UserId, SessionId: row.SessionId);
        }

        var next = NewToken();
        await db.ExecuteAsync("UPDATE refresh_tokens SET used_at = @now WHERE token_hash = @hash", new { now, hash = Hash(token) }, tx);
        await db.ExecuteAsync(
            "INSERT INTO refresh_tokens (token_hash, session_id, created_at) VALUES (@hash, @SessionId, @now)",
            new { hash = Hash(next), row.SessionId, now },
            tx);
        await db.ExecuteAsync(
            "UPDATE sessions SET last_used_at = @now, expires_at = @expires WHERE id = @SessionId",
            new { now, expires = now + (long)_options.SessionIdleLifetime.TotalMilliseconds, row.SessionId },
            tx);
        tx.Commit();
        return new RefreshResult(RefreshStatus.Rotated, next, row.UserId, row.SessionId);
    }

    /// <summary>Revokes the session the token belongs to (logout). Unknown tokens are ignored.</summary>
    public async Task RevokeByTokenAsync(string? token, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(token))
        {
            return;
        }

        await using var db = await database.OpenAsync(ct);
        await db.ExecuteAsync(
            "UPDATE sessions SET revoked_at = @now, revoke_reason = 'logout' WHERE revoked_at IS NULL AND id = (SELECT session_id FROM refresh_tokens WHERE token_hash = @hash)",
            new { now = clock.GetUtcNow().ToUnixTimeMilliseconds(), hash = Hash(token) });
    }

    /// <summary>Revokes one session of the user (from the sessions list). Returns false if it is not theirs or not active.</summary>
    public async Task<bool> RevokeAsync(string userId, string sessionId, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        return await db.ExecuteAsync(
            "UPDATE sessions SET revoked_at = @now, revoke_reason = 'revoked by user' WHERE id = @sessionId AND user_id = @userId AND revoked_at IS NULL",
            new { now = clock.GetUtcNow().ToUnixTimeMilliseconds(), sessionId, userId }) == 1;
    }

    public async Task<int> RevokeAllAsync(string userId, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        return await db.ExecuteAsync(
            "UPDATE sessions SET revoked_at = @now, revoke_reason = 'logout everywhere' WHERE user_id = @userId AND revoked_at IS NULL",
            new { now = clock.GetUtcNow().ToUnixTimeMilliseconds(), userId });
    }

    public async Task<IReadOnlyList<SessionView>> ListActiveAsync(string userId, string? currentSessionId, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        var rows = await db.QueryAsync<(string Id, string UserAgent, long CreatedAt, long LastUsedAt)>(
            "SELECT id, user_agent, created_at, last_used_at FROM sessions WHERE user_id = @userId AND revoked_at IS NULL AND expires_at > @now ORDER BY last_used_at DESC",
            new { userId, now = clock.GetUtcNow().ToUnixTimeMilliseconds() });
        return [.. rows.Select(r => new SessionView(r.Id, r.UserAgent, DateTimeOffset.FromUnixTimeMilliseconds(r.CreatedAt), DateTimeOffset.FromUnixTimeMilliseconds(r.LastUsedAt), r.Id == currentSessionId))];
    }

    private static string NewToken() => Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));

    private static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string Truncate(string value) => value.Length <= 200 ? value : value[..200];

    [LoggerMessage(Level = LogLevel.Warning, Message = "Refresh token reuse for user {UserId}: session {SessionId} revoked")]
    private partial void LogReuse(string userId, string sessionId);

    private sealed record TokenRow(string SessionId, long? UsedAt, string UserId, long? RevokedAt, long ExpiresAt);
}
