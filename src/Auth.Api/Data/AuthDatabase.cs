using Dapper;
using Microsoft.Data.Sqlite;

namespace Auth.Api.Data;

/// <summary>SQLite access for accounts and sessions. Each call opens a short-lived connection (pooled by the driver).</summary>
public sealed class AuthDatabase(string connectionString)
{
    public async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken = default)
    {
        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    public async Task InitializeAsync()
    {
        var file = new SqliteConnectionStringBuilder(connectionString).DataSource;
        if (Path.GetDirectoryName(Path.GetFullPath(file)) is { } directory)
        {
            Directory.CreateDirectory(directory);
        }

        await using var db = await OpenAsync();
        await db.ExecuteAsync("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (
                id               TEXT PRIMARY KEY,
                email            TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash    TEXT NOT NULL,
                roles            TEXT NOT NULL,          -- comma separated
                failed_logins    INTEGER NOT NULL DEFAULT 0,
                first_failure_at INTEGER NULL,           -- unix ms
                locked_until     INTEGER NULL,           -- unix ms
                created_at       TEXT NOT NULL
            );
            -- One row per login: the refresh token "family". Revoking it ends the session on every token it issued.
            CREATE TABLE IF NOT EXISTS sessions (
                id           TEXT PRIMARY KEY,
                user_id      TEXT NOT NULL REFERENCES users (id),
                user_agent   TEXT NOT NULL,
                created_at   INTEGER NOT NULL,
                last_used_at INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                revoked_at   INTEGER NULL,
                revoke_reason TEXT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions (user_id);
            -- Only the SHA-256 of a refresh token is stored: a leaked database does not leak usable tokens.
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions (id),
                created_at INTEGER NOT NULL,
                used_at    INTEGER NULL
            );
            """);
    }
}
