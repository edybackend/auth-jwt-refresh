using System.Net.Mail;
using Auth.Api.Data;
using Dapper;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace Auth.Api.Accounts;

public sealed record Account(string Id, string Email, IReadOnlyList<string> Roles);

public enum LoginStatus
{
    Succeeded,
    InvalidCredentials,
    LockedOut,
}

public sealed record LoginResult(LoginStatus Status, Account? Account = null, DateTimeOffset? LockedUntil = null);

public sealed record RegisterResult(Account? Account, string? Field = null, string? Error = null, bool Conflict = false);

public sealed class AccountService(AuthDatabase database, TimeProvider clock, IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;

    public async Task<RegisterResult> RegisterAsync(string? email, string? password, CancellationToken ct)
    {
        email = email?.Trim();
        if (email is null || email.Length > 254 || !MailAddress.TryCreate(email, out _))
        {
            return new RegisterResult(null, "email", "A valid email address is required.");
        }

        if (PasswordPolicy.Check(password, email) is { } problem)
        {
            return new RegisterResult(null, "password", problem);
        }

        var account = new Account(Guid.CreateVersion7(clock.GetUtcNow()).ToString(), email, ["user"]);
        await using var db = await database.OpenAsync(ct);
        try
        {
            await db.ExecuteAsync(
                "INSERT INTO users (id, email, password_hash, roles, created_at) VALUES (@Id, @Email, @Hash, 'user', @Now)",
                new { account.Id, account.Email, Hash = PasswordHasher.Hash(password!), Now = clock.GetUtcNow().ToString("O") });
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // UNIQUE(email)
        {
            return new RegisterResult(null, "email", "An account with this email already exists.", Conflict: true);
        }

        return new RegisterResult(account);
    }

    /// <summary>
    /// Unknown email and wrong password give the same answer and cost the same (a hash is verified either way),
    /// so the endpoint cannot be used to find out which emails have accounts.
    /// </summary>
    public async Task<LoginResult> LoginAsync(string? email, string? password, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        await using var db = await database.OpenAsync(ct);
        var user = await db.QuerySingleOrDefaultAsync<UserRow>(
            "SELECT id AS Id, email AS Email, password_hash AS PasswordHash, roles AS Roles, failed_logins AS FailedLogins, first_failure_at AS FirstFailureAt, locked_until AS LockedUntil FROM users WHERE email = @email",
            new { email = email?.Trim() ?? string.Empty });

        if (user?.LockedUntil is { } lockedUntil && lockedUntil > now.ToUnixTimeMilliseconds())
        {
            return new LoginResult(LoginStatus.LockedOut, LockedUntil: DateTimeOffset.FromUnixTimeMilliseconds(lockedUntil));
        }

        var valid = PasswordHasher.Verify(password ?? string.Empty, user?.PasswordHash ?? PasswordHasher.Dummy) && user is not null;
        if (user is null)
        {
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        if (valid)
        {
            await db.ExecuteAsync("UPDATE users SET failed_logins = 0, first_failure_at = NULL, locked_until = NULL WHERE id = @Id", new { user.Id });
            return new LoginResult(LoginStatus.Succeeded, user.ToAccount());
        }

        // Count failures inside a sliding window; the Nth failure locks the account for the window's length.
        var windowStart = now - _options.LockoutWindow;
        var failures = user.FirstFailureAt is { } first && first >= windowStart.ToUnixTimeMilliseconds() ? user.FailedLogins + 1 : 1;
        var firstFailure = failures == 1 ? now.ToUnixTimeMilliseconds() : user.FirstFailureAt!.Value;
        long? lockUntil = failures >= _options.MaxFailedLogins ? (now + _options.LockoutWindow).ToUnixTimeMilliseconds() : null;
        await db.ExecuteAsync(
            "UPDATE users SET failed_logins = @failures, first_failure_at = @firstFailure, locked_until = @lockUntil WHERE id = @Id",
            new { failures, firstFailure, lockUntil, user.Id });
        return new LoginResult(LoginStatus.InvalidCredentials);
    }

    public async Task<Account?> FindAsync(string id, CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        var user = await db.QuerySingleOrDefaultAsync<UserRow>(
            "SELECT id AS Id, email AS Email, password_hash AS PasswordHash, roles AS Roles, failed_logins AS FailedLogins, first_failure_at AS FirstFailureAt, locked_until AS LockedUntil FROM users WHERE id = @id",
            new { id });
        return user?.ToAccount();
    }

    public async Task<IReadOnlyList<Account>> ListAsync(CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        var rows = await db.QueryAsync<(string Id, string Email, string Roles)>("SELECT id, email, roles FROM users ORDER BY created_at");
        return [.. rows.Select(r => new Account(r.Id, r.Email, r.Roles.Split(',')))];
    }

    /// <summary>Demo accounts, created on the first start.</summary>
    public async Task SeedAsync(CancellationToken ct)
    {
        await using var db = await database.OpenAsync(ct);
        if (await db.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM users") > 0)
        {
            return;
        }

        foreach (var (email, roles) in new[] { ("admin@example.com", "user,admin"), ("user@example.com", "user") })
        {
            await db.ExecuteAsync(
                "INSERT INTO users (id, email, password_hash, roles, created_at) VALUES (@Id, @email, @Hash, @roles, @Now)",
                new { Id = Guid.CreateVersion7().ToString(), email, Hash = PasswordHasher.Hash("correct-horse-battery"), roles, Now = clock.GetUtcNow().ToString("O") });
        }
    }

    private sealed record UserRow(string Id, string Email, string PasswordHash, string Roles, long FailedLogins, long? FirstFailureAt, long? LockedUntil)
    {
        public Account ToAccount() => new(Id, Email, Roles.Split(','));
    }
}
