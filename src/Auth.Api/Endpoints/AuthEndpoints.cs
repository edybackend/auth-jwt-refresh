using System.Security.Claims;
using Auth.Api.Accounts;
using Auth.Api.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Auth.Api.Endpoints;

public sealed record Credentials(string? Email, string? Password);

public sealed record TokenResponse(string AccessToken, string TokenType, int ExpiresIn, Account User);

internal static class AuthEndpoints
{
    /// <summary>
    /// <c>__Secure-</c> prefix: browsers only accept it with <c>Secure</c>. <c>HttpOnly</c> keeps it away from scripts (XSS),
    /// <c>SameSite=Strict</c> keeps it off cross-site requests (CSRF), and the path limits it to the auth endpoints.
    /// </summary>
    public const string RefreshCookie = "__Secure-refresh";
    private const string CookiePath = "/api/auth";

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var auth = app.MapGroup("/api/auth").WithTags("Auth");

        auth.MapPost("/register", async (Credentials request, AccountService accounts, CancellationToken ct) =>
        {
            var result = await accounts.RegisterAsync(request.Email, request.Password, ct);
            return result switch
            {
                { Account: { } account } => Results.Created("/api/me", account),
                { Conflict: true } => Results.Problem(result.Error, statusCode: StatusCodes.Status409Conflict),
                _ => Results.ValidationProblem(new Dictionary<string, string[]> { [result.Field!] = [result.Error!] }),
            };
        })
            .WithSummary("Create an account (password: 12+ characters, not a common one)");

        auth.MapPost("/login", async (Credentials request, HttpContext http, AccountService accounts, RefreshSessions sessions, AccessTokenIssuer issuer, TimeProvider clock, CancellationToken ct) =>
        {
            var result = await accounts.LoginAsync(request.Email, request.Password, ct);
            switch (result.Status)
            {
                case LoginStatus.LockedOut:
                    http.Response.Headers.RetryAfter = Math.Ceiling((result.LockedUntil!.Value - clock.GetUtcNow()).TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
                    return Results.Problem("Too many failed attempts. The account is locked for a while.", statusCode: StatusCodes.Status423Locked);
                case LoginStatus.InvalidCredentials:
                    return Results.Problem("Wrong email or password.", statusCode: StatusCodes.Status401Unauthorized);
            }

            var (refreshToken, sessionId) = await sessions.StartAsync(result.Account!.Id, http.Request.Headers.UserAgent.ToString(), ct);
            SetRefreshCookie(http, refreshToken);
            var access = issuer.Issue(result.Account, sessionId);
            return Results.Ok(new TokenResponse(access.Token, "Bearer", access.ExpiresIn, result.Account));
        })
            .RequireRateLimiting("login")
            .WithSummary("Sign in: access token in the body, refresh token in an HttpOnly cookie");

        auth.MapPost("/refresh", async (HttpContext http, RefreshSessions sessions, AccountService accounts, AccessTokenIssuer issuer, CancellationToken ct) =>
        {
            var result = await sessions.RotateAsync(http.Request.Cookies[RefreshCookie], ct);
            if (result.Status != RefreshStatus.Rotated || await accounts.FindAsync(result.UserId!, ct) is not { } account)
            {
                ClearRefreshCookie(http);
                return Results.Problem(
                    result.Status == RefreshStatus.ReuseDetected ? "This session was revoked because a refresh token was used twice." : "Sign in again.",
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            SetRefreshCookie(http, result.NewToken!);
            var access = issuer.Issue(account, result.SessionId!);
            return Results.Ok(new TokenResponse(access.Token, "Bearer", access.ExpiresIn, account));
        })
            .WithSummary("New access token from the refresh cookie; the refresh token is rotated");

        auth.MapPost("/logout", async (HttpContext http, RefreshSessions sessions, CancellationToken ct) =>
        {
            await sessions.RevokeByTokenAsync(http.Request.Cookies[RefreshCookie], ct);
            ClearRefreshCookie(http);
            return Results.NoContent();
        })
            .WithSummary("End this session");

        auth.MapPost("/logout-all", async (ClaimsPrincipal user, HttpContext http, RefreshSessions sessions, CancellationToken ct) =>
        {
            await sessions.RevokeAllAsync(UserId(user), ct);
            ClearRefreshCookie(http);
            return Results.NoContent();
        })
            .RequireAuthorization()
            .WithSummary("End every session of the signed-in user");

        auth.MapGet("/sessions", async (ClaimsPrincipal user, RefreshSessions sessions, CancellationToken ct) =>
            Results.Ok(await sessions.ListActiveAsync(UserId(user), user.FindFirstValue("sid"), ct)))
            .RequireAuthorization()
            .WithSummary("Active sessions (devices) of the signed-in user");

        auth.MapDelete("/sessions/{id}", async (string id, ClaimsPrincipal user, RefreshSessions sessions, CancellationToken ct) =>
            await sessions.RevokeAsync(UserId(user), id, ct)
                ? Results.NoContent()
                : Results.Problem("No such active session.", statusCode: StatusCodes.Status404NotFound))
            .RequireAuthorization()
            .WithSummary("Sign one device out (at its next refresh)");

        return app;
    }

    public static IEndpointRouteBuilder MapApiEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/me", (ClaimsPrincipal user) => Results.Ok(new
        {
            Id = UserId(user),
            Email = user.FindFirstValue(JwtRegisteredClaimNames.Email),
            Roles = user.FindAll("role").Select(c => c.Value),
            Session = user.FindFirstValue("sid"),
        }))
            .RequireAuthorization()
            .WithTags("API")
            .WithSummary("Who am I (any signed-in user)");

        app.MapGet("/api/admin/users", async (AccountService accounts, CancellationToken ct) => Results.Ok(await accounts.ListAsync(ct)))
            .RequireAuthorization("admin")
            .WithTags("API")
            .WithSummary("All accounts (admin role only)");

        return app;
    }

    private static string UserId(ClaimsPrincipal user) => user.FindFirstValue(JwtRegisteredClaimNames.Sub)!;

    private static void SetRefreshCookie(HttpContext http, string token) =>
        http.Response.Cookies.Append(RefreshCookie, token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = CookiePath,
            MaxAge = TimeSpan.FromDays(7),
            IsEssential = true,
        });

    private static void ClearRefreshCookie(HttpContext http) =>
        http.Response.Cookies.Delete(RefreshCookie, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = CookiePath });
}
