using System.Net;
using System.Net.Http.Json;

namespace Auth.IntegrationTests;

public sealed class LoginTests : IDisposable
{
    private readonly AuthApp _app = new();
    private readonly HttpClient _client;

    public LoginTests() => _client = _app.Browser();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_signed_in_user_can_call_the_api_and_roles_are_enforced()
    {
        var user = await _client.LoginAsync("user@example.com");
        var admin = await _client.LoginAsync("admin@example.com");

        Assert.Equal(HttpStatusCode.OK, await _client.GetStatusAsync("/api/me", user.AccessToken));
        Assert.Equal(HttpStatusCode.Forbidden, await _client.GetStatusAsync("/api/admin/users", user.AccessToken));
        Assert.Equal(HttpStatusCode.OK, await _client.GetStatusAsync("/api/admin/users", admin.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, await _client.GetStatusAsync("/api/me", accessToken: null));
    }

    [Fact]
    public async Task The_refresh_cookie_is_out_of_reach_of_scripts_and_other_sites()
    {
        var signedIn = await _client.LoginAsync();
        var header = signedIn.SetCookieHeader.ToLowerInvariant();

        Assert.StartsWith("__secure-refresh=", header, StringComparison.Ordinal);
        Assert.Contains("httponly", header, StringComparison.Ordinal);
        Assert.Contains("secure", header, StringComparison.Ordinal);
        Assert.Contains("samesite=strict", header, StringComparison.Ordinal);
        Assert.Contains("path=/api/auth", header, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Wrong_password_and_unknown_email_look_the_same()
    {
        using var wrongPassword = await _client.PostAsJsonAsync("/api/auth/login", new { email = "user@example.com", password = "not-the-password" }, Ct);
        using var unknownEmail = await _client.PostAsJsonAsync("/api/auth/login", new { email = "nobody@example.com", password = "not-the-password" }, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, unknownEmail.StatusCode);
        Assert.Equal(
            (await wrongPassword.Content.ReadFromJsonAsync<Dictionary<string, object>>(Ct))!["detail"].ToString(),
            (await unknownEmail.Content.ReadFromJsonAsync<Dictionary<string, object>>(Ct))!["detail"].ToString());
    }

    [Fact]
    public async Task Five_failures_lock_the_account_even_for_the_right_password_until_the_window_passes()
    {
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, await _client.PostStatusAsync("/api/auth/login", new { email = "user@example.com", password = "not-the-password" }));
        }

        using var locked = await _client.PostAsJsonAsync("/api/auth/login", new { email = "user@example.com", password = Http.Password }, Ct);
        Assert.Equal(HttpStatusCode.Locked, locked.StatusCode);
        Assert.Equal(TimeSpan.FromMinutes(15), locked.Headers.RetryAfter!.Delta);

        _app.Clock.Advance(TimeSpan.FromMinutes(16));
        await _client.LoginAsync("user@example.com");
    }

    [Fact]
    public async Task Failures_outside_the_window_do_not_add_up()
    {
        for (var i = 0; i < 4; i++)
        {
            await _client.PostStatusAsync("/api/auth/login", new { email = "user@example.com", password = "not-the-password" });
        }

        _app.Clock.Advance(TimeSpan.FromMinutes(20));
        await _client.PostStatusAsync("/api/auth/login", new { email = "user@example.com", password = "not-the-password" });

        await _client.LoginAsync("user@example.com"); // 1 failure in the current window, not 5
    }

    [Theory]
    [InlineData("not-an-email", "correct horse battery staple", HttpStatusCode.BadRequest)]
    [InlineData("dana@example.com", "short", HttpStatusCode.BadRequest)]
    [InlineData("dana@example.com", "password1234", HttpStatusCode.BadRequest)]
    [InlineData("USER@example.com", "correct horse battery staple", HttpStatusCode.Conflict)]
    [InlineData("dana@example.com", "correct horse battery staple", HttpStatusCode.Created)]
    public async Task Registration_rules(string email, string password, HttpStatusCode expected) =>
        Assert.Equal(expected, await _client.PostStatusAsync("/api/auth/register", new { email, password }));

    [Fact]
    public async Task A_new_account_can_sign_in_with_the_user_role()
    {
        await _client.PostStatusAsync("/api/auth/register", new { email = "dana@example.com", password = "correct horse battery staple" });

        var signedIn = await _client.LoginAsync("dana@example.com", "correct horse battery staple");

        Assert.Equal(HttpStatusCode.Forbidden, await _client.GetStatusAsync("/api/admin/users", signedIn.AccessToken));
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }
}
