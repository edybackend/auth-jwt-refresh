using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Auth.IntegrationTests;

public sealed class RefreshTests : IDisposable
{
    private readonly AuthApp _app = new();
    private readonly HttpClient _client;

    public RefreshTests() => _client = _app.Browser();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Every_refresh_rotates_the_refresh_token()
    {
        var first = await _client.LoginAsync();

        using var response = await _client.RefreshAsync(first.RefreshCookie);
        var second = await Http.ReadAsync(response);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotEqual(first.RefreshCookie, second.RefreshCookie);
        Assert.Equal(HttpStatusCode.OK, (await _client.RefreshAsync(second.RefreshCookie)).StatusCode);
    }

    [Fact]
    public async Task Reusing_a_rotated_token_revokes_the_whole_session()
    {
        var stolen = await _client.LoginAsync();
        var legitimate = await Http.ReadAsync(await _client.RefreshAsync(stolen.RefreshCookie)); // the user refreshed

        using var attacker = await _client.RefreshAsync(stolen.RefreshCookie); // the attacker replays the old token

        Assert.Equal(HttpStatusCode.Unauthorized, attacker.StatusCode);
        Assert.Contains("used twice", await attacker.Content.ReadAsStringAsync(Ct), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.RefreshAsync(legitimate.RefreshCookie)).StatusCode); // the session is gone for both
    }

    [Fact]
    public async Task Two_simultaneous_refreshes_of_one_token_cannot_both_succeed()
    {
        var signedIn = await _client.LoginAsync();

        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => _client.RefreshAsync(signedIn.RefreshCookie)));

        Assert.True(results.Count(r => r.StatusCode == HttpStatusCode.OK) <= 1, "at most one refresh may win");
        Assert.True(results.Count(r => r.StatusCode == HttpStatusCode.Unauthorized) >= 4);
    }

    [Fact]
    public async Task Logout_ends_the_session()
    {
        var signedIn = await _client.LoginAsync();
        using var logout = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout");
        logout.Headers.Add("Cookie", signedIn.RefreshCookie);

        using var response = await _client.SendAsync(logout, Ct);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.RefreshAsync(signedIn.RefreshCookie)).StatusCode);
    }

    [Fact]
    public async Task A_user_sees_their_sessions_and_can_sign_one_device_out()
    {
        var laptop = await _client.LoginAsync(userAgent: "laptop");
        var phone = await _client.LoginAsync(userAgent: "phone");
        var sessions = await SessionsAsync(laptop.AccessToken);
        Assert.Equal(["laptop", "phone"], sessions.Select(s => s.GetProperty("userAgent").GetString()).Order());

        var phoneSession = sessions.Single(s => s.GetProperty("userAgent").GetString() == "phone").GetProperty("id").GetString();
        using var revoke = new HttpRequestMessage(HttpMethod.Delete, $"/api/auth/sessions/{phoneSession}");
        revoke.Headers.Authorization = new AuthenticationHeaderValue("Bearer", laptop.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await _client.SendAsync(revoke, Ct)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.RefreshAsync(phone.RefreshCookie)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.RefreshAsync(laptop.RefreshCookie)).StatusCode);
    }

    [Fact]
    public async Task Logout_everywhere_ends_every_session_of_the_user_only()
    {
        var laptop = await _client.LoginAsync(userAgent: "laptop");
        var phone = await _client.LoginAsync(userAgent: "phone");
        var admin = await _client.LoginAsync("admin@example.com");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout-all");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", laptop.AccessToken);

        await _client.SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.RefreshAsync(laptop.RefreshCookie)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.RefreshAsync(phone.RefreshCookie)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.RefreshAsync(admin.RefreshCookie)).StatusCode);
    }

    [Fact]
    public async Task A_session_idle_for_more_than_seven_days_expires()
    {
        var signedIn = await _client.LoginAsync();
        _app.Clock.Advance(TimeSpan.FromDays(8));

        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.RefreshAsync(signedIn.RefreshCookie)).StatusCode);
    }

    [Fact]
    public async Task An_unknown_or_missing_refresh_token_is_401()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.RefreshAsync("__Secure-refresh=made-up")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.PostAsync("/api/auth/refresh", null, Ct)).StatusCode);
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }

    private async Task<List<JsonElement>> SessionsAsync(string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/sessions");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await _client.SendAsync(request, Ct);
        return (await response.Content.ReadFromJsonAsync<List<JsonElement>>(Ct))!;
    }
}
