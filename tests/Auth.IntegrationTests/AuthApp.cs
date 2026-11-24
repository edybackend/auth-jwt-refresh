using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.IntegrationTests;

public sealed class MovableClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>The real API on a throw-away database and signing key, with a clock the test moves.</summary>
public sealed class AuthApp : WebApplicationFactory<Program>
{
    private readonly string _directory = Directory.CreateTempSubdirectory("auth-tests-").FullName;

    public MovableClock Clock { get; } = new(DateTimeOffset.UtcNow);

    public string SigningKeyPath => Path.Combine(_directory, "signing-key.pem");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("ConnectionStrings:Auth", $"Data Source={Path.Combine(_directory, "auth.db")};Pooling=False");
        builder.UseSetting("Auth:SigningKeyPath", SigningKeyPath);
        builder.UseSetting("Auth:SeedSampleAccounts", "true");
        builder.ConfigureTestServices(services => services.AddSingleton<TimeProvider>(Clock));
    }

    /// <summary>A client that does not manage cookies by itself: the tests handle the refresh cookie explicitly.</summary>
    public HttpClient Browser() => CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), HandleCookies = false });

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}

public sealed record UserDto(string Id, string Email, string[] Roles);

public sealed record TokenDto(string AccessToken, string TokenType, int ExpiresIn, UserDto User);

/// <summary>What a login or refresh gave back: the access token and the refresh cookie.</summary>
public sealed record SignedIn(string AccessToken, string RefreshCookie, string SetCookieHeader);

public static class Http
{
    public const string Password = "correct-horse-battery";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public static async Task<SignedIn> LoginAsync(this HttpClient client, string email = "user@example.com", string password = Password, string userAgent = "tests")
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login") { Content = JsonContent.Create(new { email, password }) };
        request.Headers.UserAgent.ParseAdd(userAgent);
        using var response = await client.SendAsync(request, Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadAsync(response);
    }

    public static async Task<HttpResponseMessage> RefreshAsync(this HttpClient client, string refreshCookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/refresh");
        request.Headers.Add("Cookie", refreshCookie);
        return await client.SendAsync(request, Ct);
    }

    public static async Task<SignedIn> ReadAsync(HttpResponseMessage response)
    {
        var token = (await response.Content.ReadFromJsonAsync<TokenDto>(Ct))!;
        var setCookie = response.Headers.GetValues("Set-Cookie").Single();
        return new SignedIn(token.AccessToken, setCookie.Split(';')[0], setCookie);
    }

    public static async Task<HttpStatusCode> GetStatusAsync(this HttpClient client, string url, string? accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (accessToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        using var response = await client.SendAsync(request, Ct);
        return response.StatusCode;
    }

    public static async Task<HttpStatusCode> PostStatusAsync(this HttpClient client, string url, object body)
    {
        using var response = await client.PostAsJsonAsync(url, body, Ct);
        return response.StatusCode;
    }
}
