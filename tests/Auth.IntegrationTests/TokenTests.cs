using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.IntegrationTests;

public sealed class TokenTests : IDisposable
{
    private readonly AuthApp _app = new();
    private readonly HttpClient _client;

    public TokenTests() => _client = _app.Browser();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Access_tokens_are_ES256_with_a_key_id_published_in_the_jwks()
    {
        var signedIn = await _client.LoginAsync();
        var token = new JsonWebToken(signedIn.AccessToken);
        var jwks = await _client.GetFromJsonAsync<JsonElement>("/.well-known/jwks.json", Ct);

        Assert.Equal("ES256", token.Alg);
        var key = Assert.Single(jwks.GetProperty("keys").EnumerateArray());
        Assert.Equal(token.Kid, key.GetProperty("kid").GetString());
        Assert.False(key.TryGetProperty("d", out _)); // the private part is never published
        Assert.Equal("user@example.com", token.GetClaim("email").Value);
        Assert.Equal(TimeSpan.FromMinutes(5), token.ValidTo - token.ValidFrom);
    }

    [Fact]
    public async Task A_token_expires_after_five_minutes_and_a_refresh_gives_a_working_one()
    {
        var signedIn = await _client.LoginAsync();
        _app.Clock.Advance(TimeSpan.FromMinutes(6));

        Assert.Equal(HttpStatusCode.Unauthorized, await _client.GetStatusAsync("/api/me", signedIn.AccessToken));
        using var refreshed = await _client.RefreshAsync(signedIn.RefreshCookie);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        Assert.Equal(HttpStatusCode.OK, await _client.GetStatusAsync("/api/me", (await Http.ReadAsync(refreshed)).AccessToken));
    }

    [Fact]
    public async Task Forged_tokens_are_rejected()
    {
        var real = new JsonWebToken((await _client.LoginAsync()).AccessToken);
        var parts = (await _client.LoginAsync()).AccessToken.Split('.');

        // 1. The payload changed to claim the admin role, keeping the original signature.
        var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(Base64UrlEncoder.Decode(parts[1]))!;
        payload["role"] = "admin";
        var tampered = $"{parts[0]}.{Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload))}.{parts[2]}";

        // 2. A well-formed token signed with another key.
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var foreign = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://auth.local",
            Audience = "auth-demo-api",
            Claims = new Dictionary<string, object> { ["sub"] = real.Subject, ["role"] = "admin" },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(otherKey) { KeyId = real.Kid }, SecurityAlgorithms.EcdsaSha256),
        });

        // 3. "alg": "none".
        var unsigned = $"{Base64UrlEncoder.Encode("""{"alg":"none","typ":"JWT"}""")}.{parts[1]}.";

        foreach (var token in new[] { tampered, foreign, unsigned })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, await _client.GetStatusAsync("/api/admin/users", token));
        }
    }

    [Fact]
    public async Task A_token_for_another_audience_is_rejected()
    {
        // Same key, wrong audience: a token minted for another API must not open this one.
        using var key = ECDsa.Create();
        key.ImportFromPem(await File.ReadAllTextAsync(_app.SigningKeyPath, Ct));
        var sub = new JsonWebToken((await _client.LoginAsync()).AccessToken).Subject;
        var otherAudience = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://auth.local",
            Audience = "some-other-api",
            Claims = new Dictionary<string, object> { ["sub"] = sub },
            SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256),
        });

        Assert.Equal(HttpStatusCode.Unauthorized, await _client.GetStatusAsync("/api/me", otherAudience));
    }

    public void Dispose()
    {
        _client.Dispose();
        _app.Dispose();
    }
}
