using System.Security.Claims;
using Auth.Api.Accounts;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Tokens;

public sealed record AccessToken(string Token, int ExpiresIn);

/// <summary>Short-lived JWTs. They are not revocable on their own, which is why they live 5 minutes.</summary>
public sealed class AccessTokenIssuer(SigningKey key, TimeProvider clock, IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;
    private readonly JsonWebTokenHandler _handler = new();

    public AccessToken Issue(Account account, string sessionId)
    {
        ArgumentNullException.ThrowIfNull(account);
        var now = clock.GetUtcNow().UtcDateTime;
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, account.Id),
            new(JwtRegisteredClaimNames.Email, account.Email),
            new("sid", sessionId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
        };
        claims.AddRange(account.Roles.Select(role => new Claim("role", role)));

        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            Subject = new ClaimsIdentity(claims),
            IssuedAt = now,
            NotBefore = now,
            Expires = now + _options.AccessTokenLifetime,
            SigningCredentials = key.Credentials,
        });
        return new AccessToken(token, (int)_options.AccessTokenLifetime.TotalSeconds);
    }
}
