namespace Auth.Api;

public sealed class AuthOptions
{
    public const string SectionName = "Auth";

    public string Issuer { get; set; } = "https://auth.local";

    public string Audience { get; set; } = "auth-demo-api";

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>A session (refresh token family) expires after this long without a refresh.</summary>
    public TimeSpan SessionIdleLifetime { get; set; } = TimeSpan.FromDays(7);

    public int MaxFailedLogins { get; set; } = 5;

    public TimeSpan LockoutWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Where the ES256 private key is kept (created on first start). Never commit it.</summary>
    public string SigningKeyPath { get; set; } = "data/signing-key.pem";
}
