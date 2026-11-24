using System.Threading.RateLimiting;
using Auth.Api;
using Auth.Api.Accounts;
using Auth.Api.Data;
using Auth.Api.Endpoints;
using Auth.Api.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.SectionName));
var authOptions = builder.Configuration.GetSection(AuthOptions.SectionName).Get<AuthOptions>() ?? new AuthOptions();
var signingKey = SigningKey.LoadOrCreate(authOptions.SigningKeyPath);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(signingKey);
builder.Services.AddSingleton(new AuthDatabase(builder.Configuration.GetConnectionString("Auth") ?? throw new InvalidOperationException("Connection string 'Auth' is missing.")));
builder.Services.AddSingleton<AccountService>();
builder.Services.AddSingleton<RefreshSessions>();
builder.Services.AddSingleton<AccessTokenIssuer>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<TimeProvider, IOptions<AuthOptions>>((jwt, clock, options) =>
    {
        jwt.MapInboundClaims = false; // keep "sub", "email", "role" as they are in the token
        jwt.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = options.Value.Issuer,
            ValidAudience = options.Value.Audience,
            IssuerSigningKey = signingKey.SecurityKey,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256], // never "none", never HS256 with the public key
            NameClaimType = "email",
            RoleClaimType = "role",
            // Lifetime checked against the injected clock (tests move it), with a small skew for clock drift.
            LifetimeValidator = (notBefore, expires, _, _) =>
            {
                var now = clock.GetUtcNow().UtcDateTime;
                var skew = TimeSpan.FromSeconds(30);
                return (notBefore is null || notBefore <= now + skew) && expires is not null && expires > now - skew;
            },
        };
    });
builder.Services.AddAuthorizationBuilder().AddPolicy("admin", policy => policy.RequireRole("admin"));

// Per-IP limit on the login endpoint, on top of the per-account lockout.
builder.Services.AddRateLimiter(limiter =>
{
    limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    limiter.AddPolicy("login", http => RateLimitPartition.GetFixedWindowLimiter(
        http.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 20, Window = TimeSpan.FromMinutes(1) }));
});

builder.Services.AddProblemDetails();
builder.Services.AddOpenApi();
builder.Services.AddHealthChecks();

var app = builder.Build();

var database = app.Services.GetRequiredService<AuthDatabase>();
await database.InitializeAsync();
if (app.Configuration.GetValue("Auth:SeedSampleAccounts", false))
{
    await app.Services.GetRequiredService<AccountService>().SeedAsync(CancellationToken.None);
}

app.UseExceptionHandler(new ExceptionHandlerOptions
{
    StatusCodeSelector = exception => exception is BadHttpRequestException badRequest ? badRequest.StatusCode : StatusCodes.Status500InternalServerError,
});
app.UseStatusCodePages();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapOpenApi();
app.MapScalarApiReference();
app.MapHealthChecks("/health");
app.MapGet("/.well-known/jwks.json", (SigningKey key) => Results.Ok(new { keys = new[] { key.PublicJwk } }))
    .WithTags("Auth")
    .WithSummary("Public signing key: other services validate tokens with it");
app.MapAuthEndpoints();
app.MapApiEndpoints();
app.MapFallback("/api/{**path}", () => TypedResults.Problem(statusCode: StatusCodes.Status404NotFound));
app.MapFallbackToFile("index.html");

await app.RunAsync();

/// <summary>Entry point, exposed for integration tests (WebApplicationFactory).</summary>
public partial class Program;
