using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Api.Tokens;

/// <summary>
/// The ES256 key that signs access tokens. Asymmetric on purpose: other services validate tokens with the public
/// key from <c>/.well-known/jwks.json</c> and never hold anything that could mint one.
/// </summary>
public sealed class SigningKey : IDisposable
{
    private readonly ECDsa _ecdsa;

    private SigningKey(ECDsa ecdsa)
    {
        _ecdsa = ecdsa;
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        KeyId = Base64UrlEncoder.Encode(SHA256.HashData([.. parameters.Q.X!, .. parameters.Q.Y!]))[..16];
        SecurityKey = new ECDsaSecurityKey(ecdsa) { KeyId = KeyId };
        Credentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.EcdsaSha256);
        PublicJwk = new
        {
            kty = "EC",
            crv = "P-256",
            use = "sig",
            alg = SecurityAlgorithms.EcdsaSha256,
            kid = KeyId,
            x = Base64UrlEncoder.Encode(parameters.Q.X),
            y = Base64UrlEncoder.Encode(parameters.Q.Y),
        };
    }

    public string KeyId { get; }

    public SecurityKey SecurityKey { get; }

    public SigningCredentials Credentials { get; }

    /// <summary>The public part only, as a JWK.</summary>
    public object PublicJwk { get; }

    /// <summary>Loads the key from <paramref name="path"/>, or creates and saves one on the first start.</summary>
    public static SigningKey LoadOrCreate(string path)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            ecdsa.ImportFromPem(File.ReadAllText(path));
        }
        else
        {
            if (Path.GetDirectoryName(Path.GetFullPath(path)) is { } directory)
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(path, ecdsa.ExportPkcs8PrivateKeyPem());
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }

        return new SigningKey(ecdsa);
    }

    public void Dispose() => _ecdsa.Dispose();
}
