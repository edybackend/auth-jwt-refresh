namespace Auth.Api.Accounts;

/// <summary>
/// Length over complexity rules (NIST SP 800-63B): at least 12 characters, and not a known common password.
/// A production system would check a breached-password service (k-anonymity) instead of a short list.
/// </summary>
public static class PasswordPolicy
{
    public const int MinimumLength = 12;

    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "password1234", "123456789012", "qwertyuiop12", "passwordpassword", "iloveyou1234", "administrator",
        "welcome12345", "letmein12345", "1q2w3e4r5t6y", "abc123456789", "changeme1234", "senha1234567",
        "football1234", "baseball1234", "monkey123456", "dragon123456", "sunshine1234", "princess1234",
        "qwerty123456", "000000000000", "111111111111", "123123123123", "passw0rd1234", "trustno11234",
    };

    /// <summary>Returns why the password is not acceptable, or null if it is.</summary>
    public static string? Check(string? password, string? email)
    {
        if (password is null || password.Length < MinimumLength)
        {
            return $"Use at least {MinimumLength} characters. A passphrase of a few words works well.";
        }

        if (password.Length > 128)
        {
            return "Use at most 128 characters.";
        }

        if (Common.Contains(password))
        {
            return "This password is too common.";
        }

        if (email is not null && password.Contains(email.Split('@')[0], StringComparison.OrdinalIgnoreCase) && email.Split('@')[0].Length >= 4)
        {
            return "The password must not contain your email name.";
        }

        return null;
    }
}
