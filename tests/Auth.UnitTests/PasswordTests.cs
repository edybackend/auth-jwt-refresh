using Auth.Api.Accounts;

namespace Auth.UnitTests;

public class PasswordTests
{
    [Fact]
    public void A_hash_verifies_only_the_right_password()
    {
        var hash = PasswordHasher.Hash("correct-horse-battery");

        Assert.True(PasswordHasher.Verify("correct-horse-battery", hash));
        Assert.False(PasswordHasher.Verify("correct-horse-batterY", hash));
    }

    [Fact]
    public void The_hash_records_its_parameters_and_uses_a_fresh_salt()
    {
        var first = PasswordHasher.Hash("same password here");
        var second = PasswordHasher.Hash("same password here");

        Assert.StartsWith($"pbkdf2-sha256${PasswordHasher.Iterations}$", first, StringComparison.Ordinal);
        Assert.NotEqual(first, second);
    }

    [Theory]
    [InlineData("")]
    [InlineData("plain-text")]
    [InlineData("bcrypt$10$abc$def")]
    [InlineData("pbkdf2-sha256$notanumber$AAAA$AAAA")]
    public void A_malformed_stored_hash_never_verifies(string stored) =>
        Assert.False(PasswordHasher.Verify("anything", stored));

    [Theory]
    [InlineData("short", "at least 12")]
    [InlineData("password1234", "too common")]
    [InlineData("dana-is-my-password", "email name")]
    [InlineData("correct horse battery staple", null)]
    public void The_policy_prefers_length_and_rejects_common_passwords(string password, string? problem)
    {
        var result = PasswordPolicy.Check(password, "dana@example.com");

        if (problem is null)
        {
            Assert.Null(result);
        }
        else
        {
            Assert.Contains(problem, result, StringComparison.Ordinal);
        }
    }
}
