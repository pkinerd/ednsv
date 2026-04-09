using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Ednsv.Core.Services;

/// <summary>
/// Masks potentially private details (hostnames, IPs, domains, email addresses)
/// in trace log messages using salted SHA256 hashes. The salt is generated once
/// at construction (or loaded from config) so the same value always produces
/// the same hash — allowing correlation across log lines and across restarts
/// when a static salt is used.
///
/// Hash format: base64url-encoded, truncated to 10 characters (60 bits of entropy).
/// Example: "mail.example.com" → "h:a3Bf9xKz2Q"
/// </summary>
public class TraceMasker
{
    private readonly byte[] _salt;

    /// <summary>Create with a random 256-bit salt (unique per session).</summary>
    public TraceMasker()
    {
        _salt = RandomNumberGenerator.GetBytes(32);
    }

    /// <summary>
    /// Create with a specific salt for consistent hashes across restarts.
    /// Accepts base64, hex (64 chars), or arbitrary string (hashed to 256 bits).
    /// </summary>
    public TraceMasker(string salt)
    {
        if (string.IsNullOrEmpty(salt))
        {
            _salt = RandomNumberGenerator.GetBytes(32);
            return;
        }

        // Try base64 first
        try
        {
            var bytes = Convert.FromBase64String(salt);
            if (bytes.Length >= 16) { _salt = bytes; return; }
        }
        catch { }

        // Try hex (64 hex chars = 32 bytes)
        if (salt.Length == 64 && salt.All(c => "0123456789abcdefABCDEF".Contains(c)))
        {
            _salt = Convert.FromHexString(salt);
            return;
        }

        // Arbitrary string — hash it to produce a 256-bit salt
        _salt = SHA256.HashData(Encoding.UTF8.GetBytes(salt));
    }

    /// <summary>
    /// Compute a deterministic masked identifier for a value.
    /// Same value + same salt = same hash every time.
    /// </summary>
    public string Hash(string value)
    {
        var input = Encoding.UTF8.GetBytes(value.ToLowerInvariant());
        var combined = new byte[_salt.Length + input.Length];
        Buffer.BlockCopy(_salt, 0, combined, 0, _salt.Length);
        Buffer.BlockCopy(input, 0, combined, _salt.Length, input.Length);
        var hash = SHA256.HashData(combined);
        // Base64url encode, truncate to 10 chars (60 bits)
        return Convert.ToBase64String(hash, 0, 8)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=')[..10];
    }

    // Regex patterns for things to mask
    private static readonly Regex IpV4Pattern = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        RegexOptions.Compiled);

    private static readonly Regex IpV6Pattern = new(
        @"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}::[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})",
        RegexOptions.Compiled);

    // Hostnames: word chars + dots + hyphens, at least one dot, ending in a TLD-like segment
    private static readonly Regex HostnamePattern = new(
        @"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        RegexOptions.Compiled);

    // Email addresses
    private static readonly Regex EmailPattern = new(
        @"\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Mask all potentially private details in a trace message.
    /// Replaces IPs, hostnames, and email addresses with hashed versions.
    /// Preserves structure (brackets, colons, prefixes) for readability.
    /// </summary>
    public string Mask(string message)
    {
        // Order matters: emails before hostnames (emails contain hostname-like parts)
        message = EmailPattern.Replace(message, m => $"e:{Hash(m.Value)}");
        message = IpV6Pattern.Replace(message, m => $"ip6:{Hash(m.Value)}");
        message = IpV4Pattern.Replace(message, m => $"ip4:{Hash(m.Value)}");
        message = HostnamePattern.Replace(message, m =>
        {
            // Don't mask common non-private hostnames
            var lower = m.Value.ToLowerInvariant();
            if (lower is "crt.sh" or "mta-sts" or "ednsv" or "email-dns-validator")
                return m.Value;
            // Don't mask well-known DNS/protocol labels
            if (lower.StartsWith("_") || lower.EndsWith(".arpa"))
                return m.Value;
            return $"h:{Hash(m.Value)}";
        });
        return message;
    }
}
