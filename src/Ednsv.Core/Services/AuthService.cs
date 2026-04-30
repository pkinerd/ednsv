using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Ednsv.Core.Services;

/// <summary>
/// Lightweight token-based auth: a single root user identified by a hash in
/// configuration, plus a tree of issued users persisted to a JSON file.
/// When the configured root hash is the literal string "none" the service
/// reports Disabled and the web layer skips authentication entirely.
/// </summary>
public sealed class AuthService
{
    public const string RootUsername = "ednsv";
    public const string DisabledMarker = "none";

    private static readonly Regex UsernamePattern = new("^[A-Za-z0-9._-]{1,64}$", RegexOptions.Compiled);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public sealed class User
    {
        public string Username { get; set; } = "";
        public string Hash { get; set; } = "";
        public string IssuedBy { get; set; } = "";
        public bool CanIssue { get; set; }
        public DateTime IssuedAt { get; set; }
        public string? IssuedFromIp { get; set; }
        public bool Revoked { get; set; }
        public DateTime? RevokedAt { get; set; }
        public string? RevokedBy { get; set; }
    }

    private sealed class UsersFile
    {
        public List<User> Users { get; set; } = new();
    }

    private readonly string _authDir;
    private readonly string _filePath;
    private readonly string? _rootHash;
    private readonly object _lock = new();
    private List<User> _users = new();

    public bool Disabled => _rootHash == null;

    public AuthService(string authDir, string? rootTokenHash)
    {
        _authDir = authDir;
        _filePath = Path.Combine(authDir, "users.json");

        if (string.IsNullOrWhiteSpace(rootTokenHash) ||
            rootTokenHash.Equals(DisabledMarker, StringComparison.OrdinalIgnoreCase))
        {
            _rootHash = null;
        }
        else
        {
            _rootHash = rootTokenHash.Trim();
        }
    }

    public void Load()
    {
        if (Disabled) return;
        if (!File.Exists(_filePath)) return;

        var json = File.ReadAllText(_filePath);
        if (string.IsNullOrWhiteSpace(json)) return;

        var file = JsonSerializer.Deserialize<UsersFile>(json, JsonOpts);
        if (file?.Users != null)
        {
            lock (_lock) _users = file.Users;
        }
    }

    private void SaveLocked()
    {
        Directory.CreateDirectory(_authDir);
        var file = new UsersFile { Users = _users };
        var json = JsonSerializer.Serialize(file, JsonOpts);
        var tmp = _filePath + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, _filePath, overwrite: true);
    }

    public static string Hash(string token)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Base64UrlEncode(digest);
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Base64UrlEncode(bytes);
    }

    /// <summary>Authenticates a Basic-auth username/token pair.</summary>
    public User? AuthenticateBasic(string username, string token)
    {
        if (Disabled) return null;
        if (string.IsNullOrEmpty(username)) return null;

        var presented = Hash(token);

        if (username.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
        {
            return ConstantTimeEquals(presented, _rootHash!) ? RootUser() : null;
        }

        lock (_lock)
        {
            foreach (var u in _users)
            {
                if (!u.Username.Equals(username, StringComparison.OrdinalIgnoreCase)) continue;
                if (u.Revoked) continue;
                if (ConstantTimeEquals(presented, u.Hash)) return Clone(u);
            }
        }
        return null;
    }

    /// <summary>Authenticates a Bearer token (no username).</summary>
    public User? AuthenticateBearer(string token)
    {
        if (Disabled) return null;

        var presented = Hash(token);

        // Compare against root first
        if (ConstantTimeEquals(presented, _rootHash!)) return RootUser();

        lock (_lock)
        {
            foreach (var u in _users)
            {
                if (u.Revoked) continue;
                if (ConstantTimeEquals(presented, u.Hash)) return Clone(u);
            }
        }
        return null;
    }

    public enum IssueStatus { Success, Disabled, InvalidUsername, UsernameTaken }

    public sealed record IssueResult(IssueStatus Status, User? User = null, string? Token = null);

    /// <summary>Issues a new token. Returns the raw token (only chance to read it).</summary>
    public IssueResult Issue(string newUsername, bool canIssue, string issuedBy, string? issuedFromIp)
    {
        if (Disabled) return new IssueResult(IssueStatus.Disabled);

        newUsername = newUsername?.Trim() ?? "";
        if (!UsernamePattern.IsMatch(newUsername)) return new IssueResult(IssueStatus.InvalidUsername);
        if (newUsername.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
            return new IssueResult(IssueStatus.UsernameTaken);

        lock (_lock)
        {
            if (_users.Any(u => u.Username.Equals(newUsername, StringComparison.OrdinalIgnoreCase)))
                return new IssueResult(IssueStatus.UsernameTaken);

            var token = GenerateToken();
            var user = new User
            {
                Username = newUsername,
                Hash = Hash(token),
                IssuedBy = issuedBy,
                CanIssue = canIssue,
                IssuedAt = DateTime.UtcNow,
                IssuedFromIp = issuedFromIp,
                Revoked = false
            };
            _users.Add(user);
            SaveLocked();
            return new IssueResult(IssueStatus.Success, Clone(user), token);
        }
    }

    public enum RevokeStatus { Success, Disabled, NotFound, NotAllowed, AlreadyRevoked }

    public sealed record RevokeResult(RevokeStatus Status, IReadOnlyList<string>? Affected = null);

    /// <summary>
    /// Revokes the target user and cascades to all descendants (everyone they
    /// issued, recursively). Caller must be the root user, or an ancestor of
    /// the target in the issuance chain.
    /// </summary>
    public RevokeResult Revoke(string targetUsername, string requestedBy)
    {
        if (Disabled) return new RevokeResult(RevokeStatus.Disabled);
        if (string.IsNullOrEmpty(targetUsername)) return new RevokeResult(RevokeStatus.NotFound);
        if (targetUsername.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
            return new RevokeResult(RevokeStatus.NotAllowed);

        lock (_lock)
        {
            var target = _users.FirstOrDefault(u =>
                u.Username.Equals(targetUsername, StringComparison.OrdinalIgnoreCase));
            if (target == null) return new RevokeResult(RevokeStatus.NotFound);

            if (!IsAncestorOrRootLocked(requestedBy, target.Username))
                return new RevokeResult(RevokeStatus.NotAllowed);

            var toRevoke = new List<User> { target };
            toRevoke.AddRange(GetDescendantsLocked(target.Username));

            var now = DateTime.UtcNow;
            var affected = new List<string>();
            foreach (var u in toRevoke)
            {
                if (u.Revoked) continue;
                u.Revoked = true;
                u.RevokedAt = now;
                u.RevokedBy = requestedBy;
                affected.Add(u.Username);
            }

            if (affected.Count == 0)
                return new RevokeResult(RevokeStatus.AlreadyRevoked, Array.Empty<string>());

            SaveLocked();
            return new RevokeResult(RevokeStatus.Success, affected);
        }
    }

    /// <summary>Returns users visible to the caller — root sees everyone, others see their descendants.</summary>
    public IReadOnlyList<User> ListVisibleTo(string requestedBy)
    {
        if (Disabled) return Array.Empty<User>();
        lock (_lock)
        {
            if (requestedBy.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
                return _users.Select(Clone).ToList();
            return GetDescendantsLocked(requestedBy).Select(Clone).ToList();
        }
    }

    private List<User> GetDescendantsLocked(string username)
    {
        var result = new List<User>();
        var queue = new Queue<string>();
        queue.Enqueue(username);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { username };
        while (queue.Count > 0)
        {
            var current = queue.Dequeue();
            foreach (var u in _users)
            {
                if (!u.IssuedBy.Equals(current, StringComparison.OrdinalIgnoreCase)) continue;
                if (!seen.Add(u.Username)) continue;
                result.Add(u);
                queue.Enqueue(u.Username);
            }
        }
        return result;
    }

    private bool IsAncestorOrRootLocked(string ancestor, string target)
    {
        if (ancestor.Equals(RootUsername, StringComparison.OrdinalIgnoreCase)) return true;

        var current = _users.FirstOrDefault(u =>
            u.Username.Equals(target, StringComparison.OrdinalIgnoreCase));
        var hops = 0;
        while (current != null && hops++ < 1024)
        {
            if (current.IssuedBy.Equals(ancestor, StringComparison.OrdinalIgnoreCase)) return true;
            if (current.IssuedBy.Equals(RootUsername, StringComparison.OrdinalIgnoreCase)) return false;
            if (string.IsNullOrEmpty(current.IssuedBy)) return false;
            current = _users.FirstOrDefault(u =>
                u.Username.Equals(current.IssuedBy, StringComparison.OrdinalIgnoreCase));
        }
        return false;
    }

    private static User RootUser() => new()
    {
        Username = RootUsername,
        Hash = "",
        IssuedBy = "",
        CanIssue = true,
        IssuedAt = DateTime.MinValue,
        Revoked = false
    };

    private static User Clone(User u) => new()
    {
        Username = u.Username,
        Hash = u.Hash,
        IssuedBy = u.IssuedBy,
        CanIssue = u.CanIssue,
        IssuedAt = u.IssuedAt,
        IssuedFromIp = u.IssuedFromIp,
        Revoked = u.Revoked,
        RevokedAt = u.RevokedAt,
        RevokedBy = u.RevokedBy
    };

    private static bool ConstantTimeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
