using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using StackExchange.Redis;

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
        public bool IsAdmin { get; set; }
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

    // Distributed coordination (opt-in) — mirrors ConfigService. A Redis beacon
    // holds the GUID of the current users.json head; reads check it on demand so
    // a revocation on one pod is visible everywhere, and writes promote a new
    // head via compare-and-set (retrying on a concurrent change).
    private readonly RedisConnection? _redis;
    private string _headGuid = Guid.NewGuid().ToString("N");
    private const string BeaconSuffix = "users:head";

    public bool Disabled => _rootHash == null;

    public AuthService(string authDir, string? rootTokenHash, RedisConnection? redis = null)
    {
        _authDir = authDir;
        _filePath = Path.Combine(authDir, "users.json");
        _redis = redis != null && redis.Enabled ? redis : null;

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
        InitBeacon(); // publish/adopt the cluster head before reading the file
        if (!File.Exists(_filePath)) return;

        var json = File.ReadAllText(_filePath);
        if (string.IsNullOrWhiteSpace(json)) return;

        var file = JsonSerializer.Deserialize<UsersFile>(json, JsonOpts);
        if (file?.Users != null)
        {
            // Backward-compat: legacy "canIssue" field upgrades to IsAdmin.
            // Walk the raw JSON in array order to detect the old key.
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("users", out var arr) &&
                    arr.ValueKind == JsonValueKind.Array)
                {
                    int i = 0;
                    foreach (var el in arr.EnumerateArray())
                    {
                        if (i >= file.Users.Count) break;
                        if (!file.Users[i].IsAdmin &&
                            el.TryGetProperty("canIssue", out var ci) &&
                            ci.ValueKind == JsonValueKind.True)
                        {
                            file.Users[i].IsAdmin = true;
                        }
                        i++;
                    }
                }
            }
            catch { /* best-effort migration */ }

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

    // ── Distributed coordination (beacon) ────────────────────────────────

    private const int MaxWriteAttempts = 5;

    /// <summary>Reload users.json if another pod advanced the beacon. Must hold _lock.</summary>
    private void EnsureFreshLocked()
    {
        if (_redis == null) return;
        var db = _redis.GetDatabase();
        if (db == null) return; // Redis down — keep serving the last-known local copy.
        var beacon = _redis.Key(BeaconSuffix);
        RedisValue v;
        try { v = db.StringGet(beacon); }
        catch { return; }
        if (v.IsNullOrEmpty)
        {
            try { db.StringSet(beacon, _headGuid, when: When.NotExists); } catch { /* best effort */ }
            return;
        }
        string remote = v!;
        if (remote == _headGuid) return;
        ReloadUsersFromDiskLocked();
        _headGuid = remote;
    }

    /// <summary>Persist users and promote a new head. Returns false on a beacon
    /// CAS conflict (caller reloads and retries). Throws when Redis is required
    /// but unreachable. Must hold _lock.</summary>
    private bool TryCommitLocked()
    {
        if (_redis == null)
        {
            SaveLocked();
            _headGuid = Guid.NewGuid().ToString("N");
            return true;
        }
        var db = _redis.GetDatabase();
        if (db == null)
            throw new StoreUnavailableException("Redis is unreachable; refusing to persist user changes to avoid divergence across pods.");
        var beacon = _redis.Key(BeaconSuffix);
        var newHead = Guid.NewGuid().ToString("N");
        var tran = db.CreateTransaction();
        tran.AddCondition(Condition.StringEqual(beacon, _headGuid));
        _ = tran.StringSetAsync(beacon, newHead);
        bool committed;
        try { committed = tran.Execute(); }
        catch { throw new StoreUnavailableException("Redis transaction failed while coordinating the user write."); }
        if (!committed) return false;
        SaveLocked();
        _headGuid = newHead;
        return true;
    }

    private void InitBeacon()
    {
        if (_redis == null) return;
        var db = _redis.GetDatabase();
        if (db == null) return;
        var beacon = _redis.Key(BeaconSuffix);
        try
        {
            var existing = db.StringGet(beacon);
            if (existing.IsNullOrEmpty)
                db.StringSet(beacon, _headGuid, when: When.NotExists);
            else
                _headGuid = existing!; // adopt the cluster head for the shared file.
        }
        catch { /* best effort — fall back to local head */ }
    }

    private void ReloadUsersFromDiskLocked()
    {
        if (!File.Exists(_filePath)) { _users = new List<User>(); return; }
        try
        {
            var json = File.ReadAllText(_filePath);
            if (string.IsNullOrWhiteSpace(json)) { _users = new List<User>(); return; }
            var file = JsonSerializer.Deserialize<UsersFile>(json, JsonOpts);
            if (file?.Users != null) _users = file.Users;
        }
        catch { /* keep current in-memory copy if the file is momentarily unreadable */ }
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
            EnsureFreshLocked();
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
            EnsureFreshLocked();
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
    public IssueResult Issue(string newUsername, bool isAdmin, string issuedBy, string? issuedFromIp)
    {
        if (Disabled) return new IssueResult(IssueStatus.Disabled);

        newUsername = newUsername?.Trim() ?? "";
        if (!UsernamePattern.IsMatch(newUsername)) return new IssueResult(IssueStatus.InvalidUsername);
        if (newUsername.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
            return new IssueResult(IssueStatus.UsernameTaken);

        for (int attempt = 0; ; attempt++)
        {
            lock (_lock)
            {
                EnsureFreshLocked();
                if (_users.Any(u => u.Username.Equals(newUsername, StringComparison.OrdinalIgnoreCase)))
                    return new IssueResult(IssueStatus.UsernameTaken);

                var token = GenerateToken();
                var user = new User
                {
                    Username = newUsername,
                    Hash = Hash(token),
                    IssuedBy = issuedBy,
                    IsAdmin = isAdmin,
                    IssuedAt = DateTime.UtcNow,
                    IssuedFromIp = issuedFromIp,
                    Revoked = false
                };
                _users.Add(user);
                if (TryCommitLocked())
                    return new IssueResult(IssueStatus.Success, Clone(user), token);
                _users.Remove(user); // CAS lost — discard and retry from fresh state
            }
            if (attempt >= MaxWriteAttempts)
                throw new StoreUnavailableException("Could not persist the new user after repeated concurrent modifications.");
        }
    }

    public enum RevokeStatus { Success, Disabled, NotFound, NotAllowed, AlreadyRevoked }

    public sealed record RevokeResult(RevokeStatus Status, IReadOnlyList<string>? Affected = null);

    public enum DeleteStatus { Success, Disabled, NotFound, NotAllowed, NotRevoked }

    public sealed record DeleteResult(DeleteStatus Status, IReadOnlyList<string>? Affected = null);

    /// <summary>
    /// Permanently removes a revoked user record. Only the root user may delete,
    /// and only users that are already revoked. Cascades to descendants so a
    /// subtree of revoked accounts is wiped together.
    /// </summary>
    public DeleteResult Delete(string targetUsername, string requestedBy)
    {
        if (Disabled) return new DeleteResult(DeleteStatus.Disabled);
        if (string.IsNullOrEmpty(targetUsername)) return new DeleteResult(DeleteStatus.NotFound);
        if (!requestedBy.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
            return new DeleteResult(DeleteStatus.NotAllowed);
        if (targetUsername.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
            return new DeleteResult(DeleteStatus.NotAllowed);

        for (int attempt = 0; ; attempt++)
        {
            lock (_lock)
            {
                EnsureFreshLocked();
                var target = _users.FirstOrDefault(u =>
                    u.Username.Equals(targetUsername, StringComparison.OrdinalIgnoreCase));
                if (target == null) return new DeleteResult(DeleteStatus.NotFound);
                if (!target.Revoked) return new DeleteResult(DeleteStatus.NotRevoked);

                var toDelete = new List<User> { target };
                toDelete.AddRange(GetDescendantsLocked(target.Username));
                var names = new HashSet<string>(toDelete.Select(u => u.Username), StringComparer.OrdinalIgnoreCase);

                _users.RemoveAll(u => names.Contains(u.Username));
                if (TryCommitLocked())
                    return new DeleteResult(DeleteStatus.Success, names.ToArray());
                // CAS lost — next iteration's EnsureFreshLocked reloads the true state.
            }
            if (attempt >= MaxWriteAttempts)
                throw new StoreUnavailableException("Could not persist the user deletion after repeated concurrent modifications.");
        }
    }

    /// <summary>
    /// Revokes the target user and cascades to all descendants (everyone they
    /// issued, recursively). Caller must be the root user, or an ancestor of
    /// the target in the issuance chain — unless <paramref name="elevated"/> is
    /// set, in which case the caller may revoke any user except root. Elevated
    /// revoke is granted to external-IdP admins (SSO / JWT), who sit outside the
    /// token issuance tree and are trusted by the IdP; the root user (config
    /// token) is never revocable by anyone.
    /// </summary>
    public RevokeResult Revoke(string targetUsername, string requestedBy, bool elevated = false)
    {
        if (Disabled) return new RevokeResult(RevokeStatus.Disabled);
        if (string.IsNullOrEmpty(targetUsername)) return new RevokeResult(RevokeStatus.NotFound);
        if (targetUsername.Equals(RootUsername, StringComparison.OrdinalIgnoreCase))
            return new RevokeResult(RevokeStatus.NotAllowed);

        for (int attempt = 0; ; attempt++)
        {
            lock (_lock)
            {
                EnsureFreshLocked();
                var target = _users.FirstOrDefault(u =>
                    u.Username.Equals(targetUsername, StringComparison.OrdinalIgnoreCase));
                if (target == null) return new RevokeResult(RevokeStatus.NotFound);

                if (!elevated && !IsAncestorOrRootLocked(requestedBy, target.Username))
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

                if (TryCommitLocked())
                    return new RevokeResult(RevokeStatus.Success, affected);
                // CAS lost — next iteration's EnsureFreshLocked reloads the true state.
            }
            if (attempt >= MaxWriteAttempts)
                throw new StoreUnavailableException("Could not persist the revocation after repeated concurrent modifications.");
        }
    }

    /// <summary>Returns users visible to the caller — root sees everyone, others see their descendants.</summary>
    public IReadOnlyList<User> ListVisibleTo(string requestedBy)
    {
        if (Disabled) return Array.Empty<User>();
        lock (_lock)
        {
            EnsureFreshLocked();
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
        IsAdmin = true,
        IssuedAt = DateTime.MinValue,
        Revoked = false
    };

    private static User Clone(User u) => new()
    {
        Username = u.Username,
        Hash = u.Hash,
        IssuedBy = u.IssuedBy,
        IsAdmin = u.IsAdmin,
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
