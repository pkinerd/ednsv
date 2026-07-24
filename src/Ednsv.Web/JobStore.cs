using System.Text.Json;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

// Serializable snapshot of a validation job. In single-instance mode this is
// produced on demand from the live ValidationJob; in distributed mode it is
// also written to Redis so any pod can serve GET /api/status/{id}.
//
// The DNS/SMTP stat blocks are computed (delta-from-baseline) at snapshot time
// on the executing pod, because the underlying counters are per-process — a
// remote pod reads the already-computed values from the snapshot rather than
// the (meaningless-to-it) live singleton counters.

sealed record JobDnsStats(
    long Queries, int CacheHits, int Sent, int Received,
    int TotalCacheHits, int TotalCacheMisses, int TotalCacheSize);

sealed record JobSmtpStats(
    int ProbesStarted, int ProbesDone, int PortsStarted, int PortsDone);

sealed class JobState
{
    public string JobId { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Status { get; set; } = "running"; // running|completed|failed
    public string? CurrentCheck { get; set; }
    public int CompletedChecks { get; set; }
    public int Pass { get; set; }
    public int Info { get; set; }
    public int Warning { get; set; }
    public int Error { get; set; }
    public int Critical { get; set; }
    public JobDnsStats? Dns { get; set; }
    public JobSmtpStats? Smtp { get; set; }
    public DateTime StartedAt { get; set; }
    public double? DurationSeconds { get; set; }
    public ValidationReport? Report { get; set; }
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Redis-backed store for validation job snapshots. Used only in distributed
/// mode (Redis configured). Running jobs get a sliding TTL so a stalled/abandoned
/// job expires; terminal jobs get a short retention TTL from completion.
/// All operations are best-effort — a Redis error is swallowed and the local
/// in-memory tracker remains the fallback for same-pod polls.
/// </summary>
sealed class RedisJobStore
{
    private static readonly TimeSpan RunningTtl = TimeSpan.FromMinutes(15);
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly RedisConnection _redis;
    private readonly TimeSpan _terminalTtl;

    public RedisJobStore(RedisConnection redis, TimeSpan terminalTtl)
    {
        _redis = redis;
        _terminalTtl = terminalTtl;
    }

    public bool Enabled => _redis.Enabled;

    public void Save(JobState state, bool terminal)
    {
        var db = _redis.GetDatabase();
        if (db == null) return;
        try
        {
            var ttl = terminal ? _terminalTtl : RunningTtl;
            db.StringSet(_redis.Key($"job:{state.JobId}"),
                JsonSerializer.Serialize(state, Json), ttl,
                flags: StackExchange.Redis.CommandFlags.FireAndForget);
        }
        catch { /* best-effort: local tracker still serves same-pod polls */ }
    }

    public JobState? Get(string jobId)
    {
        var db = _redis.GetDatabase();
        if (db == null) return null;
        try
        {
            var val = db.StringGet(_redis.Key($"job:{jobId}"));
            if (val.IsNullOrEmpty) return null;
            return JsonSerializer.Deserialize<JobState>(val!, Json);
        }
        catch { return null; }
    }
}
