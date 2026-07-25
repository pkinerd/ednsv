using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;
using StackExchange.Redis;

namespace Ednsv.Core.Services;

/// <summary>
/// Optional shared L2 for a <see cref="ProbeCache{T}"/>: a Redis-backed,
/// per-key-TTL cache sitting behind the per-pod L1 <see cref="MemoryCache"/>.
/// Values are serialised to a string via caller-supplied delegates and stored
/// under <c>{InstanceName}:cache:{type}:{key}</c>.
///
/// Every operation is best-effort: a null database (Redis unconfigured or
/// currently unreachable) or any serialisation/transport error is swallowed and
/// treated as a miss, so callers transparently fall through to the network.
/// </summary>
public sealed class ProbeCacheL2<TValue> where TValue : class
{
    private readonly RedisConnection _redis;
    private readonly string _prefix;
    private readonly TimeSpan? _ttl;
    private readonly Func<TValue, string?> _serialize;
    private readonly Func<string, TValue?> _deserialize;

    public ProbeCacheL2(RedisConnection redis, string type, TimeSpan? ttl,
        Func<TValue, string?> serialize, Func<string, TValue?> deserialize)
    {
        _redis = redis;
        _prefix = $"cache:{type}:";
        _ttl = ttl;
        _serialize = serialize;
        _deserialize = deserialize;
    }

    /// <summary>True when the backing Redis connection is configured.</summary>
    public bool Enabled => _redis.Enabled;

    /// <summary>Read a value from the L2, or null on miss / any error.</summary>
    public async Task<TValue?> TryGetAsync(string key)
    {
        var db = _redis.GetDatabase();
        if (db == null) return null;
        try
        {
            var val = await db.StringGetAsync(_redis.Key(_prefix + key));
            if (val.IsNullOrEmpty) return null;
            return _deserialize(val!);
        }
        catch { return null; }
    }

    /// <summary>Write-through to the L2 (fire-and-forget). Best-effort.</summary>
    public void Set(string key, TValue value)
    {
        var db = _redis.GetDatabase();
        if (db == null) return;
        string? payload;
        try { payload = _serialize(value); }
        catch { return; }
        if (payload == null) return;
        try { db.StringSet(_redis.Key(_prefix + key), payload, _ttl, flags: CommandFlags.FireAndForget); }
        catch { /* best effort — an L2 write failure just means the next pod refills */ }
    }
}

/// <summary>
/// Single-source-of-truth cache using MemoryCache with optional TTL.
/// Maintains a write-through key log for disk export.
///
/// All reads go through MemoryCache only. The ConcurrentDictionary tracks
/// keys+values for disk persistence export — it is never read during
/// normal cache lookups.
///
/// In-flight deduplication: GetOrCreateAsync ensures only one factory
/// call runs per key. Concurrent callers for the same key await the
/// same Task. On completion (success or failure), the in-flight entry
/// is removed so the next caller can start fresh.
///
/// Recheck bypass: when a key prefix matches the current validation's
/// recheck deps, MemoryCache is skipped and a fresh value is obtained.
/// The fresh value is written back to MemoryCache for other users.
/// </summary>
public class ProbeCache<TValue> where TValue : class
{
    private readonly MemoryCache _cache;
    private readonly TimeSpan? _ttl;
    // Optional shared L2 (Redis). Null in single-instance mode.
    private readonly ProbeCacheL2<TValue>? _l2;
    // Results this process fetched fresh and has not yet written to disk. Never
    // read during cache lookups. Entries imported from disk and values read from
    // the shared Redis L2 deliberately do NOT land here — they are already
    // persisted, and re-persisting them is what made every flush rewrite the whole
    // cache. A flush drains this and removes exactly what it wrote.
    private readonly ConcurrentDictionary<string, BagEntry<TValue>> _bag = new();
    // In-flight query deduplication — concurrent callers for the same key share one Task.
    // Uses Lazy<Task> so that even if ConcurrentDictionary.GetOrAdd invokes the value
    // factory on multiple threads, only one Lazy is stored and only its .Value (which
    // starts the real work) is ever accessed — guaranteeing exactly one factory call.
    private readonly ConcurrentDictionary<string, Lazy<Task<TValue>>> _inflight = new();

    /// <summary>
    /// Optional trace callback for cache-level diagnostics (hits, dedup joins).
    /// Backed by <see cref="TraceContext.Sink"/> — setting this delegates to the
    /// per-request AsyncLocal sink so concurrent validations don't share state.
    /// </summary>
    public Action<string>? Trace
    {
        get => TraceContext.Sink;
        set => TraceContext.Sink = value;
    }

    public ProbeCache(TimeSpan? ttl = null, ProbeCacheL2<TValue>? l2 = null)
    {
        _cache = new MemoryCache(new MemoryCacheOptions());
        _ttl = ttl;
        _l2 = l2 != null && l2.Enabled ? l2 : null;
    }

    /// <summary>Evict every entry: MemoryCache, the disk-export log, and any in-flight map.</summary>
    /// <summary>Try to read a cached value. Returns false on miss or recheck bypass.</summary>
    public bool TryGet(string key, out TValue value, RecheckHelper.CacheDep recheckFlag = RecheckHelper.CacheDep.None)
    {
        // If this validation is rechecking this cache type, bypass
        if (recheckFlag != RecheckHelper.CacheDep.None &&
            RecheckHelper.CurrentRecheckDeps.Value.HasFlag(recheckFlag))
        {
            value = default!;
            return false;
        }

        if (_cache.TryGetValue(key, out TValue? cached) && cached != null)
        {
            value = cached;
            return true;
        }

        value = default!;
        return false;
    }

    /// <summary>
    /// Get a cached value or create it using the factory. Only one factory call
    /// runs per key — concurrent callers await the same Task. On failure, the
    /// in-flight entry is removed so the next caller retries.
    /// The optional shouldPersist predicate controls disk persistence: when false,
    /// the result is still cached in MemoryCache (for within-run dedup) but not
    /// added to the export log (so it won't be saved to disk).
    /// </summary>
    public async Task<TValue> GetOrCreateAsync(string key, Func<Task<TValue>> factory,
        RecheckHelper.CacheDep recheckFlag = RecheckHelper.CacheDep.None,
        Func<TValue, bool>? shouldPersist = null,
        Action? onHit = null)
    {
        // 1. Check cache (respects recheck bypass)
        if (TryGet(key, out var cached, recheckFlag))
        {
            Trace?.Invoke($"[CACHE] HIT {key}");
            onHit?.Invoke();
            return cached;
        }

        // 2. Join existing in-flight task or start a new one.
        //    Lazy ensures only one factory runs even if GetOrAdd calls
        //    the value factory on multiple threads (documented .NET behavior).
        // Recheck bypass also skips the L2 read (but not the L2 write-back below,
        // so a forced recheck refreshes the shared cache for other pods).
        bool bypass = recheckFlag != RecheckHelper.CacheDep.None &&
            RecheckHelper.CurrentRecheckDeps.Value.HasFlag(recheckFlag);

        bool isNewEntry = false;
        var lazy = _inflight.GetOrAdd(key, _ =>
        {
            isNewEntry = true;
            return new Lazy<Task<TValue>>(() => RunFactory(key, factory, shouldPersist, bypass));
        });

        if (!isNewEntry)
            Trace?.Invoke($"[CACHE] DEDUP JOIN {key} (awaiting in-flight request)");

        try
        {
            return await lazy.Value;
        }
        catch
        {
            // Remove failed entry so next caller retries
            _inflight.TryRemove(key, out _);
            throw;
        }
    }

    private async Task<TValue> RunFactory(string key, Func<Task<TValue>> factory, Func<TValue, bool>? shouldPersist, bool skipL2Read)
    {
        try
        {
            // L1 already missed. Try the shared L2 before the network; a hit
            // populates L1 so subsequent local reads are fast.
            if (!skipL2Read && _l2 != null)
            {
                var l2v = await _l2.TryGetAsync(key);
                if (l2v != null)
                {
                    Trace?.Invoke($"[CACHE] L2 HIT {key}");
                    // Memory only: another instance fetched and persisted this, so
                    // writing it out again would duplicate their work on our disk.
                    SetMemoryOnly(key, l2v);
                    return l2v;
                }
            }

            var result = await factory();
            // Always cache in MemoryCache (avoids repeated network calls within a run).
            // Only queue for persistence / push to L2 when shouldPersist approves
            // (transient errors stay L1-only and never poison disk or the shared L2).
            if (shouldPersist == null || shouldPersist(result))
            {
                Set(key, result);
                _l2?.Set(key, result);
            }
            else
                SetMemoryOnly(key, result);
            return result;
        }
        finally
        {
            _inflight.TryRemove(key, out _);
        }
    }

    /// <summary>Store a freshly fetched value in MemoryCache and queue it for
    /// persistence.</summary>
    public void Set(string key, TValue value)
    {
        if (_ttl.HasValue)
            _cache.Set(key, value, _ttl.Value);
        else
            _cache.Set(key, value);

        var now = DateTime.UtcNow;
        _bag[key] = new BagEntry<TValue>(value, now, _ttl.HasValue ? now + _ttl.Value : DateTime.MaxValue);
    }

    /// <summary>
    /// Store a value in MemoryCache only, without queueing it for persistence.
    /// Used for three cases that must not be written back: transient errors that
    /// should not outlive the process, values read from the shared Redis L2 (another
    /// instance already persisted them), and entries imported from disk (they are
    /// on disk by definition).
    /// </summary>
    private void SetMemoryOnly(string key, TValue value)
    {
        if (_ttl.HasValue)
            _cache.Set(key, value, _ttl.Value);
        else
            _cache.Set(key, value);
    }

    /// <summary>Import an entry read from disk into MemoryCache. It is not queued
    /// for persistence: it came from disk, so writing it back is the redundancy this
    /// design exists to remove.</summary>
    public void Import(string key, TValue value)
    {
        SetMemoryOnly(key, value);
    }

    /// <summary>Import an entry read from disk, carrying its original fetch time.
    /// Same rule as the other overload — MemoryCache only, never the bag.</summary>
    public void Import(string key, TValue value, DateTime cachedAtUtc)
    {
        _ = cachedAtUtc; // the on-disk record already carries it
        SetMemoryOnly(key, value);
    }

    /// <summary>Values awaiting persistence that are still live in MemoryCache.</summary>
    public Dictionary<string, TValue> Export()
    {
        var result = new Dictionary<string, TValue>();
        foreach (var kvp in _bag)
        {
            if (_cache.TryGetValue(kvp.Key, out TValue? val) && val != null)
                result[kvp.Key] = val;
        }
        return result;
    }

    /// <summary>Values awaiting persistence with the time each was fetched, so disk
    /// records age from the real fetch rather than from when they were written.</summary>
    public Dictionary<string, (TValue Value, DateTime CachedAtUtc)> ExportTimed()
    {
        var result = new Dictionary<string, (TValue, DateTime)>();
        foreach (var kvp in _bag)
        {
            if (_cache.TryGetValue(kvp.Key, out TValue? val) && val != null)
                result[kvp.Key] = (val, kvp.Value.WrittenUtc);
        }
        return result;
    }

    /// <summary>Remove entries matching a predicate.</summary>
    public void Remove(Func<string, bool> predicate)
    {
        foreach (var key in _bag.Keys)
        {
            if (predicate(key))
            {
                _cache.Remove(key);
                _bag.TryRemove(key, out _);
            }
        }
    }

    /// <summary>Live entries held in memory. Reported as the cache size, so it
    /// tracks what is actually cached rather than what is queued for writing —
    /// the bag is usually near-empty just after a flush.</summary>
    public int Count => _cache.Count;
}

/// <summary>
/// Value-type version of ProbeCache for bool, int, etc.
/// Uses Box wrapper internally since MemoryCache needs reference types.
/// </summary>
public class ProbeCacheValue<TValue> where TValue : struct
{
    private readonly MemoryCache _cache;
    private readonly TimeSpan? _ttl;
    // See ProbeCache<T>._bag — values this process fetched and has yet to persist.
    private readonly ConcurrentDictionary<string, BagEntry<TValue>> _bag = new();
    private readonly ConcurrentDictionary<string, Lazy<Task<TValue>>> _inflight = new();

    /// <summary>
    /// Optional trace callback for cache-level diagnostics — see
    /// <see cref="ProbeCache{T}.Trace"/> for AsyncLocal backing.
    /// </summary>
    public Action<string>? Trace
    {
        get => TraceContext.Sink;
        set => TraceContext.Sink = value;
    }

    private sealed class Box { public TValue Value; }

    public ProbeCacheValue(TimeSpan? ttl = null)
    {
        _cache = new MemoryCache(new MemoryCacheOptions());
        _ttl = ttl;
    }

    /// <summary>Evict every entry: MemoryCache, the disk-export log, and any in-flight map.</summary>
    public bool TryGet(string key, out TValue value, RecheckHelper.CacheDep recheckFlag = RecheckHelper.CacheDep.None)
    {
        if (recheckFlag != RecheckHelper.CacheDep.None &&
            RecheckHelper.CurrentRecheckDeps.Value.HasFlag(recheckFlag))
        {
            value = default;
            return false;
        }

        if (_cache.TryGetValue(key, out Box? box) && box != null)
        {
            value = box.Value;
            return true;
        }

        value = default;
        return false;
    }

    public async Task<TValue> GetOrCreateAsync(string key, Func<Task<TValue>> factory,
        RecheckHelper.CacheDep recheckFlag = RecheckHelper.CacheDep.None,
        Func<TValue, bool>? shouldPersist = null)
    {
        if (TryGet(key, out var cached, recheckFlag))
        {
            Trace?.Invoke($"[CACHE] HIT {key}");
            return cached;
        }

        bool isNewEntry = false;
        var lazy = _inflight.GetOrAdd(key, _ =>
        {
            isNewEntry = true;
            return new Lazy<Task<TValue>>(() => RunFactory(key, factory, shouldPersist));
        });

        if (!isNewEntry)
            Trace?.Invoke($"[CACHE] DEDUP JOIN {key} (awaiting in-flight request)");

        try
        {
            return await lazy.Value;
        }
        catch
        {
            _inflight.TryRemove(key, out _);
            throw;
        }
    }

    private async Task<TValue> RunFactory(string key, Func<Task<TValue>> factory, Func<TValue, bool>? shouldPersist)
    {
        try
        {
            var result = await factory();
            if (shouldPersist == null || shouldPersist(result))
                Set(key, result);
            else
                SetMemoryOnly(key, result);
            return result;
        }
        finally
        {
            _inflight.TryRemove(key, out _);
        }
    }

    public void Set(string key, TValue value)
    {
        var box = new Box { Value = value };
        if (_ttl.HasValue)
            _cache.Set(key, box, _ttl.Value);
        else
            _cache.Set(key, box);

        var now = DateTime.UtcNow;
        _bag[key] = new BagEntry<TValue>(value, now, _ttl.HasValue ? now + _ttl.Value : DateTime.MaxValue);
    }

    private void SetMemoryOnly(string key, TValue value)
    {
        var box = new Box { Value = value };
        if (_ttl.HasValue)
            _cache.Set(key, box, _ttl.Value);
        else
            _cache.Set(key, box);
    }

    /// <summary>Import from disk into MemoryCache only — never the bag.</summary>
    public void Import(string key, TValue value)
    {
        SetMemoryOnly(key, value);
    }

    public Dictionary<string, TValue> Export()
    {
        var result = new Dictionary<string, TValue>();
        foreach (var kvp in _bag)
        {
            if (_cache.TryGetValue(kvp.Key, out Box? box) && box != null)
                result[kvp.Key] = box.Value;
        }
        return result;
    }

    public void Remove(Func<string, bool> predicate)
    {
        foreach (var key in _bag.Keys)
        {
            if (predicate(key))
            {
                _cache.Remove(key);
                _bag.TryRemove(key, out _);
            }
        }
    }

    /// <summary>Live entries held in memory — see ProbeCache&lt;T&gt;.Count.</summary>
    public int Count => _cache.Count;
}
