using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;

namespace Ednsv.Core.Services;

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
    // Write-through log for disk export — never read during cache lookups
    private readonly ConcurrentDictionary<string, TValue> _exportLog = new();
    // In-flight query deduplication — concurrent callers for the same key share one Task.
    // Uses Lazy<Task> so that even if ConcurrentDictionary.GetOrAdd invokes the value
    // factory on multiple threads, only one Lazy is stored and only its .Value (which
    // starts the real work) is ever accessed — guaranteeing exactly one factory call.
    private readonly ConcurrentDictionary<string, Lazy<Task<TValue>>> _inflight = new();

    /// <summary>Optional trace callback for cache-level diagnostics (hits, dedup joins).</summary>
    public Action<string>? Trace { get; set; }

    public ProbeCache(TimeSpan? ttl = null)
    {
        _cache = new MemoryCache(new MemoryCacheOptions());
        _ttl = ttl;
    }

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
            // Remove failed entry so next caller retries
            _inflight.TryRemove(key, out _);
            throw;
        }
    }

    private async Task<TValue> RunFactory(string key, Func<Task<TValue>> factory, Func<TValue, bool>? shouldPersist)
    {
        try
        {
            var result = await factory();
            // Always cache in MemoryCache (avoids repeated network calls within a run).
            // Only add to _exportLog when shouldPersist approves (controls disk persistence).
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

    /// <summary>Store a value in MemoryCache and the disk export log.</summary>
    public void Set(string key, TValue value)
    {
        if (_ttl.HasValue)
            _cache.Set(key, value, _ttl.Value);
        else
            _cache.Set(key, value);

        _exportLog[key] = value;
    }

    /// <summary>
    /// Store a value in MemoryCache only — NOT added to the disk export log.
    /// Used for error/timeout results that should be available within the current
    /// process (avoiding repeated network calls) but not persisted across restarts.
    /// </summary>
    private void SetMemoryOnly(string key, TValue value)
    {
        if (_ttl.HasValue)
            _cache.Set(key, value, _ttl.Value);
        else
            _cache.Set(key, value);
    }

    /// <summary>Import entries from disk into the cache.</summary>
    public void Import(string key, TValue value)
    {
        Set(key, value);
    }

    /// <summary>Export all entries that are still alive in MemoryCache.</summary>
    public Dictionary<string, TValue> Export()
    {
        var result = new Dictionary<string, TValue>();
        foreach (var kvp in _exportLog)
        {
            // Only export entries still alive in MemoryCache (not expired)
            if (_cache.TryGetValue(kvp.Key, out TValue? val) && val != null)
                result[kvp.Key] = val;
        }
        return result;
    }

    /// <summary>Remove entries matching a predicate.</summary>
    public void Remove(Func<string, bool> predicate)
    {
        foreach (var key in _exportLog.Keys)
        {
            if (predicate(key))
            {
                _cache.Remove(key);
                _exportLog.TryRemove(key, out _);
            }
        }
    }

    public int Count => _exportLog.Count;
}

/// <summary>
/// Value-type version of ProbeCache for bool, int, etc.
/// Uses Box wrapper internally since MemoryCache needs reference types.
/// </summary>
public class ProbeCacheValue<TValue> where TValue : struct
{
    private readonly MemoryCache _cache;
    private readonly TimeSpan? _ttl;
    private readonly ConcurrentDictionary<string, TValue> _exportLog = new();
    private readonly ConcurrentDictionary<string, Lazy<Task<TValue>>> _inflight = new();

    /// <summary>Optional trace callback for cache-level diagnostics (hits, dedup joins).</summary>
    public Action<string>? Trace { get; set; }

    private sealed class Box { public TValue Value; }

    public ProbeCacheValue(TimeSpan? ttl = null)
    {
        _cache = new MemoryCache(new MemoryCacheOptions());
        _ttl = ttl;
    }

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

        _exportLog[key] = value;
    }

    private void SetMemoryOnly(string key, TValue value)
    {
        var box = new Box { Value = value };
        if (_ttl.HasValue)
            _cache.Set(key, box, _ttl.Value);
        else
            _cache.Set(key, box);
    }

    public void Import(string key, TValue value)
    {
        Set(key, value);
    }

    public Dictionary<string, TValue> Export()
    {
        var result = new Dictionary<string, TValue>();
        foreach (var kvp in _exportLog)
        {
            if (_cache.TryGetValue(kvp.Key, out Box? box) && box != null)
                result[kvp.Key] = box.Value;
        }
        return result;
    }

    public void Remove(Func<string, bool> predicate)
    {
        foreach (var key in _exportLog.Keys)
        {
            if (predicate(key))
            {
                _cache.Remove(key);
                _exportLog.TryRemove(key, out _);
            }
        }
    }

    public int Count => _exportLog.Count;
}
