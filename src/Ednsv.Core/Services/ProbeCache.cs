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
    // Track which keys were imported from disk (for CLI recheck importedOnly mode)
    private readonly ConcurrentDictionary<string, bool> _importedKeys = new();
    // In-flight query deduplication — concurrent callers for the same key share one Task.
    // Uses Lazy<Task> so that even if ConcurrentDictionary.GetOrAdd invokes the value
    // factory on multiple threads, only one Lazy is stored and only its .Value (which
    // starts the real work) is ever accessed — guaranteeing exactly one factory call.
    private readonly ConcurrentDictionary<string, Lazy<Task<TValue>>> _inflight = new();

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
    /// The optional shouldCache predicate controls whether the result is stored;
    /// if it returns false, the result is returned but not cached (next caller retries).
    /// </summary>
    public async Task<TValue> GetOrCreateAsync(string key, Func<Task<TValue>> factory,
        RecheckHelper.CacheDep recheckFlag = RecheckHelper.CacheDep.None,
        Func<TValue, bool>? shouldCache = null)
    {
        // 1. Check cache (respects recheck bypass)
        if (TryGet(key, out var cached, recheckFlag))
            return cached;

        // 2. Join existing in-flight task or start a new one.
        //    Lazy ensures only one factory runs even if GetOrAdd calls
        //    the value factory on multiple threads (documented .NET behavior).
        var lazy = _inflight.GetOrAdd(key, _ => new Lazy<Task<TValue>>(
            () => RunFactory(key, factory, shouldCache)));

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

    private async Task<TValue> RunFactory(string key, Func<Task<TValue>> factory, Func<TValue, bool>? shouldCache)
    {
        try
        {
            var result = await factory();
            if (shouldCache == null || shouldCache(result))
                Set(key, result);
            return result;
        }
        finally
        {
            _inflight.TryRemove(key, out _);
        }
    }

    /// <summary>Store a value in the cache and the export log.</summary>
    public void Set(string key, TValue value)
    {
        if (_ttl.HasValue)
            _cache.Set(key, value, _ttl.Value);
        else
            _cache.Set(key, value);

        _exportLog[key] = value;
    }

    /// <summary>Import entries from disk (marks them as imported for CLI recheck).</summary>
    public void Import(string key, TValue value)
    {
        Set(key, value);
        _importedKeys.TryAdd(key, true);
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

    /// <summary>Remove entries matching a predicate. importedOnly=true only removes disk-imported entries.</summary>
    public void Remove(Func<string, bool> predicate, bool importedOnly = true)
    {
        var keys = importedOnly ? _importedKeys.Keys : (ICollection<string>)_exportLog.Keys;
        foreach (var key in keys)
        {
            if (predicate(key))
            {
                _cache.Remove(key);
                _exportLog.TryRemove(key, out _);
                _importedKeys.TryRemove(key, out _);
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
    private readonly ConcurrentDictionary<string, bool> _importedKeys = new();
    private readonly ConcurrentDictionary<string, Lazy<Task<TValue>>> _inflight = new();

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
        RecheckHelper.CacheDep recheckFlag = RecheckHelper.CacheDep.None)
    {
        if (TryGet(key, out var cached, recheckFlag))
            return cached;

        var lazy = _inflight.GetOrAdd(key, _ => new Lazy<Task<TValue>>(
            () => RunFactory(key, factory)));

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

    private async Task<TValue> RunFactory(string key, Func<Task<TValue>> factory)
    {
        try
        {
            var result = await factory();
            Set(key, result);
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

    public void Import(string key, TValue value)
    {
        Set(key, value);
        _importedKeys.TryAdd(key, true);
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

    public void Remove(Func<string, bool> predicate, bool importedOnly = true)
    {
        var keys = importedOnly ? _importedKeys.Keys : (ICollection<string>)_exportLog.Keys;
        foreach (var key in keys)
        {
            if (predicate(key))
            {
                _cache.Remove(key);
                _exportLog.TryRemove(key, out _);
                _importedKeys.TryRemove(key, out _);
            }
        }
    }

    public int Count => _exportLog.Count;
}
