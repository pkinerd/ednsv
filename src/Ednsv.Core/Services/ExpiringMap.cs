using Microsoft.Extensions.Caching.Memory;

namespace Ednsv.Core.Services;

/// <summary>
/// A <see cref="MemoryCache"/> plus this project's three cache rules, for the caches
/// that are not a <see cref="ProbeCache{T}"/>: RCPT probes, relay tests, AXFR verdicts
/// and responses, unreachable-server counts, domain result summaries and the per-server
/// <c>LookupClient</c> pool.
///
/// <para><b>Expiry is MemoryCache's job, not ours.</b> It already does the whole of it —
/// exact expiry on read, and a sweep for keys nobody reads again, triggered by a cache
/// operation, rate-limited by <c>ExpirationScanFrequency</c> and dispatched to the
/// thread pool. An earlier version of this type reimplemented that over a
/// <see cref="System.Collections.Concurrent.ConcurrentDictionary{TKey,TValue}"/> and
/// owned the sweep, its rate limit and its single-flight gate. Nothing needed it:
/// tuple keys work here (the keys are <c>object</c>, and a <c>ValueTuple</c> compares
/// structurally), the one caller wanting an atomic read-modify-write is served by a lock
/// on a path that only runs when a DNS query has already failed, and enumerating the
/// live set — the one thing MemoryCache genuinely cannot do before .NET 9 — turned out
/// to have no production caller at all.</para>
///
/// <para><b>What this type is actually for</b> is the three rules that are ours rather
/// than the platform's, each of which was a bug when it lived at the call sites instead:
/// <list type="number">
/// <item>the recheck bypass, so a validation rechecking this cache type reads a miss —
/// omitted at four call sites until recently, which made <c>--recheck</c> a no-op for
/// RCPT, relay and AXFR findings;</item>
/// <item>a null TTL meaning "no expiry", which is what <c>CacheTtlHours=0</c> means
/// everywhere else in the app;</item>
/// <item>an import keeping the expiry stamped on its record rather than being handed a
/// fresh full TTL, so a nearly-dead entry read from disk is not resurrected.</item>
/// </list></para>
/// </summary>
public sealed class ExpiringMap<TKey, TValue> where TKey : notnull
{
    private readonly MemoryCache _cache = new(new MemoryCacheOptions());
    private readonly TimeSpan? _ttl;

    // Serialises the compound writes — add-if-absent and read-modify-write — that
    // MemoryCache has no atomic primitive for. Reads and plain Set are outside it:
    // MemoryCache is thread-safe, and last-writer-wins is what Set means anyway.
    //
    // Contention is not a concern. What goes through here is an import from disk, or the
    // unreachable-server counter on a path only reached once a DNS query has already
    // failed; the work under the lock is a dictionary probe and a store.
    private readonly object _writeLock = new();

    public ExpiringMap(TimeSpan? ttl) => _ttl = ttl;

    /// <summary>
    /// Entries held, <b>including any that have expired but not yet been swept</b> —
    /// MemoryCache reports what it is holding, not what is readable. That makes this the
    /// number to look at for the memory question; for "is this entry still live", read it.
    /// </summary>
    public int Count => _cache.Count;

    /// <summary>
    /// Read a value. An expired entry is a miss — MemoryCache checks expiry on the read
    /// itself, so the TTL is exact whether or not anything has swept.
    ///
    /// <para><paramref name="recheckFlag"/> is the recheck bypass, identical in mechanism
    /// and meaning to <see cref="ProbeCache{T}.TryGet"/>: when the current validation is
    /// rechecking this cache type, every read is a miss so the caller refetches. It is
    /// <see cref="RecheckHelper.CacheDep.None"/> — never bypassed — for a caller with no
    /// cache type of its own.</para>
    /// </summary>
    public bool TryGetValue(TKey key, out TValue value,
        RecheckHelper.CacheDep recheckFlag = RecheckHelper.CacheDep.None)
    {
        if (recheckFlag != RecheckHelper.CacheDep.None
            && RecheckHelper.CurrentRecheckDeps.Value.HasFlag(recheckFlag))
        {
            value = default!;
            return false;
        }

        if (_cache.TryGetValue(key, out TValue? cached))
        {
            value = cached!;
            return true;
        }

        value = default!;
        return false;
    }

    /// <summary>
    /// Add if no live value is present, returning whether this call stored the value. An
    /// expired entry counts as absent, since MemoryCache has already stopped serving it.
    ///
    /// <para>Atomic against other <see cref="TryAdd(TKey,TValue)"/> and
    /// <see cref="AddOrUpdate"/> calls, which is what the import path needs: exactly one
    /// of two racing importers stores, and a value already present is never replaced. It
    /// is deliberately <i>not</i> atomic against <see cref="Set"/> — a network result
    /// landing between the check and the store wins, and would have won anyway.</para>
    /// </summary>
    public bool TryAdd(TKey key, TValue value)
    {
        lock (_writeLock)
        {
            if (_cache.TryGetValue(key, out _)) return false;

            Store(key, value, Expiry());
            return true;
        }
    }

    /// <summary>
    /// As <see cref="TryAdd(TKey,TValue)"/>, with an expiry of the caller's choosing — an
    /// entry read from disk keeps the expiry stamped on its record rather than being
    /// handed a fresh full TTL and resurrected. One already past its expiry is refused
    /// rather than stored and immediately dropped.
    /// </summary>
    public bool TryAdd(TKey key, TValue value, DateTime expiresUtc)
    {
        if (expiresUtc <= DateTime.UtcNow) return false;

        lock (_writeLock)
        {
            if (_cache.TryGetValue(key, out _)) return false;

            Store(key, value, expiresUtc);
            return true;
        }
    }

    /// <summary>Store a value, replacing whatever is there.</summary>
    public void Set(TKey key, TValue value) => Store(key, value, Expiry());

    /// <summary>
    /// Read-modify-write for a value derived from the one already cached. An expired
    /// entry is treated as absent, so <paramref name="add"/> is used rather than
    /// <paramref name="update"/> being handed a value nobody was allowed to read. Either
    /// way the entry gets a fresh expiry: it has just been written.
    /// </summary>
    public TValue AddOrUpdate(TKey key, TValue add, Func<TValue, TValue> update)
    {
        lock (_writeLock)
        {
            var next = _cache.TryGetValue(key, out TValue? existing) ? update(existing!) : add;
            Store(key, next, Expiry());
            return next;
        }
    }

    /// <summary>
    /// Get the cached value or create it. The factory may run more than once under
    /// contention — only one result is stored — so it must be cheap and side-effect free.
    /// Use <see cref="ProbeCache{T}"/> where exactly one call matters.
    /// </summary>
    public TValue GetOrAdd(TKey key, Func<TKey, TValue> factory)
    {
        if (TryGetValue(key, out var live)) return live;

        var created = factory(key);
        Store(key, created, Expiry());
        return created;
    }

    public bool TryRemove(TKey key)
    {
        if (!_cache.TryGetValue(key, out _)) return false;
        _cache.Remove(key);
        return true;
    }

    /// <summary>Where the null-TTL rule lives: no expiry set at all, so the entry lives
    /// for the process — bounded by the number of distinct keys, exactly as
    /// <c>CacheTtlHours=0</c> means everywhere else.</summary>
    private void Store(TKey key, TValue value, DateTime? expiresUtc)
    {
        if (expiresUtc.HasValue)
            _cache.Set(key, value, new DateTimeOffset(
                DateTime.SpecifyKind(expiresUtc.Value, DateTimeKind.Utc)));
        else
            _cache.Set(key, value);
    }

    /// <summary>The expiry a value written now would carry, or null when nothing expires.</summary>
    private DateTime? Expiry() => _ttl.HasValue ? DateTime.UtcNow + _ttl.Value : null;
}
