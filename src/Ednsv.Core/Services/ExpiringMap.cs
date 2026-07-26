using System.Collections.Concurrent;

namespace Ednsv.Core.Services;

/// <summary>
/// A keyed map whose entries expire, for the caches that are not a
/// <see cref="ProbeCache{T}"/>: RCPT probes, relay tests, AXFR verdicts and
/// responses, unreachable-server counts, domain result summaries and the per-server
/// <c>LookupClient</c> pool.
///
/// <para><b>Why not just use MemoryCache.</b> Three of those callers need something
/// MemoryCache does not offer: an atomic read-modify-write (the unreachable-server
/// counter), a non-string key (the AXFR caches are keyed by an
/// <c>(ip, domain)</c> tuple), and enumeration of what is live (the domain summaries).
/// A <see cref="ConcurrentDictionary{TKey,TValue}"/> of value-plus-expiry gives all
/// three, and it is what these caches already were — minus the expiry.</para>
///
/// <para><b>Expiry is enforced on read, not by a timer.</b> An entry past its expiry
/// is treated as absent and removed on the spot, so the TTL is honoured exactly
/// whether or not anything has swept. The sweep — <see cref="Prune"/>, run
/// automatically every <see cref="PruneEvery"/> writes — exists only to bound
/// <i>memory</i>, for keys that are written once and never read again. Tying it to
/// writes rather than a timer means a map nobody is writing to needs no upkeep, since
/// it cannot be growing either.</para>
///
/// <para>A null TTL means no expiry, the same thing <c>CacheTtlHours=0</c> means
/// everywhere else: entries then live for the process, bounded by the number of
/// distinct keys exactly as <see cref="Microsoft.Extensions.Caching.Memory.MemoryCache"/>
/// would be.</para>
/// </summary>
public sealed class ExpiringMap<TKey, TValue> where TKey : notnull
{
    /// <summary>Value plus its own expiry. A record struct so
    /// <see cref="ConcurrentDictionary{TKey,TValue}.TryRemove(KeyValuePair{TKey,TValue})"/>
    /// can compare the whole entry, which is what stops a read-side eviction from
    /// dropping the newer value that replaced the expired one it found. The comparison
    /// is by <c>EqualityComparer&lt;Entry&gt;.Default</c>, so for a value type with
    /// value equality a replacement written in the same clock tick, with an identical
    /// value, could still be evicted — one extra miss on a cache, and nothing worse.</summary>
    private readonly record struct Entry(TValue Value, DateTime ExpiresUtc);

    private readonly ConcurrentDictionary<TKey, Entry> _map = new();
    private readonly TimeSpan? _ttl;

    /// <summary>Writes between automatic prunes. Small enough that overshoot is
    /// negligible against the caches this holds, large enough that the scan is
    /// amortised to nothing.</summary>
    private const int PruneEvery = 256;

    private int _writesSincePrune;

    public ExpiringMap(TimeSpan? ttl) => _ttl = ttl;

    private DateTime Expiry() => _ttl.HasValue ? DateTime.UtcNow + _ttl.Value : DateTime.MaxValue;

    /// <summary>Entries held, expired ones included. The gap between this and
    /// <see cref="Count"/> is prune lag — the only thing standing between the TTL and
    /// the memory actually released, and the number to look at when asking whether this
    /// map can grow without bound.</summary>
    public int AllocatedCount => _map.Count;

    /// <summary>Live entries. Expired ones are excluded whether or not they have been
    /// pruned yet, so this is the cache size rather than the allocation size.</summary>
    public int Count
    {
        get
        {
            var now = DateTime.UtcNow;
            var n = 0;
            foreach (var kv in _map)
                if (kv.Value.ExpiresUtc > now) n++;
            return n;
        }
    }

    /// <summary>
    /// Read a value. An expired entry is a miss, and is removed as it is found —
    /// matched by whole entry, so a fresher value written between the read and the
    /// removal survives.
    ///
    /// <para><paramref name="recheckFlag"/> is the recheck bypass, identical in
    /// mechanism and meaning to <see cref="ProbeCache{T}.TryGet"/>: when the current
    /// validation is rechecking this cache type, every read is a miss so the caller
    /// refetches. It is <see cref="RecheckHelper.CacheDep.None"/> — never bypassed —
    /// for a caller that has no cache type of its own.</para>
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

        if (_map.TryGetValue(key, out var entry))
        {
            if (entry.ExpiresUtc > DateTime.UtcNow)
            {
                value = entry.Value;
                return true;
            }
            _map.TryRemove(new KeyValuePair<TKey, Entry>(key, entry));
        }

        value = default!;
        return false;
    }

    /// <summary>
    /// Add if no live value is present, returning whether this call stored the value.
    /// An expired entry counts as absent and is replaced, so a cache whose entry has
    /// aged out accepts the refetched value rather than silently discarding it — the
    /// bug a bare <c>TryAdd</c> against a map with expiry would have.
    /// </summary>
    public bool TryAdd(TKey key, TValue value) => TryAdd(key, value, Expiry());

    /// <summary>
    /// As <see cref="TryAdd(TKey,TValue)"/>, with an expiry of the caller's choosing —
    /// an entry read from disk keeps the expiry stamped on its record rather than being
    /// handed a fresh full TTL and resurrected.
    /// </summary>
    public bool TryAdd(TKey key, TValue value, DateTime expiresUtc)
    {
        if (expiresUtc <= DateTime.UtcNow) return false;
        CountWrite();

        while (true)
        {
            if (_map.TryAdd(key, new Entry(value, expiresUtc))) return true;

            if (!_map.TryGetValue(key, out var existing)) continue; // removed under us — retry
            if (existing.ExpiresUtc > DateTime.UtcNow) return false; // a live value wins

            if (_map.TryUpdate(key, new Entry(value, expiresUtc), existing)) return true;
        }
    }

    /// <summary>Store a value, replacing whatever is there.</summary>
    public void Set(TKey key, TValue value)
    {
        CountWrite();
        _map[key] = new Entry(value, Expiry());
    }

    /// <summary>
    /// Atomic read-modify-write, for a value derived from the one already cached.
    /// An expired entry is treated as absent, so <paramref name="add"/> runs rather
    /// than <paramref name="update"/> being handed a stale value. Either way the entry
    /// gets a fresh expiry: it has just been written.
    /// </summary>
    public TValue AddOrUpdate(TKey key, TValue add, Func<TValue, TValue> update)
    {
        CountWrite();
        var expires = Expiry();
        var entry = _map.AddOrUpdate(key,
            _ => new Entry(add, expires),
            (_, existing) => existing.ExpiresUtc > DateTime.UtcNow
                ? new Entry(update(existing.Value), expires)
                : new Entry(add, expires));
        return entry.Value;
    }

    /// <summary>
    /// Get the cached value or create it. The factory may run more than once under
    /// contention — only one result is stored — so it must be cheap and side-effect
    /// free, exactly as <see cref="ConcurrentDictionary{TKey,TValue}.GetOrAdd"/>
    /// requires. Use <see cref="ProbeCache{T}"/> where a single call matters.
    /// </summary>
    public TValue GetOrAdd(TKey key, Func<TKey, TValue> factory)
    {
        if (TryGetValue(key, out var live)) return live;

        var created = factory(key);
        if (TryAdd(key, created)) return created;

        // Someone else got there first; prefer their copy, but fall back to ours if it
        // has already gone again.
        return TryGetValue(key, out var winner) ? winner : created;
    }

    public bool TryRemove(TKey key) => _map.TryRemove(key, out _);

    /// <summary>Live entries, as a snapshot. Safe to enumerate while others write.</summary>
    public IEnumerable<KeyValuePair<TKey, TValue>> Snapshot()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _map.ToArray())
            if (kv.Value.ExpiresUtc > now)
                yield return new KeyValuePair<TKey, TValue>(kv.Key, kv.Value.Value);
    }

    /// <summary>Drop every expired entry. Called automatically as writes accumulate;
    /// public so a caller with a natural maintenance point can do it sooner.</summary>
    public void Prune()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _map.ToArray())
            if (kv.Value.ExpiresUtc <= now)
                _map.TryRemove(kv);
    }

    private void CountWrite()
    {
        if (Interlocked.Increment(ref _writesSincePrune) < PruneEvery) return;

        Interlocked.Exchange(ref _writesSincePrune, 0);
        Prune();
    }
}
