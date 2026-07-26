using System.Collections.Concurrent;

namespace Ednsv.Core.Services;

/// <summary>
/// A keyed map whose entries expire, for the caches that are not a
/// <see cref="ProbeCache{T}"/>: RCPT probes, relay tests, AXFR verdicts and
/// responses, unreachable-server counts, domain result summaries and the per-server
/// <c>LookupClient</c> pool.
///
/// <para><b>Why not just use MemoryCache.</b> Two of those callers need something it
/// does not offer on .NET 8: an atomic read-modify-write (the unreachable-server
/// counter, which increments a value derived from the one already cached) and
/// enumeration of what is live (the domain summaries — <c>MemoryCache</c> exposes
/// <c>Count</c> and nothing else until <c>Keys</c> arrives in .NET 9, which is why
/// <see cref="ProbeCache{T}"/> has to keep a parallel key index of its own). A
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> of value-plus-expiry gives both, and
/// it is what these caches already were — minus the expiry.</para>
///
/// <para><b>Maintenance follows MemoryCache's own design rather than inventing one.</b>
/// Expiry is enforced on read: an entry past its expiry is treated as absent and
/// removed on the spot, so the TTL is honoured exactly whether or not anything has
/// swept. That leaves keys written once and never read again, which is what
/// <see cref="Prune"/> is for — and the sweep is <i>triggered</i> by a write,
/// <i>rate-limited</i> to one per <see cref="PruneInterval"/>, and <i>run on the thread
/// pool</i> rather than on the caller. MemoryCache does the same three things:
/// <c>StartScanForExpiredItemsIfNeeded</c> runs on cache operations, gated by
/// <c>ExpirationScanFrequency</c> (also a minute by default), and hands
/// <c>ScanForExpiredItems</c> to <c>TaskScheduler.Default</c>. Triggering on a write
/// rather than a timer is what makes an idle map free: it cannot be growing, so it
/// needs no upkeep, and there is no timer to own or dispose.</para>
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

    /// <summary>Shortest gap between automatic prunes. A minute, matching
    /// <c>MemoryCacheOptions.ExpirationScanFrequency</c>'s default: expired entries stay
    /// unreadable throughout, so the only thing the interval bounds is how long their
    /// memory is held.</summary>
    private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);

    private readonly TimeSpan _pruneInterval;

    // Monotonic, so a clock change cannot stall or storm the sweep.
    private long _lastPruneTicks = Environment.TickCount64;

    // 0 = nothing scheduled, 1 = a prune is queued or running.
    //
    // The interval check below already stops a burst of writers queueing a scan each,
    // and in practice it stops all of them — a test releasing 64 threads at once cannot
    // get a second one through the window, and MemoryCache ships with this same race and
    // no gate at all. This makes it a guarantee rather than a very high probability, and
    // covers the one case no time gate can: a scan that outlives its own interval, where
    // the next write would otherwise queue a second scan over the same entries.
    private int _pruneScheduled;

    /// <param name="ttl">Entry lifetime, or null for no expiry.</param>
    /// <param name="pruneInterval">Overrides <see cref="PruneInterval"/>. For tests: the
    /// default is a minute, which no test should be waiting out.</param>
    public ExpiringMap(TimeSpan? ttl, TimeSpan? pruneInterval = null)
    {
        _ttl = ttl;
        _pruneInterval = pruneInterval ?? PruneInterval;
    }

    private DateTime Expiry() => _ttl.HasValue ? DateTime.UtcNow + _ttl.Value : DateTime.MaxValue;

    /// <summary>Entries held, expired ones included. The gap between this and
    /// <see cref="Count"/> is prune lag — the only thing standing between the TTL and
    /// the memory actually released, and the number to look at when asking whether this
    /// map can grow without bound.</summary>
    public int AllocatedCount => _map.Count;

    /// <summary>
    /// Sweeps that have run. Only a diagnostic, but it is what makes the two claims
    /// about the maintenance path assertable rather than merely intended: that a burst
    /// of concurrent writes schedules <i>one</i> sweep between them, and that the
    /// interval — not the write count — is what paces them.
    /// </summary>
    public int PruneRuns => Volatile.Read(ref _pruneRuns);

    private int _pruneRuns;

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
        SchedulePruneIfDue();

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
        SchedulePruneIfDue();
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
        SchedulePruneIfDue();
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

    /// <summary>
    /// Drop every expired entry. Scheduled automatically after a write; public because a
    /// caller with a natural maintenance point can do it sooner, and because a test
    /// should be able to force it rather than wait.
    ///
    /// <para>Removals match the whole entry, so a value written while this is running is
    /// never taken with the expired one it replaced. Enumerating a
    /// <see cref="ConcurrentDictionary{TKey,TValue}"/> while removing from it is
    /// supported and does not throw, so no snapshot copy is needed.</para>
    /// </summary>
    public void Prune()
    {
        Interlocked.Increment(ref _pruneRuns);

        var now = DateTime.UtcNow;
        foreach (var kv in _map)
            if (kv.Value.ExpiresUtc <= now)
                _map.TryRemove(kv);
    }

    /// <summary>
    /// Called after every write. Cheap on the hot path — two reads and, at most once a
    /// minute, one <c>CompareExchange</c> and a thread-pool queue — because the scan
    /// itself must not land on the caller. These writes are completed by probe threads
    /// finishing a network round-trip, and walking a few thousand entries is not their
    /// work.
    /// </summary>
    private void SchedulePruneIfDue()
    {
        var now = Environment.TickCount64;
        if (now - Volatile.Read(ref _lastPruneTicks) < _pruneInterval.TotalMilliseconds) return;

        // Single-flight: whoever wins the gate owns the next scan, and everyone else
        // returns immediately. Released in PruneAndRelease.
        if (Interlocked.CompareExchange(ref _pruneScheduled, 1, 0) != 0) return;

        Volatile.Write(ref _lastPruneTicks, now);

        // Unsafe = does not capture the ExecutionContext, which is the point as well as
        // the saving: a sweep has no business inheriting the recheck flags or the trace
        // sink of whichever validation happened to trigger it.
        ThreadPool.UnsafeQueueUserWorkItem(
            static state => state.PruneAndRelease(), this, preferLocal: false);
    }

    private void PruneAndRelease()
    {
        try { Prune(); }
        catch { /* a cache sweep must never take the process down */ }
        finally { Volatile.Write(ref _pruneScheduled, 0); }
    }
}
