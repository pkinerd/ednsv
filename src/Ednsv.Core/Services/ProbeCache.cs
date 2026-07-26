using System.Collections.Concurrent;
using System.Text.Json.Nodes;
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

    /// <summary>Write-through to the L2 (fire-and-forget). Best-effort.
    /// <paramref name="entryTtl"/> overrides the cache-wide TTL for values that carry
    /// their own — a DNS answer bounded by its record TTL, say — so the shared copy
    /// does not outlive the local one.</summary>
    public void Set(string key, TValue value, TimeSpan? entryTtl = null)
    {
        var db = _redis.GetDatabase();
        if (db == null) return;
        string? payload;
        try { payload = _serialize(value); }
        catch { return; }
        if (payload == null) return;
        try { db.StringSet(_redis.Key(_prefix + key), payload, entryTtl ?? _ttl, flags: CommandFlags.FireAndForget); }
        catch { /* best effort — an L2 write failure just means the next pod refills */ }
    }

    /// <summary>
    /// Publish a value read from disk into the shared L2, but only if no value is
    /// there already. Used to warm Redis from the disk tier at startup.
    ///
    /// <para>Both halves matter. <paramref name="ttl"/> is the entry's <i>remaining</i>
    /// life, not a fresh full TTL, or loading a nearly-dead entry would resurrect it
    /// for another whole period. <c>When.NotExists</c> keeps a cluster-wide restart
    /// idempotent and stops one instance overwriting a fresher value another has
    /// already published — every instance holds an overlapping view of the same
    /// files, so without it they would all race to publish their own copies.</para>
    /// </summary>
    public void SetIfAbsent(string key, TValue value, TimeSpan ttl)
    {
        if (ttl <= TimeSpan.Zero) return;
        var db = _redis.GetDatabase();
        if (db == null) return;
        string? payload;
        try { payload = _serialize(value); }
        catch { return; }
        if (payload == null) return;
        try
        {
            db.StringSet(_redis.Key(_prefix + key), payload, ttl,
                when: When.NotExists, flags: CommandFlags.FireAndForget);
        }
        catch { /* best effort */ }
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

    // False when there is no disk tier configured. The gate belongs here rather than
    // only on the flusher: with nothing draining it, a bag nobody writes out grows for
    // the life of the process.
    private readonly bool _persist;

    /// <summary>
    /// Key → absolute expiry for everything in L1, so the shared cache can be
    /// republished from memory after it has been emptied. <see cref="MemoryCache"/>
    /// cannot be enumerated on .NET 8, hence the parallel index.
    ///
    /// <para>Null unless there is a shared tier to warm <i>and</i> something that will
    /// warm it, so a single-instance deployment pays nothing for it at all. The second
    /// half of that condition matters as much as the first: nothing else prunes this
    /// index, so with the shared-cache watch turned off it would accumulate every
    /// distinct key the process ever cached — expired entries included — for the life
    /// of the process.</para>
    ///
    /// <para>It is a <i>hint</i>, not a second source of truth: every use checks the
    /// key against MemoryCache and drops it if it has gone. That makes a stale entry
    /// harmless, which matters because eviction callbacks fire lazily and cannot be
    /// relied on to keep an index exact.</para>
    /// </summary>
    private readonly ConcurrentDictionary<string, DateTime>? _l2Index;

    /// <param name="warmSharedCache">False when nothing will ever republish this cache
    /// into the shared tier — no Redis, or the shared-cache watch disabled. Skips the
    /// key index entirely; see <see cref="_l2Index"/>.</param>
    public ProbeCache(TimeSpan? ttl = null, ProbeCacheL2<TValue>? l2 = null, bool persist = true,
        bool warmSharedCache = true)
    {
        _cache = new MemoryCache(new MemoryCacheOptions());
        _ttl = ttl;
        _l2 = l2 != null && l2.Enabled ? l2 : null;
        _persist = persist;
        _l2Index = _l2 != null && warmSharedCache ? new ConcurrentDictionary<string, DateTime>() : null;
    }

    /// <summary>The expiry an entry cached now would carry.</summary>
    private DateTime AbsoluteExpiry(TimeSpan? entryTtl)
    {
        var ttl = entryTtl ?? _ttl;
        return ttl.HasValue ? DateTime.UtcNow + ttl.Value : DateTime.MaxValue;
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
        Action? onHit = null,
        Func<TValue, TimeSpan?>? entryTtl = null)
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
            return new Lazy<Task<TValue>>(() => RunFactory(key, factory, shouldPersist, bypass, entryTtl));
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

    private async Task<TValue> RunFactory(string key, Func<Task<TValue>> factory,
        Func<TValue, bool>? shouldPersist, bool skipL2Read, Func<TValue, TimeSpan?>? entryTtl)
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
                // Computed once and used for L1, the disk record and the L2 alike, so
                // a value bounded by its own TTL is bounded everywhere.
                TimeSpan? ttl;
                try { ttl = entryTtl?.Invoke(result); }
                catch { ttl = null; } // a TTL we cannot derive falls back to the cache's
                Set(key, result, ttl);
                _l2?.Set(key, result, ttl);
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

    /// <summary>
    /// Store a freshly fetched value in MemoryCache and queue it for persistence.
    ///
    /// <para><paramref name="entryTtl"/> lets a value shorten its own life below the
    /// cache-wide TTL — a DNS answer whose records say thirty seconds should not be
    /// served for two hours. It applies to the MemoryCache expiry and to the expiry
    /// stamped on the disk record together, so the two never disagree.</para>
    /// </summary>
    public void Set(string key, TValue value, TimeSpan? entryTtl = null)
    {
        var ttl = entryTtl ?? _ttl;
        var expires = ttl.HasValue ? DateTime.UtcNow + ttl.Value : DateTime.MaxValue;

        if (ttl.HasValue)
            _cache.Set(key, value, ttl.Value);
        else
            _cache.Set(key, value);

        if (_l2Index != null) _l2Index[key] = expires;

        if (!_persist) return; // no disk tier — nothing would ever drain the bag

        _bag[key] = new BagEntry<TValue>(value, DateTime.UtcNow, expires);
    }

    /// <summary>
    /// Store a value in MemoryCache only, without queueing it for persistence.
    /// Used for three cases that must not be written back: transient errors that
    /// should not outlive the process, values read from the shared Redis L2 (another
    /// instance already persisted them), and entries imported from disk (they are
    /// on disk by definition).
    /// </summary>
    private void SetMemoryOnly(string key, TValue value, DateTime? absoluteExpiryUtc = null)
    {
        if (absoluteExpiryUtc.HasValue)
            _cache.Set(key, value, new DateTimeOffset(
                DateTime.SpecifyKind(absoluteExpiryUtc.Value, DateTimeKind.Utc)));
        else if (_ttl.HasValue)
            _cache.Set(key, value, _ttl.Value);
        else
            _cache.Set(key, value);

        if (_l2Index != null) _l2Index[key] = absoluteExpiryUtc ?? AbsoluteExpiry(null);
    }

    /// <summary>
    /// Take an entry read from disk. Never queued for persistence — it came from
    /// disk, so writing it back is the redundancy this design exists to remove.
    ///
    /// <para><b>Present keys are left alone.</b> The load runs in the background
    /// while the instance is already serving, so a validation can fetch and cache a
    /// key before the loader reaches it. That value came from the network just now
    /// and the disk copy did not; overwriting it would age the cache backwards. A
    /// fetch still in flight counts as present, since it will cache its result on
    /// completion. The check is not atomic against a fetch that both starts and
    /// finishes inside it — the cost of closing that window is a lock on every read,
    /// and the consequence of losing it is one key holding a slightly older value
    /// until its expiry.</para>
    ///
    /// <para><paramref name="expiresUtc"/> is the entry's own expiry from its record.
    /// Honouring it means an entry with ten minutes left is cached for ten minutes
    /// rather than being handed a fresh full TTL and resurrected; one already past
    /// its expiry is refused outright. Records written before per-entry expiry
    /// existed pass null and fall back to the cache's TTL.</para>
    ///
    /// <para>Returns whether the value was taken.</para>
    /// </summary>
    public bool Import(string key, TValue value, DateTime? expiresUtc = null)
    {
        if (expiresUtc.HasValue && expiresUtc.Value <= DateTime.UtcNow) return false;

        // Warm the shared tier *before* consulting L1, not after. Whether we already
        // hold a key locally says nothing about whether the shared cache holds it —
        // and it matters most in the case the ordering would break: re-running the
        // load to repopulate an emptied Redis finds L1 already holding nearly
        // everything, so a warm placed below these checks would publish nothing at
        // all. `SetIfAbsent` makes it safe to attempt unconditionally.
        if (expiresUtc.HasValue && _l2 != null)
            _l2.SetIfAbsent(key, value, expiresUtc.Value - DateTime.UtcNow);

        if (_inflight.ContainsKey(key)) return false;
        if (_cache.TryGetValue(key, out TValue? live) && live != null) return false;

        SetMemoryOnly(key, value, expiresUtc);
        return true;
    }

    /// <summary>
    /// Snapshot the values awaiting persistence as writable records, plus the means
    /// to drop them once written. Entries whose MemoryCache copy has already expired
    /// are discarded rather than written; anything the serialiser rejects is left in
    /// the bag for a later attempt rather than silently lost.
    /// </summary>
    public PendingWrites CollectPending(string type, Func<TValue, JsonNode?> serialize)
    {
        var snapshot = _bag.ToArray();
        if (snapshot.Length == 0) return PendingWrites.None;

        var records = new List<CacheRecord>(snapshot.Length);
        var claimed = new List<KeyValuePair<string, BagEntry<TValue>>>(snapshot.Length);
        var dropped = new List<KeyValuePair<string, BagEntry<TValue>>>();

        foreach (var kv in snapshot)
        {
            if (!_cache.TryGetValue(kv.Key, out TValue? live) || live == null)
            {
                dropped.Add(kv); // expired out of memory before we got to it
                continue;
            }

            JsonNode? json;
            try { json = serialize(kv.Value.Value); }
            catch { continue; } // leave it queued; a later flush may fare better
            if (json == null) continue;

            records.Add(new CacheRecord
            {
                Type = type,
                Key = kv.Key,
                WrittenUtc = kv.Value.WrittenUtc,
                ExpiresUtc = kv.Value.ExpiresUtc,
                Value = json
            });
            claimed.Add(kv);
        }

        foreach (var kv in dropped) _bag.TryRemove(kv);

        return new PendingWrites(records, () =>
        {
            // Reference-matched removal: a newer entry for the same key that landed
            // during the write is not equal to this one and therefore survives.
            foreach (var kv in claimed) _bag.TryRemove(kv);
        });
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

    /// <summary>
    /// Republish everything this instance holds in L1 into the shared cache, for use
    /// after Redis has been emptied. Returns how many keys were published.
    ///
    /// <para>Memory rather than disk is the right source, and not only because it is
    /// fresher and needs no file I/O: <b>L1 is a superset of what this instance would
    /// have found on disk.</b> The startup load imports every instance's live records
    /// into L1, so after startup L1 holds those <i>plus</i> everything fetched since —
    /// including the last flush interval's worth, which is not on disk yet. It also
    /// works where a disk re-read cannot: a deployment running <c>CacheDir=none</c>
    /// against a managed Redis has no disk tier at all, and its L1 is then the only
    /// copy of those results in existence.</para>
    ///
    /// <para><c>SetIfAbsent</c> with each entry's remaining life, so instances warming
    /// concurrently cannot clobber each other or resurrect a nearly-dead value.</para>
    /// </summary>
    public int WarmSharedCache()
    {
        if (_l2 == null || _l2Index == null) return 0;

        var now = DateTime.UtcNow;
        var warmed = 0;

        foreach (var kv in _l2Index)
        {
            if (kv.Value <= now || !_cache.TryGetValue(kv.Key, out TValue? live) || live == null)
            {
                _l2Index.TryRemove(kv.Key, out _); // gone from L1 — the index was only a hint
                continue;
            }

            _l2.SetIfAbsent(kv.Key, live, kv.Value - now);
            warmed++;
        }

        return warmed;
    }

    /// <summary>
    /// Drop index entries whose keys have expired. Called periodically because
    /// MemoryCache expires lazily and never tells us: without this the index would
    /// accumulate every key the process had ever cached, rather than the live set.
    /// </summary>
    public void PruneSharedCacheIndex()
    {
        if (_l2Index == null) return;

        var now = DateTime.UtcNow;
        foreach (var kv in _l2Index)
            if (kv.Value <= now)
                _l2Index.TryRemove(kv.Key, out _);
    }

    /// <summary>Keys currently tracked for a shared-cache warm. Diagnostics and tests.</summary>
    public int SharedCacheIndexCount => _l2Index?.Count ?? 0;

    /// <summary>Remove entries matching a predicate.</summary>
    public void Remove(Func<string, bool> predicate)
    {
        foreach (var key in _bag.Keys)
        {
            if (predicate(key))
            {
                _cache.Remove(key);
                _bag.TryRemove(key, out _);
                _l2Index?.TryRemove(key, out _);
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

    /// <summary>See <see cref="ProbeCache{T}"/> — false when there is no disk tier.</summary>
    private readonly bool _persist;

    public ProbeCacheValue(TimeSpan? ttl = null, bool persist = true)
    {
        _cache = new MemoryCache(new MemoryCacheOptions());
        _ttl = ttl;
        _persist = persist;
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

        if (!_persist) return; // see ProbeCache<T>.Set

        var now = DateTime.UtcNow;
        _bag[key] = new BagEntry<TValue>(value, now, _ttl.HasValue ? now + _ttl.Value : DateTime.MaxValue);
    }

    private void SetMemoryOnly(string key, TValue value, DateTime? absoluteExpiryUtc = null)
    {
        var box = new Box { Value = value };
        if (absoluteExpiryUtc.HasValue)
            _cache.Set(key, box, new DateTimeOffset(
                DateTime.SpecifyKind(absoluteExpiryUtc.Value, DateTimeKind.Utc)));
        else if (_ttl.HasValue)
            _cache.Set(key, box, _ttl.Value);
        else
            _cache.Set(key, box);
    }

    /// <summary>See <see cref="ProbeCache{T}.Import"/> — same rules, no L2 behind
    /// this variant.</summary>
    public bool Import(string key, TValue value, DateTime? expiresUtc = null)
    {
        if (expiresUtc.HasValue && expiresUtc.Value <= DateTime.UtcNow) return false;
        if (_inflight.ContainsKey(key)) return false;
        if (_cache.TryGetValue(key, out Box? live) && live != null) return false;

        SetMemoryOnly(key, value, expiresUtc);
        return true;
    }

    /// <summary>See <see cref="ProbeCache{T}.CollectPending"/>.</summary>
    public PendingWrites CollectPending(string type, Func<TValue, JsonNode?> serialize)
    {
        var snapshot = _bag.ToArray();
        if (snapshot.Length == 0) return PendingWrites.None;

        var records = new List<CacheRecord>(snapshot.Length);
        var claimed = new List<KeyValuePair<string, BagEntry<TValue>>>(snapshot.Length);
        var dropped = new List<KeyValuePair<string, BagEntry<TValue>>>();

        foreach (var kv in snapshot)
        {
            if (!_cache.TryGetValue(kv.Key, out Box? box) || box == null)
            {
                dropped.Add(kv);
                continue;
            }

            JsonNode? json;
            try { json = serialize(kv.Value.Value); }
            catch { continue; }
            if (json == null) continue;

            records.Add(new CacheRecord
            {
                Type = type,
                Key = kv.Key,
                WrittenUtc = kv.Value.WrittenUtc,
                ExpiresUtc = kv.Value.ExpiresUtc,
                Value = json
            });
            claimed.Add(kv);
        }

        foreach (var kv in dropped) _bag.TryRemove(kv);

        return new PendingWrites(records, () =>
        {
            foreach (var kv in claimed) _bag.TryRemove(kv);
        });
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
