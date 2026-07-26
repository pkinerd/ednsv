using System.Collections.Concurrent;
using System.Text.Json.Nodes;

namespace Ednsv.Core.Services;

/// <summary>
/// The write queue for caches that keep their entries in a plain dictionary rather
/// than a <see cref="ProbeCache{T}"/> — RCPT probes, relay tests, AXFR results,
/// unreachable-server counts and domain result summaries.
///
/// <para>These could have been written out whole on every flush instead, since they
/// are small. They are not, because the bag is also the dirty flag: with any
/// wholesale source in the mix a flush would find records every single tick and
/// write a file whether or not anything had changed, which is the amplification this
/// design exists to remove. Queueing each write keeps an idle process silent.</para>
///
/// <para>Unlike a <see cref="ProbeCache{T}"/> bag there is no MemoryCache behind
/// this to check an entry against — these dictionaries hold their values for the
/// life of the process — so a queued entry is written as it stands. Expiry applies
/// on disk via <see cref="BagEntry{TValue}.ExpiresUtc"/> and on the next load.</para>
/// </summary>
public sealed class WriteBag<TValue>
{
    private readonly ConcurrentDictionary<string, BagEntry<TValue>> _bag = new();
    private readonly TimeSpan? _ttl;

    public WriteBag(TimeSpan? ttl)
    {
        _ttl = ttl;
    }

    /// <summary>Entries queued for the next flush. Not the size of the cache itself.</summary>
    public int Count => _bag.Count;

    /// <summary>Queue a freshly-fetched value. Imports from disk must not call this.</summary>
    public void Add(string key, TValue value)
    {
        var now = DateTime.UtcNow;
        _bag[key] = new BagEntry<TValue>(value, now, _ttl.HasValue ? now + _ttl.Value : DateTime.MaxValue);
    }

    /// <summary>Drop a queued entry — used when the cached value it stood for is
    /// invalidated before it was ever written.</summary>
    public void Remove(string key) => _bag.TryRemove(key, out _);

    public void Remove(Func<string, bool> predicate)
    {
        foreach (var key in _bag.Keys.Where(predicate).ToList())
            _bag.TryRemove(key, out _);
    }

    /// <summary>See <see cref="ProbeCache{T}.CollectPending"/> — same contract, same
    /// reference-matched commit.</summary>
    public PendingWrites Collect(string type, Func<TValue, JsonNode?> serialize)
    {
        var snapshot = _bag.ToArray();
        if (snapshot.Length == 0) return PendingWrites.None;

        var records = new List<CacheRecord>(snapshot.Length);
        var claimed = new List<KeyValuePair<string, BagEntry<TValue>>>(snapshot.Length);

        foreach (var kv in snapshot)
        {
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

        if (records.Count == 0) return PendingWrites.None;

        return new PendingWrites(records, () =>
        {
            foreach (var kv in claimed) _bag.TryRemove(kv);
        });
    }
}
