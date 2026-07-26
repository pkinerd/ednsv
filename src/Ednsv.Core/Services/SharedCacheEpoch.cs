using StackExchange.Redis;

namespace Ednsv.Core.Services;

/// <summary>
/// Notices when the shared Redis cache has been emptied underneath a running
/// instance, so the disk tier can be republished into it.
///
/// <para><b>Why this is needed.</b> A Redis restart without persistence, a
/// <c>FLUSHALL</c>, or a failover to an empty replica leaves the L2 cold — and it
/// does <i>not</i> refill on its own in any useful timeframe, because the instances
/// that would refill it are all still serving happily from their own L1 and disk and
/// have no reason to refetch. The shared cache stays degraded until entries age out
/// of L1 naturally. That silently breaks the recovery path the deployment guidance
/// leans on: a rescheduled pod with a pod-local cache directory is supposed to be
/// repopulated from the L2.</para>
///
/// <para><b>How.</b> A single nonce key. Its <i>value</i> is what matters, not its
/// contents: if it is gone, everything else is gone with it; if it has changed,
/// another instance has already noticed a flush and re-warmed. Either way the answer
/// is the same — republish what we hold.</para>
///
/// <para><b>Every instance re-warms, not just the one that noticed.</b> That looks
/// wasteful and is deliberate. On a shared mount one instance would suffice, since it
/// can read every instance's files; but the recommended layout alongside Redis is a
/// <i>pod-local</i> cache directory, where each instance holds only its own share and
/// a single warmer would republish only a fraction. The application cannot tell the
/// two layouts apart, so it does the thing that is correct for both. The redundant
/// case costs N passes of <c>SET NX</c> over the same keys, once, which is idempotent
/// and cannot clobber a fresher value.</para>
///
/// <para><b>Limits worth stating.</b> This detects the key vanishing, which is not
/// quite the same as the cache being emptied: under an <c>allkeys-*</c> eviction
/// policy the nonce can be evicted while other keys survive, producing a re-warm that
/// was not needed — harmless, since the warm is add-if-absent. Conversely a partial
/// eviction that spares the nonce goes unnoticed. It is a cheap heuristic for the
/// case that actually hurts, not a consistency mechanism.</para>
/// </summary>
public sealed class SharedCacheEpoch
{
    /// <summary>Deliberately outside the <c>cache:</c> namespace, so it can never
    /// collide with a cache type's keys.</summary>
    private const string KeySuffix = "cache-epoch";

    private readonly RedisConnection _redis;
    private string? _known;

    public SharedCacheEpoch(RedisConnection redis)
    {
        _redis = redis;
    }

    /// <summary>The epoch this instance last observed. Null until the first check.</summary>
    public string? Known => _known;

    /// <summary>
    /// Returns true when the shared cache should be re-warmed — that is, when the
    /// epoch has vanished or changed since the last successful check.
    ///
    /// <para>The first check never asks for a re-warm: startup has just loaded from
    /// disk, which warms the L2 already.</para>
    ///
    /// <para>An unreachable Redis is never mistaken for a flush — otherwise an outage
    /// would trigger a full disk re-read on every tick for as long as it lasted. Two
    /// guards cover that, and they are redundant on purpose rather than by accident: a
    /// failed read bails immediately, and a missing key is acted on only when the
    /// follow-up write succeeds, which proves the connection was live. Either alone
    /// handles a flat outage; the second is what covers a connection lost between the
    /// two calls. Note that <see cref="RedisConnection.GetDatabase"/> does <i>not</i>
    /// help here: with <c>abortConnect=false</c> the multiplexer hands back a database
    /// whether or not a server is reachable, so the failure surfaces on the command.</para>
    /// </summary>
    public async Task<bool> ShouldRewarmAsync()
    {
        var db = _redis.GetDatabase();
        if (db == null) return false;

        var key = _redis.Key(KeySuffix);

        string? current;
        try { current = await db.StringGetAsync(key); }
        catch { return false; } // unreachable, not empty

        if (current == null)
        {
            var mine = Guid.NewGuid().ToString("N");
            bool claimed;
            try { claimed = await db.StringSetAsync(key, mine, when: When.NotExists); }
            catch { return false; } // the write failed — treat it as an outage, not a flush

            if (claimed)
            {
                var firstEver = _known == null;
                _known = mine;
                // Nothing to do on the first check: the startup load already warmed it.
                return !firstEver;
            }

            // Another instance claimed it between our read and our write.
            try { current = await db.StringGetAsync(key); }
            catch { return false; }
            if (current == null) return false;
        }

        if (_known == null)
        {
            _known = current; // first observation of an epoch someone else established
            return false;
        }

        if (_known == current) return false;

        _known = current;
        return true;
    }
}
