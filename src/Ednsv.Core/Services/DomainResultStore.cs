using System.Text.Json;

namespace Ednsv.Core.Services;

/// <summary>
/// The per-domain record of the last validation — severity counts plus the checks
/// that came back at warning or above. Read by <see cref="RecheckHelper"/> to decide
/// which cache types a targeted recheck should bypass.
///
/// <para>It used to write itself straight to disk on every completed validation, a
/// full read-modify-write of one JSON file under a semaphore. It now behaves like
/// every other cache: the in-memory map updates immediately, and the write is queued
/// for the flush timer.</para>
///
/// <para>What that costs is bounded. An <i>ungraceful</i> crash loses up to one flush
/// interval of these notes, so an affected domain's next targeted recheck bypasses
/// nothing and serves from cache — a recheck less aggressive than asked for, not a
/// wrong answer. The running process is unaffected, since the map is updated inline,
/// and a graceful shutdown flushes.</para>
///
/// <para>The map expires on the configured TTL, so a summary cannot outlive the probe
/// results a recheck decision would be made against. The file it replaced expired
/// nothing at all, and recheck decisions could rest on month-old records.</para>
/// </summary>
public sealed class DomainResultStore
{
    private readonly ExpiringMap<string, DomainResultSummary> _results;
    private readonly WriteBag<DomainResultSummary> _bag;

    /// <param name="persist">False when there is no disk tier configured: the map is
    /// still kept, since recheck decisions within this process depend on it, but
    /// nothing is queued for a write that will never happen.</param>
    public DomainResultStore(TimeSpan? ttl, bool persist = true)
    {
        _results = new ExpiringMap<string, DomainResultSummary>(ttl);
        _bag = new WriteBag<DomainResultSummary>(ttl, persist);
    }

    /// <summary>
    /// How many summaries are held, including any that have expired but not yet been
    /// swept — see <see cref="ExpiringMap{TKey,TValue}.Count"/>. Whether a particular
    /// domain's summary is still live is a question for <see cref="TryGet"/>.
    /// </summary>
    public int Count => _results.Count;

    /// <summary>Record a validation that just completed. Queued for the next flush.</summary>
    public void Set(string domain, DomainResultSummary summary)
    {
        var key = domain.ToLowerInvariant();
        _results.Set(key, summary);
        _bag.Add(key, summary);
    }

    /// <summary>
    /// Take a summary read from disk. Memory only — it is already persisted — and
    /// add-if-absent, so a validation that completed while the background load was
    /// running keeps its result rather than being overwritten by an older one.
    ///
    /// <para><paramref name="expiresUtc"/> is the expiry stamped on the record, kept
    /// rather than replaced with a fresh full TTL so a nearly-dead summary is not
    /// resurrected for another whole period.</para>
    /// </summary>
    public bool Import(string domain, DomainResultSummary summary, DateTime? expiresUtc = null)
        => expiresUtc.HasValue
            ? _results.TryAdd(domain.ToLowerInvariant(), summary, expiresUtc.Value)
            : _results.TryAdd(domain.ToLowerInvariant(), summary);

    public bool TryGet(string domain, out DomainResultSummary summary)
        => _results.TryGetValue(domain.ToLowerInvariant(), out summary!);

    public PendingWrites CollectPending()
        => _bag.Collect(CacheTypes.DomainResults, s => JsonSerializer.SerializeToNode(s));
}
