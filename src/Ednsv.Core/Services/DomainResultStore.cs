using System.Collections.Concurrent;
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
/// and a graceful shutdown flushes. Folding it in also fixes its unbounded growth for
/// free, because queued entries carry an expiry and the old file never expired
/// anything.</para>
/// </summary>
public sealed class DomainResultStore
{
    private readonly ConcurrentDictionary<string, DomainResultSummary> _results = new();
    private readonly WriteBag<DomainResultSummary> _bag;

    public DomainResultStore(TimeSpan? ttl)
    {
        _bag = new WriteBag<DomainResultSummary>(ttl);
    }

    /// <summary>Every summary this process knows, keyed by lowercased domain.</summary>
    public ConcurrentDictionary<string, DomainResultSummary> Results => _results;

    /// <summary>Record a validation that just completed. Queued for the next flush.</summary>
    public void Set(string domain, DomainResultSummary summary)
    {
        var key = domain.ToLowerInvariant();
        _results[key] = summary;
        _bag.Add(key, summary);
    }

    /// <summary>Take a summary read from disk. Memory only — it is already persisted.</summary>
    public void Import(string domain, DomainResultSummary summary)
        => _results[domain.ToLowerInvariant()] = summary;

    public bool TryGet(string domain, out DomainResultSummary summary)
        => _results.TryGetValue(domain.ToLowerInvariant(), out summary!);

    public PendingWrites CollectPending()
        => _bag.Collect(CacheTypes.DomainResults, s => JsonSerializer.SerializeToNode(s));
}
