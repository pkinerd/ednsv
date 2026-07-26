using DnsClient;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Record-TTL gating end to end through the resolver, rather than over the clamp in
/// isolation. Needs live DNS, and self-skips without it, as the round-trip tests do.
///
/// <para>What matters most here is the <i>default</i>: gating ships off, so a live
/// query must still produce an entry bounded only by the cache TTL. Turning it on is
/// a separate, later decision.</para>
/// </summary>
public sealed class DnsTtlGatingTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromHours(2);

    private static async Task<CacheRecord?> QueryAndCollect(DnsResolverService dns)
    {
        var response = await dns.QueryAsync("example.com", QueryType.A);
        if (response.HasError) return null; // no outbound DNS — nothing to assert on

        foreach (var pending in dns.CollectPendingWrites())
            foreach (var record in pending.Records)
                if (record.Type == CacheTypes.Dns) return record;

        return null;
    }

    private static bool Ready(CacheRecord? record)
    {
        if (record != null) return true;
        Console.WriteLine("SKIPPED: no outbound DNS");
        return false;
    }

    [Fact]
    public async Task ByDefaultAnEntryIsBoundedOnlyByTheCacheTtl()
    {
        var dns = new DnsResolverService(null, cacheTtl: Cap);
        var before = DateTime.UtcNow;

        var record = await QueryAndCollect(dns);
        if (!Ready(record)) return;

        Assert.InRange(record!.ExpiresUtc, before.AddHours(2).AddSeconds(-5), DateTime.UtcNow.AddHours(2));
    }

    [Fact]
    public async Task WithAFloorSetTheEntryIsBoundedByTheZonesRecordTtls()
    {
        // example.com publishes an A record TTL well under two hours, so gating on
        // must visibly shorten the entry. The floor is small enough not to swallow it.
        var dns = new DnsResolverService(null, cacheTtl: Cap,
            tuning: new DnsTuning { CacheMinTtlSeconds = 5 });
        var before = DateTime.UtcNow;

        var record = await QueryAndCollect(dns);
        if (!Ready(record)) return;

        Assert.True(record!.ExpiresUtc < before.AddHours(1),
            $"expected a record-bounded expiry, got {record.ExpiresUtc:O} against a 2h cap");
        Assert.True(record.ExpiresUtc > before, "the entry expired before it was written");
    }

    [Fact]
    public async Task AGenerousFloorRaisesAShortRecordTtl()
    {
        // The floor is what stops a domain with 30-second records forcing a refetch
        // on essentially every validation.
        var dns = new DnsResolverService(null, cacheTtl: Cap,
            tuning: new DnsTuning { CacheMinTtlSeconds = 3600 });
        var before = DateTime.UtcNow;

        var record = await QueryAndCollect(dns);
        if (!Ready(record)) return;

        Assert.InRange(record!.ExpiresUtc, before.AddMinutes(59), DateTime.UtcNow.AddMinutes(61));
    }

    [Fact]
    public async Task TheCacheTtlRemainsTheCeilingEvenWithAnAbsurdFloor()
    {
        var dns = new DnsResolverService(null, cacheTtl: Cap,
            tuning: new DnsTuning { CacheMinTtlSeconds = 60 * 60 * 24 * 7 });
        var before = DateTime.UtcNow;

        var record = await QueryAndCollect(dns);
        if (!Ready(record)) return;

        Assert.InRange(record!.ExpiresUtc, before.AddHours(2).AddSeconds(-5), DateTime.UtcNow.AddHours(2));
    }
}
