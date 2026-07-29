using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The second, tighter ceiling on negative answers.
///
/// <para>A stale "this exists" merely goes out of date. A stale "this does not exist"
/// becomes a false finding — "No PTR record, Gmail will reject mail" against an IP with
/// perfectly good reverse DNS. Honouring an SOA MINIMUM of a day for an answer a
/// stressed resolver may simply have got wrong turns one bad reply into a long-lived,
/// disk-persisted, fleet-shared error, so negatives get far less tolerance than
/// positives.</para>
/// </summary>
public sealed class NegativeTtlCapTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromHours(2);      // CacheTtlHours
    private static readonly TimeSpan NegCap = TimeSpan.FromSeconds(600); // the default
    private static readonly TimeSpan Floor = TimeSpan.FromSeconds(60);

    [Fact]
    public void ALongSoaMinimumIsHeldToTheNegativeCap()
    {
        // cnn.com publishes 86400 (the Route 53 default). Without this cap that became
        // two hours — the cache TTL — for an answer that may be wrong.
        Assert.Equal(NegCap,
            DnsCacheTtl.ForNegative(TimeSpan.FromSeconds(86400), Floor, Cap, NegCap));
    }

    [Fact]
    public void AShortSoaMinimumIsStillHonoured()
    {
        // The cap is a ceiling, not a replacement: a zone asking for less gets less.
        Assert.Equal(TimeSpan.FromSeconds(300),
            DnsCacheTtl.ForNegative(TimeSpan.FromSeconds(300), Floor, Cap, NegCap));
    }

    [Fact]
    public void TheFloorStillRaisesAVeryShortNegativeTtl()
    {
        Assert.Equal(Floor, DnsCacheTtl.ForNegative(TimeSpan.FromSeconds(5), Floor, Cap, NegCap));
    }

    [Fact]
    public void TheCacheTtlRemainsTheOuterCeiling()
    {
        // A negative cap above CacheTtlHours must not extend anything — the sweep still
        // deletes the record file at fileTime + CacheTtlHours.
        Assert.Equal(Cap, DnsCacheTtl.ForNegative(TimeSpan.FromDays(7), Floor, Cap,
            TimeSpan.FromDays(30)));
    }

    [Fact]
    public void TheCapAppliesEvenWithGatingOff()
    {
        // Independent of the floor, unlike DnsCacheTtl.For: it is a ceiling, and the
        // damage it bounds does not depend on whether record-TTL gating is enabled.
        // Gating ships off, so this is the default path.
        Assert.Equal(NegCap, DnsCacheTtl.ForNegative(TimeSpan.FromSeconds(86400),
            TimeSpan.Zero, Cap, NegCap));
        Assert.Equal(NegCap, DnsCacheTtl.ForNegative(null, TimeSpan.Zero, Cap, NegCap));
    }

    [Fact]
    public void WithNoCapConfiguredNothingChanges()
    {
        // 0 removes it: negatives fall back to being bounded by the cache TTL alone.
        Assert.Null(DnsCacheTtl.ForNegative(TimeSpan.FromSeconds(86400), TimeSpan.Zero, Cap, null));
        Assert.Equal(Cap, DnsCacheTtl.ForNegative(TimeSpan.FromSeconds(86400), Floor, Cap, null));
    }

    [Fact]
    public void ANegativeAnswerWithNoSoaTakesTheCapRatherThanTheCacheTtl()
    {
        // The caller only reaches here once the response is an answer with an empty
        // answer section, so this is still a negative answer — the cap is the safer
        // reading of the two.
        Assert.Equal(NegCap, DnsCacheTtl.ForNegative(null, Floor, Cap, NegCap));
    }

    [Fact]
    public void PositiveAnswersAreUntouchedByTheNegativeCap()
    {
        // The asymmetry is the whole point: a 6-hour A record still gets the cache TTL,
        // not ten minutes.
        Assert.Equal(Cap, DnsCacheTtl.For(TimeSpan.FromSeconds(21600), Floor, Cap));
        Assert.Equal(TimeSpan.FromSeconds(1800), DnsCacheTtl.For(TimeSpan.FromSeconds(1800), Floor, Cap));
    }

    [Fact]
    public void TheShippedDefaultIsTenMinutes()
    {
        Assert.Equal(600, new DnsTuning().CacheNegativeTtlCapSeconds);
    }

    [Fact]
    public void ARecheckStillBypassesACappedNegativeEntry()
    {
        // The cap shortens a negative answer's life; a recheck ignores its life
        // entirely. "Recheck all" must reach the network however fresh the entry is.
        var cache = new ProbeCache<List<string>>(Cap, persist: false);
        cache.Set("ptr:1.2.3.4", new List<string>(), NegCap);

        Assert.True(cache.TryGet("ptr:1.2.3.4", out _, RecheckHelper.CacheDep.Smtp));

        RecheckHelper.CurrentRecheckDeps.Value = RecheckHelper.CacheDep.All;
        try
        {
            Assert.False(cache.TryGet("ptr:1.2.3.4", out _, RecheckHelper.CacheDep.Ptr),
                "a recheck read a cached negative answer instead of refetching");
        }
        finally { RecheckHelper.CurrentRecheckDeps.Value = RecheckHelper.CacheDep.None; }
    }
}
