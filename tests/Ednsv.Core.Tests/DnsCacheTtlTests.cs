using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The record-TTL clamp: how long a DNS answer may be cached given what the zone
/// published, the configured floor, and the cache-wide cap.
///
/// <para>It ships off. This release is "stop rewriting everything, and a shorter
/// cap"; gating is a second, separately observable change to enable once the effect
/// of the shorter cap has been seen on its own. These tests pin the arithmetic so
/// turning it on later is a config change rather than a code change.</para>
/// </summary>
public sealed class DnsCacheTtlTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromHours(2);

    // ── Gating off ───────────────────────────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(30)]
    [InlineData(1800)]
    [InlineData(86400)]
    public void WithNoFloorEveryAnswerGetsTheCacheTtl(int recordSeconds)
    {
        // Null means "no per-entry TTL", which leaves the cache-wide one governing —
        // exactly the behaviour before this existed.
        Assert.Null(DnsCacheTtl.For(TimeSpan.FromSeconds(recordSeconds), TimeSpan.Zero, Cap));
    }

    [Fact]
    public void ANegativeFloorIsTreatedAsOffRatherThanAsATtl()
    {
        Assert.Null(DnsCacheTtl.For(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(-1), Cap));
    }

    // ── The clamp ────────────────────────────────────────────────────────

    [Theory]
    // record,  floor,   expected
    [InlineData(0,       60,      60)]      // a zero TTL must not mean "never cache"
    [InlineData(30,      60,      60)]      // below the floor — raised
    [InlineData(30,      300,     300)]
    [InlineData(1800,    60,      1800)]    // between floor and cap — kept
    [InlineData(1800,    300,     1800)]
    [InlineData(86400,   60,      7200)]    // above the cap — lowered to it
    [InlineData(86400,   300,     7200)]
    [InlineData(60,      60,      60)]      // exactly the floor
    [InlineData(7200,    60,      7200)]    // exactly the cap
    public void TheRecordTtlIsClampedBetweenTheFloorAndTheCap(int record, int floor, int expected)
    {
        var ttl = DnsCacheTtl.For(TimeSpan.FromSeconds(record), TimeSpan.FromSeconds(floor), Cap);

        Assert.Equal(TimeSpan.FromSeconds(expected), ttl);
    }

    [Theory]
    [InlineData(60)]
    [InlineData(300)]
    public void AResponseThatPublishedNoTtlInheritsTheCacheTtl(int floor)
    {
        // The floor raises TTLs we were given; it is not a default for responses that
        // carried none. Null here means "no per-entry TTL", leaving CacheTtlHours
        // governing — the same answer gating-off gives.
        //
        // This used to return the floor, and it was the dominant path rather than a
        // corner: a validation of a clean domain issues hundreds of negative lookups,
        // so a 60-second floor became a 60-second lifetime for most of the cache.
        Assert.Null(DnsCacheTtl.For(null, TimeSpan.FromSeconds(floor), Cap));
    }

    [Fact]
    public void AFloorAboveTheCapIsStillCappedSoNothingOutlivesItsFile()
    {
        // A misconfigured floor must not let an entry outlive the record file it was
        // written into — the sweep deletes that file at fileTime + the cap.
        var ttl = DnsCacheTtl.For(TimeSpan.FromSeconds(30), TimeSpan.FromDays(7), Cap);

        Assert.Equal(Cap, ttl);
    }

    [Fact]
    public void WithNoCapTheFloorAndRecordTtlGovernAlone()
    {
        // The CLI runs without a cache TTL by default.
        Assert.Equal(TimeSpan.FromSeconds(1800),
            DnsCacheTtl.For(TimeSpan.FromSeconds(1800), TimeSpan.FromSeconds(60), cap: null));
        Assert.Equal(TimeSpan.FromDays(7),
            DnsCacheTtl.For(TimeSpan.FromDays(7), TimeSpan.FromSeconds(60), cap: null));
    }

    // ── Reading the answer section ───────────────────────────────────────

    private static DnsResourceRecord Record(string name, int ttl) =>
        new ARecord(new ResourceRecordInfo(name, ResourceRecordType.A, QueryClass.IN, ttl, 4),
            System.Net.IPAddress.Loopback);

    [Fact]
    public void TheMinimumTtlAcrossTheAnswerSectionIsUsed()
    {
        var answers = new[] { Record("a.example.", 3600), Record("b.example.", 45), Record("c.example.", 600) };

        Assert.Equal(TimeSpan.FromSeconds(45), DnsCacheTtl.MinRecordTtl(answers));
    }

    [Fact]
    public void AnEmptyAnswerSectionHasNoMinimum()
    {
        Assert.Null(DnsCacheTtl.MinRecordTtl(Array.Empty<DnsResourceRecord>()));
    }

    [Fact]
    public void AZeroTtlRecordIsReadAsZeroNotAsAbsent()
    {
        Assert.Equal(TimeSpan.Zero, DnsCacheTtl.MinRecordTtl(new[] { Record("a.example.", 0) }));
    }

    // ── Reading the authority section (negative answers) ─────────────────

    private static SoaRecord Soa(int ttl, uint minimum) =>
        new(new ResourceRecordInfo("example.", ResourceRecordType.SOA, QueryClass.IN, ttl, 0),
            DnsString.Parse("ns.example."), DnsString.Parse("hostmaster.example."),
            serial: 1, refresh: 7200, retry: 3600, expire: 1209600, minimum: minimum);

    [Theory]
    // soaTtl, minimum, expected — RFC 2308 §5 takes the lesser of the two
    [InlineData(3600, 900u, 900)]
    [InlineData(900, 3600u, 900)]
    [InlineData(1800, 1800u, 1800)]
    [InlineData(0, 900u, 0)]
    public void ANegativeAnswerTakesTheLesserOfTheSoaTtlAndItsMinimum(int soaTtl, uint minimum, int expected)
    {
        Assert.Equal(TimeSpan.FromSeconds(expected), DnsCacheTtl.NegativeTtl(new[] { Soa(soaTtl, minimum) }));
    }

    [Fact]
    public void AnAuthoritySectionWithNoSoaHasNoNegativeTtl()
    {
        // Referrals carry NS records rather than an SOA — nothing to read.
        Assert.Null(DnsCacheTtl.NegativeTtl(new[] { Record("a.example.", 3600) }));
        Assert.Null(DnsCacheTtl.NegativeTtl(Array.Empty<DnsResourceRecord>()));
    }

    [Fact]
    public void TheShortestSoaWins()
    {
        Assert.Equal(TimeSpan.FromSeconds(300),
            DnsCacheTtl.NegativeTtl(new DnsResourceRecord[] { Soa(3600, 900), Soa(3600, 300) }));
    }

    [Fact]
    public void ANegativeTtlIsClampedLikeAnyOtherPublishedTtl()
    {
        // The whole point of routing it through For(): an SOA minimum of 5 seconds is
        // still raised to the floor, and one of a week is still held to the cap.
        var floor = TimeSpan.FromSeconds(60);

        Assert.Equal(floor, DnsCacheTtl.For(DnsCacheTtl.NegativeTtl(new[] { Soa(3600, 5) }), floor, Cap));
        Assert.Equal(Cap, DnsCacheTtl.For(DnsCacheTtl.NegativeTtl(new[] { Soa(604800, 604800) }), floor, Cap));
    }

    [Fact]
    public void TheAnswerSectionIsPreferredOverTheAuthoritySection()
    {
        // A positive answer that happens to carry an SOA alongside it — the records
        // that answered the question are what governs.
        var answers = new[] { Record("a.example.", 120) };
        var authorities = new DnsResourceRecord[] { Soa(3600, 3600) };

        var ttl = DnsCacheTtl.MinRecordTtl(answers) ?? DnsCacheTtl.NegativeTtl(authorities);

        Assert.Equal(TimeSpan.FromSeconds(120), ttl);
    }

    [Fact]
    public async Task TheInitialTtlIsUsedSoAgeingDoesNotShortenTheEntry()
    {
        // DnsResourceRecord.TimeToLive counts down while DnsClient holds the record.
        // Reading that instead would shorten every entry by however long the response
        // sat around before it was cached — invisibly, and worse the busier the run.
        // The wait is what makes the two diverge; without it they are equal and the
        // test would pass either way.
        var record = Record("a.example.", 600);
        await Task.Delay(1200);
        Assert.True(record.TimeToLive < record.InitialTimeToLive,
            "the record did not age — this test can no longer tell the two apart");

        Assert.Equal(TimeSpan.FromSeconds(600), DnsCacheTtl.MinRecordTtl(new[] { record }));
    }
}
