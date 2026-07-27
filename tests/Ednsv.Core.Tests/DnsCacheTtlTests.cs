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
    public void AnEmptyAnswerSectionFallsBackToTheFloor(int floor)
    {
        // NXDOMAIN and NODATA are real responses, they are cached, and their answer
        // sections are always empty — so this is a routine path, not an edge case.
        // "No TTL, cache forever" and "zero, never cache" are both wrong here.
        var ttl = DnsCacheTtl.For(null, TimeSpan.FromSeconds(floor), Cap);

        Assert.Equal(TimeSpan.FromSeconds(floor), ttl);
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
