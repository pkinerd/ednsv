using System.Text.Json;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The write queue behind the caches that keep their entries in a plain dictionary —
/// RCPT probes, relay tests, AXFR results, unreachable-server counts and domain
/// summaries. These used to be written out whole on every flush, which meant a flush
/// found something to write on every tick whether or not anything had changed.
///
/// <para>The two-phase collect/commit contract is what makes a flush safe without
/// holding a lock across the write, and it is pinned here rather than only through
/// <see cref="DiskCacheService"/>: injecting a mid-write I/O failure portably is not
/// possible, so the ordering guarantee is tested where it lives.</para>
/// </summary>
public sealed class WriteBagTests
{
    private static WriteBag<string> Bag(TimeSpan? ttl = null) => new(ttl ?? TimeSpan.FromHours(1));

    private static PendingWrites Collect(WriteBag<string> bag)
        => bag.Collect("test", v => JsonSerializer.SerializeToNode(v));

    [Fact]
    public void AnAddIsQueuedForTheNextFlush()
    {
        var bag = Bag();
        bag.Add("k", "v");

        var record = Assert.Single(Collect(bag).Records);
        Assert.Equal("test", record.Type);
        Assert.Equal("k", record.Key);
        Assert.Equal("v", record.Value?.GetValue<string>());
    }

    [Fact]
    public void AnEmptyBagCollectsNothing()
    {
        // This is what stops an idle process writing a file on every tick.
        Assert.Empty(Collect(Bag()).Records);
    }

    [Fact]
    public void CommittingDrainsTheBag()
    {
        var bag = Bag();
        bag.Add("k", "v");

        Collect(bag).Commit();

        Assert.Empty(Collect(bag).Records);
        Assert.Equal(0, bag.Count);
    }

    [Fact]
    public void CollectingWithoutCommittingLeavesTheEntryQueued()
    {
        // A failed write must not drop anything: nothing leaves the bag until the
        // file it went into has landed, so the next flush simply retries.
        var bag = Bag();
        bag.Add("k", "v");

        Assert.Single(Collect(bag).Records); // the flush that failed
        Assert.Single(Collect(bag).Records); // the next one still sees it
    }

    [Fact]
    public void AValueReplacedDuringAFlushSurvivesTheCommit()
    {
        // Reference-matched removal. Value equality here would let the flush delete
        // the newer entry that replaced the one it actually persisted, silently.
        var bag = Bag();
        bag.Add("k", "old");
        var inFlight = Collect(bag);

        bag.Add("k", "new");
        inFlight.Commit();

        var survivor = Assert.Single(Collect(bag).Records);
        Assert.Equal("new", survivor.Value?.GetValue<string>());
    }

    [Fact]
    public void AnIdenticalValueReplacedDuringAFlushAlsoSurvives()
    {
        // The same test with an equal value, which is where a record or a default
        // Equals would quietly do the wrong thing.
        var bag = Bag();
        bag.Add("k", "same");
        var inFlight = Collect(bag);

        bag.Add("k", "same");
        inFlight.Commit();

        Assert.Single(Collect(bag).Records);
    }

    [Fact]
    public void RemovingAKeyUnqueuesIt()
    {
        var bag = Bag();
        bag.Add("k", "v");

        bag.Remove("k");

        Assert.Empty(Collect(bag).Records);
    }

    [Fact]
    public void RemovingByPredicateUnqueuesTheMatches()
    {
        // Recheck invalidation: what was just dropped from the cache must not then
        // be written to disk as though it were current.
        var bag = Bag();
        bag.Add("drop:1", "a");
        bag.Add("keep:1", "b");

        bag.Remove(k => k.StartsWith("drop:"));

        var record = Assert.Single(Collect(bag).Records);
        Assert.Equal("keep:1", record.Key);
    }

    [Fact]
    public void EntriesCarryAnExpiryDerivedFromTheTtl()
    {
        var bag = Bag(TimeSpan.FromHours(2));
        var before = DateTime.UtcNow;
        bag.Add("k", "v");

        var record = Assert.Single(Collect(bag).Records);
        Assert.InRange(record.WrittenUtc, before.AddSeconds(-1), DateTime.UtcNow.AddSeconds(1));
        Assert.InRange(record.ExpiresUtc,
            before.AddHours(2).AddSeconds(-1), DateTime.UtcNow.AddHours(2).AddSeconds(1));
    }

    [Fact]
    public void WithoutATtlEntriesNeverExpireOnTheirOwn()
    {
        // The reader's configured TTL still bounds these — see
        // DiskCacheRecordFileTests.TheReadersTtlBoundsARecordThatCarriesNoExpiryOfItsOwn.
        var bag = new WriteBag<string>(null);
        bag.Add("k", "v");

        Assert.Equal(DateTime.MaxValue, Assert.Single(Collect(bag).Records).ExpiresUtc);
    }

    [Fact]
    public void AValueTheSerialiserRejectsStaysQueuedRatherThanBeingLost()
    {
        // Alongside one that serialises fine, so the flush really does write and
        // commit — the rejected entry has to survive that commit, not merely survive
        // a flush that turned out to have nothing to write.
        var bag = Bag();
        bag.Add("good", "v");
        bag.Add("bad", "explode");

        var pending = bag.Collect("test",
            v => v == "explode" ? throw new InvalidOperationException("nope") : JsonSerializer.SerializeToNode(v));
        Assert.Equal("good", Assert.Single(pending.Records).Key);
        pending.Commit();

        Assert.Equal("bad", Assert.Single(Collect(bag).Records).Key);
    }
}
