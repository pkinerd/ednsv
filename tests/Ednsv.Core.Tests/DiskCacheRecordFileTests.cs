using System.Globalization;
using System.Text.Json;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The file-per-flush model: each flush writes one immutable JSONL file into this
/// instance's folder, holding only what has been fetched since the last one, and a
/// load merges every instance's files with the later fetch winning per key.
///
/// <para>Domain results stand in for "a cache with something queued" throughout,
/// because they are the one bag that can be filled without touching the network.
/// Everything under test — the dirty-flag behaviour, the drain, the merge, the sweep
/// — is in <see cref="DiskCacheService"/> and shared by every cache type.</para>
/// </summary>
public sealed class DiskCacheRecordFileTests : IDisposable
{
    private readonly string _dir;

    public DiskCacheRecordFileTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"ednsv-records-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private SmtpProbeService _smtp = new();
    private HttpProbeService _http = new();
    private DnsResolverService _dns = new();

    private Task SaveAsync(DomainResultStore? store = null)
        => DiskCacheService.SaveAsync(_dir, _smtp, _http, _dns, store);

    private async Task<(DiskCacheService.CacheLoadResult? result, DomainResultStore store)> LoadAsync(
        TimeSpan? ttl = null, bool retryErrors = false)
    {
        var store = new DomainResultStore(TimeSpan.FromHours(24));
        // Fresh services, so anything asserted afterwards came off disk.
        _smtp = new SmtpProbeService();
        _http = new HttpProbeService();
        _dns = new DnsResolverService();
        var result = await DiskCacheService.LoadAsync(_dir, ttl ?? TimeSpan.FromHours(24),
            _smtp, _http, _dns, retryErrors, store);
        return (result, store);
    }

    private string[] RecordFiles() => Directory.GetFiles(_dir, "*.jsonl", SearchOption.AllDirectories);

    private static DomainResultStore StoreWith(params string[] domains)
    {
        var store = new DomainResultStore(TimeSpan.FromHours(24));
        foreach (var d in domains)
            store.Set(d, new DomainResultSummary { ValidatedAtUtc = DateTime.UtcNow, PassCount = 1 });
        return store;
    }

    /// <summary>Writes a record file into a named folder as if another instance had
    /// flushed it, with a filename timestamp of <paramref name="writtenUtc"/>.</summary>
    private string WriteForeignFile(string instance, DateTime writtenUtc, params CacheRecord[] records)
    {
        var dir = Path.Combine(_dir, instance);
        Directory.CreateDirectory(dir);
        var name = $"cache.{writtenUtc.ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture)}"
                   + $".{Guid.NewGuid().ToString("N")[..8]}.jsonl";
        var path = Path.Combine(dir, name);
        File.WriteAllLines(path, records.Select(r => JsonSerializer.Serialize(r)));
        return path;
    }

    private static CacheRecord DomainRecord(string domain, DateTime writtenUtc, DateTime expiresUtc, int passCount)
        => new()
        {
            Type = CacheTypes.DomainResults,
            Key = domain,
            WrittenUtc = writtenUtc,
            ExpiresUtc = expiresUtc,
            Value = JsonSerializer.SerializeToNode(
                new DomainResultSummary { ValidatedAtUtc = writtenUtc, PassCount = passCount })
        };

    // ── Writing ──────────────────────────────────────────────────────────

    [Fact]
    public async Task NothingQueuedWritesNoFile()
    {
        // The bags are the dirty flag. An idle process must not create a file per
        // tick — that was the whole cost of the previous model.
        await SaveAsync(new DomainResultStore(TimeSpan.FromHours(24)));

        Assert.Empty(RecordFiles());
    }

    [Fact]
    public async Task AFlushWritesOneFileIntoThisInstancesFolder()
    {
        await SaveAsync(StoreWith("a.example", "b.example"));

        var file = Assert.Single(RecordFiles());
        Assert.Equal(DiskCacheService.InstanceFolder(_dir), Path.GetDirectoryName(file));
        Assert.Equal(2, File.ReadAllLines(file).Length);
    }

    [Fact]
    public async Task EachFlushWritesANewFileAndNeverRewritesAnOldOne()
    {
        var store = StoreWith("first.example");
        await SaveAsync(store);
        var first = Assert.Single(RecordFiles());
        var firstContents = File.ReadAllText(first);

        store.Set("second.example", new DomainResultSummary { ValidatedAtUtc = DateTime.UtcNow });
        await SaveAsync(store);

        Assert.Equal(2, RecordFiles().Length);
        Assert.Equal(firstContents, File.ReadAllText(first));
    }

    [Fact]
    public async Task ASecondFlushWithNothingNewWritesNothing()
    {
        // The drain is what makes this true: the first flush emptied the bag, so
        // there is nothing left to re-serialise. This is the amplification fix.
        var store = StoreWith("only.example");
        await SaveAsync(store);
        await SaveAsync(store);

        Assert.Single(RecordFiles());
    }

    [Fact]
    public async Task AnEntryAddedDuringAFlushSurvivesTheDrain()
    {
        var store = StoreWith("written.example");
        var pending = store.CollectPending();          // what the flush is about to write
        store.Set("arrived-meanwhile.example",         // lands while the write is in flight
            new DomainResultSummary { ValidatedAtUtc = DateTime.UtcNow });
        pending.Commit();                              // drains only what was collected

        await SaveAsync(store);

        var lines = File.ReadAllLines(Assert.Single(RecordFiles()));
        var line = Assert.Single(lines);
        Assert.Contains("arrived-meanwhile.example", line);
    }

    [Fact]
    public async Task AFlushThatThrowsLeavesTheBagIntactForTheNextOne()
    {
        // A file where the instance folder should be: CreateDirectory throws, so the
        // write never happens and nothing may be committed. The ordering guarantee
        // itself — commit strictly after the file lands — is pinned in WriteBagTests,
        // since a mid-write I/O failure cannot be injected portably.
        var folder = DiskCacheService.InstanceFolder(_dir);
        File.WriteAllText(folder, "in the way");

        var store = StoreWith("retry.example");
        await Assert.ThrowsAnyAsync<IOException>(() => SaveAsync(store));

        File.Delete(folder);
        await SaveAsync(store);

        var line = Assert.Single(File.ReadAllLines(Assert.Single(RecordFiles())));
        Assert.Contains("retry.example", line);
    }

    [Fact]
    public async Task AFlushRecreatesItsFolderIfSomethingRemovedIt()
    {
        // The sweep removes an empty folder belonging to an instance idle longer than
        // the TTL, and that instance can be this one, still running. Every flush must
        // therefore create the folder, not just the first.
        await SaveAsync(StoreWith("first.example"));
        Directory.Delete(DiskCacheService.InstanceFolder(_dir), recursive: true);

        await SaveAsync(StoreWith("second.example"));

        Assert.Single(RecordFiles());
    }

    // ── Reading and merging ──────────────────────────────────────────────

    [Fact]
    public async Task DomainResultsRoundTripThroughTheBag()
    {
        await SaveAsync(StoreWith("round.example"));

        var (_, store) = await LoadAsync();

        Assert.True(store.TryGet("round.example", out var summary));
        Assert.Equal(1, summary.PassCount);
    }

    [Fact]
    public async Task FilesFromEveryInstanceAreMerged()
    {
        var now = DateTime.UtcNow;
        WriteForeignFile("poda", now, DomainRecord("a.example", now, now.AddHours(1), 1));
        WriteForeignFile("podb", now, DomainRecord("b.example", now, now.AddHours(1), 1));

        var (_, store) = await LoadAsync();

        Assert.Contains("a.example", store.Results.Keys);
        Assert.Contains("b.example", store.Results.Keys);
    }

    [Fact]
    public async Task TheLaterFetchWinsRegardlessOfWhichFileItIsIn()
    {
        var now = DateTime.UtcNow;
        // The newer entry is deliberately in the file written *earlier*, so only the
        // per-record timestamp can order them — a filename or mtime comparison would
        // pick the wrong one.
        WriteForeignFile("poda", now.AddMinutes(-30),
            DomainRecord("same.example", now, now.AddHours(1), passCount: 99));
        WriteForeignFile("podb", now.AddMinutes(-5),
            DomainRecord("same.example", now.AddMinutes(-20), now.AddHours(1), passCount: 1));

        var (_, store) = await LoadAsync();

        Assert.True(store.TryGet("same.example", out var summary));
        Assert.Equal(99, summary.PassCount);
    }

    [Fact]
    public async Task AnExpiredRecordIsDropped()
    {
        var now = DateTime.UtcNow;
        WriteForeignFile("poda", now,
            DomainRecord("live.example", now, now.AddHours(1), 1),
            DomainRecord("dead.example", now, now.AddMinutes(-1), 1));

        var (_, store) = await LoadAsync();

        Assert.Contains("live.example", store.Results.Keys);
        Assert.DoesNotContain("dead.example", store.Results.Keys);
    }

    [Fact]
    public async Task TheReadersTtlBoundsARecordThatCarriesNoExpiryOfItsOwn()
    {
        // A process running without a TTL stamps DateTime.MaxValue. The reader's
        // configured cap still has to bound how stale a value it will accept.
        var now = DateTime.UtcNow;
        WriteForeignFile("poda", now,
            DomainRecord("ancient.example", now.AddHours(-10), DateTime.MaxValue, 1));

        var (_, store) = await LoadAsync(ttl: TimeSpan.FromHours(2));

        Assert.DoesNotContain("ancient.example", store.Results.Keys);
    }

    [Fact]
    public async Task AnUnparseableLineIsSkippedAndTheRestOfTheFileLoads()
    {
        var now = DateTime.UtcNow;
        var path = WriteForeignFile("poda", now, DomainRecord("good.example", now, now.AddHours(1), 1));
        File.AppendAllLines(path, new[] { "{ not json", "", "{\"t\":\"nope\"}" });

        var (_, store) = await LoadAsync();

        Assert.Contains("good.example", store.Results.Keys);
    }

    [Fact]
    public async Task ARecordOfAnUnknownTypeIsIgnored()
    {
        var now = DateTime.UtcNow;
        WriteForeignFile("poda", now,
            new CacheRecord
            {
                Type = "invented-by-a-later-version", Key = "k",
                WrittenUtc = now, ExpiresUtc = now.AddHours(1),
                Value = JsonSerializer.SerializeToNode("payload")
            },
            DomainRecord("known.example", now, now.AddHours(1), 1));

        var (result, store) = await LoadAsync();

        Assert.Contains("known.example", store.Results.Keys);
        Assert.Equal(0, result?.Total ?? 0); // domain results are loaded but not counted
    }

    [Fact]
    public async Task PtrRecordsAreImportedAndCounted()
    {
        // Covers the dispatch to a service other than the domain-result store, and
        // that keys are written and read back verbatim with no translation step.
        var now = DateTime.UtcNow;
        WriteForeignFile("poda", now, new CacheRecord
        {
            Type = CacheTypes.Ptr, Key = "ptr:8.8.8.8",
            WrittenUtc = now, ExpiresUtc = now.AddHours(1),
            Value = JsonSerializer.SerializeToNode(new List<string> { "dns.google." })
        });

        var (result, _) = await LoadAsync();

        Assert.Equal(1, result?.PtrLookups);
    }

    [Fact]
    public async Task ImportedEntriesInThePlainDictionaryCachesAreNotWrittenBack()
    {
        // RCPT probes, relay tests, AXFR results and unreachable counts live in plain
        // dictionaries rather than ProbeCaches. They used to be serialised whole on
        // every flush, so everything read at startup was rewritten for the life of
        // the process — and a flush always had something to write, defeating the
        // dirty flag. They carry their own write queues now, and an import does not
        // touch them.
        var now = DateTime.UtcNow;
        WriteForeignFile("poda", now,
            new CacheRecord
            {
                Type = CacheTypes.Rcpt, Key = "mx.example|user@example.com",
                WrittenUtc = now, ExpiresUtc = now.AddHours(1),
                Value = JsonSerializer.SerializeToNode(
                    new RcptCacheEntry { Accepted = true, Response = "250 OK" })
            },
            new CacheRecord
            {
                Type = CacheTypes.Axfr, Key = "192.0.2.1|example.com",
                WrittenUtc = now, ExpiresUtc = now.AddHours(1),
                Value = JsonSerializer.SerializeToNode(false)
            });

        var (result, _) = await LoadAsync();
        Assert.Equal(1, result?.RcptProbes);

        var before = RecordFiles().Length;
        await SaveAsync();

        Assert.Equal(before, RecordFiles().Length);
    }

    // ── Sweep ────────────────────────────────────────────────────────────

    [Fact]
    public void SweepDeletesRecordFilesByTheirFilenameTimestamp()
    {
        var now = DateTime.UtcNow;
        var stale = WriteForeignFile("deadpod", now.AddHours(-48));
        var live = WriteForeignFile("livepod", now.AddMinutes(-5));

        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));

        Assert.False(File.Exists(stale), "a file older than the TTL should be swept");
        Assert.True(File.Exists(live));
    }

    [Fact]
    public async Task SweepAppliesToThisInstancesOwnFilesToo()
    {
        // There is no file being appended to, so nothing needs exempting — the rule
        // is uniform across every folder including our own.
        await SaveAsync(StoreWith("mine.example"));
        var own = Assert.Single(RecordFiles());
        var aged = Path.Combine(Path.GetDirectoryName(own)!,
            $"cache.{DateTime.UtcNow.AddHours(-48):yyyyMMdd'T'HHmmssfff}Z.deadbeef.jsonl");
        File.Move(own, aged);

        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));

        Assert.Empty(RecordFiles());
    }

    [Fact]
    public void SweepRemovesAnEmptyForeignFolderOnceItHasAgedPastTheTtl()
    {
        var stale = WriteForeignFile("deadpod", DateTime.UtcNow.AddHours(-48));
        var folder = Path.GetDirectoryName(stale)!;

        // First pass takes the file. Removing it refreshes the folder's mtime, so the
        // folder itself is not yet eligible — a dead instance's folder lingers for
        // roughly twice the TTL, which is deliberate slack.
        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));
        Assert.True(Directory.Exists(folder), "the folder should survive the sweep that emptied it");

        Directory.SetLastWriteTimeUtc(folder, DateTime.UtcNow.AddHours(-48));
        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));

        Assert.False(Directory.Exists(folder));
    }

    [Fact]
    public void SweepNeverRemovesThisInstancesOwnFolderEvenWhenEmptyAndOld()
    {
        var own = DiskCacheService.InstanceFolder(_dir);
        Directory.CreateDirectory(own);
        Directory.SetLastWriteTimeUtc(own, DateTime.UtcNow.AddDays(-30));

        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));

        Assert.True(Directory.Exists(own));
    }

    [Fact]
    public void SweepLeavesAFolderThatStillHasLiveFiles()
    {
        var live = WriteForeignFile("livepod", DateTime.UtcNow.AddMinutes(-5));
        var folder = Path.GetDirectoryName(live)!;
        Directory.SetLastWriteTimeUtc(folder, DateTime.UtcNow.AddDays(-30));

        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));

        Assert.True(Directory.Exists(folder));
        Assert.True(File.Exists(live));
    }

    [Fact]
    public void SweepLeavesFilesItDidNotWrite()
    {
        // The cache directory is configurable. Deleting by a "*.json" glob would take
        // an operator's unrelated files with it — and config.json and users.json if
        // it were ever pointed at the data directory itself.
        var stranger = Path.Combine(_dir, "config.json");
        File.WriteAllText(stranger, "{}");
        File.SetLastWriteTimeUtc(stranger, DateTime.UtcNow.AddDays(-365));

        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));

        Assert.True(File.Exists(stranger));
    }

    [Fact]
    public void SweepDeletesNothingWhenTheTtlIsZero()
    {
        var stale = WriteForeignFile("deadpod", DateTime.UtcNow.AddDays(-365));

        DiskCacheService.Sweep(_dir, TimeSpan.Zero);

        Assert.True(File.Exists(stale));
    }

    [Fact]
    public void SweepRemovesStaleTempsLeftByAKilledWriter()
    {
        var dir = Path.Combine(_dir, "deadpod");
        Directory.CreateDirectory(dir);
        var orphan = Path.Combine(dir, "cache.20260101T000000000Z.abcdef12.jsonl.deadbeef.tmp");
        File.WriteAllText(orphan, "half a flush");
        File.SetLastWriteTimeUtc(orphan, DateTime.UtcNow.AddHours(-2));

        var fresh = Path.Combine(dir, "cache.20260101T000000000Z.abcdef13.jsonl.cafebabe.tmp");
        File.WriteAllText(fresh, "a write happening right now");

        DiskCacheService.Sweep(_dir, TimeSpan.FromHours(24));

        Assert.False(File.Exists(orphan));
        Assert.True(File.Exists(fresh), "a temp from a write in flight must not be deleted");
    }
}
