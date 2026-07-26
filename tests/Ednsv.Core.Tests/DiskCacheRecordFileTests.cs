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
    /// flushed it, with a filename timestamp of <paramref name="writtenUtc"/>. Note
    /// that the sweep deletes by that timestamp, so a test wanting its file read back
    /// must date it inside the TTL.</summary>
    private string WriteForeignFile(string instance, DateTime writtenUtc, params CacheRecord[] records)
        => WriteRawFile(instance, writtenUtc, records.Select(r => JsonSerializer.Serialize(r)).ToArray());

    /// <summary>As <see cref="WriteForeignFile"/>, but with the lines written
    /// verbatim — for exercising the envelope scanner against JSON this codebase
    /// would not itself produce.</summary>
    private string WriteRawFile(string instance, DateTime writtenUtc, params string[] lines)
        => WriteRawFile(instance, writtenUtc, string.Concat(lines.Select(l => l + "\n")));

    private string WriteRawFile(string instance, DateTime writtenUtc, string contents)
    {
        var dir = Path.Combine(_dir, instance);
        Directory.CreateDirectory(dir);
        var name = $"cache.{writtenUtc.ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture)}"
                   + $".{Guid.NewGuid().ToString("N")[..8]}.jsonl";
        var path = Path.Combine(dir, name);
        File.WriteAllText(path, contents);
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

        Assert.True(store.TryGet("a.example", out _));
        Assert.True(store.TryGet("b.example", out _));
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

        Assert.True(store.TryGet("live.example", out _));
        Assert.False(store.TryGet("dead.example", out _));
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

        Assert.False(store.TryGet("ancient.example", out _));
    }

    [Fact]
    public async Task AnUnparseableLineIsSkippedAndTheRestOfTheFileLoads()
    {
        // Bad lines on both sides of the good one, so a reader that gave up on the
        // first failure could not pass this by accident.
        var now = DateTime.UtcNow;
        WriteRawFile("poda", now,
            "{ not json",
            "",
            JsonSerializer.Serialize(DomainRecord("good.example", now, now.AddHours(1), 1)),
            "{\"t\":\"nope\"}",
            "  binary noise");

        var (_, store) = await LoadAsync();

        Assert.True(store.TryGet("good.example", out _));
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

        Assert.True(store.TryGet("known.example", out _));
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

    // ── The envelope scan ────────────────────────────────────────────────
    //
    // Lines are scanned for t/k/w/e with a Utf8JsonReader that skips the payload, so
    // the expensive typed deserialisation only ever runs for keys that survive the
    // merge. The scanner has to stay in sync with the reader across whatever the
    // payload happens to contain, which is what these pin.

    [Fact]
    public async Task TheEnvelopeIsFoundWhateverOrderTheFieldsAreIn()
    {
        // The payload is skipped rather than parsed, so a nested object before the
        // fields we want must not throw the reader off — a Skip that mis-counted
        // depth would lose every field after v.
        var now = DateTime.UtcNow;
        var summary = JsonSerializer.Serialize(new DomainResultSummary { ValidatedAtUtc = now, PassCount = 7 });
        var line = "{\"v\":" + summary + ",\"t\":\"" + CacheTypes.DomainResults + "\",\"k\":\"ordered.example\""
                   + ",\"w\":\"" + now.ToString("O") + "\",\"e\":\"" + now.AddHours(1).ToString("O") + "\"}";
        WriteRawFile("poda", now, line);

        var (_, store) = await LoadAsync();

        Assert.True(store.TryGet("ordered.example", out var got));
        Assert.Equal(7, got.PassCount);
    }

    [Fact]
    public async Task FieldsAddedByALaterVersionAreSkippedRatherThanFailingTheLine()
    {
        // The unknown fields come first, so a skip that lost track of nesting depth
        // would take the fields we actually need down with them.
        var now = DateTime.UtcNow;
        var summary = JsonSerializer.Serialize(new DomainResultSummary { ValidatedAtUtc = now, PassCount = 3 });
        var line = "{\"x\":[1,2,{\"y\":[3,{\"z\":null}]}],\"q\":\"trailing\""
                   + ",\"t\":\"" + CacheTypes.DomainResults + "\",\"k\":\"future.example\""
                   + ",\"w\":\"" + now.ToString("O") + "\",\"e\":\"" + now.AddHours(1).ToString("O") + "\""
                   + ",\"v\":" + summary + "}";
        WriteRawFile("poda", now, line);

        var (_, store) = await LoadAsync();

        Assert.True(store.TryGet("future.example", out var got));
        Assert.Equal(3, got.PassCount);
    }

    [Fact]
    public async Task CrlfLineEndingsAreRead()
    {
        var now = DateTime.UtcNow;
        var records = new[]
        {
            DomainRecord("a.example", now, now.AddHours(1), 1),
            DomainRecord("b.example", now, now.AddHours(1), 1)
        };
        WriteRawFile("poda", now,
            string.Join("\r\n", records.Select(r => JsonSerializer.Serialize(r))) + "\r\n");

        var (_, store) = await LoadAsync();

        Assert.True(store.TryGet("a.example", out _));
        Assert.True(store.TryGet("b.example", out _));
    }

    [Fact]
    public async Task ALineMissingItsTypeOrKeyIsSkipped()
    {
        var now = DateTime.UtcNow;
        var path = WriteForeignFile("poda", now, DomainRecord("good.example", now, now.AddHours(1), 1));
        File.AppendAllLines(path, new[]
        {
            "{\"k\":\"no-type\",\"w\":\"" + now.ToString("O") + "\",\"e\":\"" + now.AddHours(1).ToString("O") + "\",\"v\":1}",
            "{\"t\":\"dns\",\"w\":\"" + now.ToString("O") + "\",\"e\":\"" + now.AddHours(1).ToString("O") + "\",\"v\":1}"
        });

        var (result, store) = await LoadAsync();

        Assert.True(store.TryGet("good.example", out _));
        Assert.Equal(0, result?.DnsQueries ?? 0);
    }

    [Fact]
    public async Task ARecordFileBeatsALegacyFileForTheSameKey()
    {
        // Every import is add-if-absent and record files are read first, so the
        // frozen legacy copy cannot win over one written since the upgrade.
        var now = DateTime.UtcNow;
        WriteForeignFile("poda", now, DomainRecord("both.example", now, now.AddHours(1), passCount: 42));
        File.WriteAllText(Path.Combine(_dir, "domain-results.podb.json"),
            JsonSerializer.Serialize(
                new Dictionary<string, DomainResultSummary>
                {
                    ["both.example"] = new() { ValidatedAtUtc = now, PassCount = 1 }
                },
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));

        var (_, store) = await LoadAsync();

        Assert.True(store.TryGet("both.example", out var got));
        Assert.Equal(42, got.PassCount);
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
    public void AZeroTtlKeepsFilesInsideTheRetentionFloor()
    {
        // Zero means "no expiry", not "everything expired" — taking it literally would
        // put the cutoff at now and delete the whole cache on the first sweep.
        var recent = WriteForeignFile("livepod", DateTime.UtcNow.AddHours(-1));

        DiskCacheService.Sweep(_dir, TimeSpan.Zero);

        Assert.True(File.Exists(recent));
    }

    [Fact]
    public void AZeroTtlStillSweepsAtTheRetentionFloor()
    {
        // ...and it does not mean "never sweep" either. Memory is keyed, so a refetch
        // replaces its entry and the working set stays flat. Disk is append-only: the
        // same key fetched again lands in a *later* file rather than replacing
        // anything, and every recheck and every instance adds more. The sweep is the
        // only thing that removes them, so switching it off grows the directory
        // without bound.
        var inside = WriteForeignFile("livepod",
            DateTime.UtcNow - DiskCacheService.UncappedRetention + TimeSpan.FromHours(1));
        var beyond = WriteForeignFile("deadpod",
            DateTime.UtcNow - DiskCacheService.UncappedRetention - TimeSpan.FromHours(1));

        DiskCacheService.Sweep(_dir, TimeSpan.Zero);

        Assert.True(File.Exists(inside), "a file inside the floor should be kept");
        Assert.False(File.Exists(beyond), "a file past the floor should be swept");
    }

    [Fact]
    public async Task AZeroTtlBoundsHowManyFilesAccumulate()
    {
        // The end-to-end shape of the same thing: flush repeatedly with expiry off,
        // back-date the files as an instance running for days would, and check the
        // directory does not simply keep everything.
        for (var i = 0; i < 5; i++)
            await SaveAsync(StoreWith($"d{i}.example"));

        var files = RecordFiles();
        Assert.Equal(5, files.Length);

        // Age three of them past the floor, as they would be after a couple of days.
        foreach (var path in files.Take(3))
        {
            var aged = Path.Combine(Path.GetDirectoryName(path)!,
                $"cache.{DateTime.UtcNow - DiskCacheService.UncappedRetention - TimeSpan.FromHours(1):yyyyMMdd'T'HHmmssfff}Z"
                + $".{Guid.NewGuid().ToString("N")[..8]}.jsonl");
            File.Move(path, aged);
        }

        DiskCacheService.Sweep(_dir, TimeSpan.Zero);

        Assert.Equal(2, RecordFiles().Length);
    }

    // ── The flusher's sweep ──────────────────────────────────────────────
    //
    // The load sweeps once, at startup. After that the flush timer is the only thing
    // that ever removes a file, so a long-running instance depends entirely on it.

    private async Task RunFlusherUntilAsync(TimeSpan ttl, Func<bool> done, DomainResultStore? store = null)
    {
        var flusher = new BackgroundCacheFlusher(_dir, _smtp, _http, _dns,
            TimeSpan.FromMilliseconds(50), ttl, store);
        try
        {
            for (var i = 0; i < 100 && !done(); i++) await Task.Delay(50);
        }
        finally
        {
            await flusher.DisposeAsync();
        }
    }

    [Fact]
    public async Task TheFlusherSweepsOnItsTimer()
    {
        var stale = WriteForeignFile("deadpod", DateTime.UtcNow.AddHours(-48));

        await RunFlusherUntilAsync(TimeSpan.FromHours(24), () => !File.Exists(stale),
            StoreWith("something.example"));

        Assert.False(File.Exists(stale));
    }

    [Fact]
    public async Task TheFlusherSweepsEvenWithNothingToWrite()
    {
        // The save returns early when no bag has anything queued. The sweep must not
        // ride on that: an instance that has gone quiet still has to clear out the
        // files it wrote earlier, and the folders of instances that have gone.
        var stale = WriteForeignFile("deadpod", DateTime.UtcNow.AddHours(-48));

        await RunFlusherUntilAsync(TimeSpan.FromHours(24), () => !File.Exists(stale));

        Assert.False(File.Exists(stale));
        Assert.Empty(RecordFiles());
    }

    [Fact]
    public async Task TheFlusherStillSweepsWhenExpiryIsDisabled()
    {
        // The case this whole floor exists for: a long-running instance with
        // CacheTtlHours=0. Nothing else would ever delete a file between restarts,
        // and each flush appends another one.
        var stale = WriteForeignFile("deadpod",
            DateTime.UtcNow - DiskCacheService.UncappedRetention - TimeSpan.FromHours(1));
        var live = WriteForeignFile("livepod", DateTime.UtcNow.AddHours(-1));

        await RunFlusherUntilAsync(TimeSpan.Zero, () => !File.Exists(stale));

        Assert.False(File.Exists(stale), "expiry off must not mean the sweep is off");
        Assert.True(File.Exists(live), "a file inside the floor should survive");
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
