using System.Text.Json;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Each process writes its own copy of every cache file and reads all of them
/// merged, so replicas sharing a DataDir stop read-modify-writing one file and
/// dropping each other's entries. These tests stand in for "another pod" by
/// writing files with a foreign instance suffix directly.
/// </summary>
public sealed class DiskCachePerInstanceTests : IDisposable
{
    private readonly string _dir;

    public DiskCachePerInstanceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"ednsv-perinst-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private string WriteDomainResults(string fileName, string domain, DateTime validatedAt)
    {
        var path = Path.Combine(_dir, fileName);
        var payload = new Dictionary<string, DomainResultSummary>
        {
            [domain] = new() { ValidatedAtUtc = validatedAt, PassCount = 1 }
        };
        File.WriteAllText(path, JsonSerializer.Serialize(payload, Json));
        return path;
    }

    [Fact]
    public async Task LoadDomainResults_MergesAcrossInstances()
    {
        WriteDomainResults("domain-results.poda.json", "a.example", DateTime.UtcNow);
        WriteDomainResults("domain-results.podb.json", "b.example", DateTime.UtcNow);

        var loaded = await DiskCacheService.LoadDomainResultsAsync(_dir);

        Assert.NotNull(loaded);
        Assert.Contains("a.example", loaded!.Keys);
        Assert.Contains("b.example", loaded.Keys);
    }

    [Fact]
    public async Task LoadDomainResults_NewestValidationWinsPerDomain()
    {
        var older = DateTime.UtcNow.AddHours(-2);
        var newer = DateTime.UtcNow;
        WriteDomainResults("domain-results.poda.json", "same.example", older);
        WriteDomainResults("domain-results.podb.json", "same.example", newer);

        var loaded = await DiskCacheService.LoadDomainResultsAsync(_dir);

        Assert.Equal(newer, loaded!["same.example"].ValidatedAtUtc, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task LoadDomainResults_StillReadsTheLegacySharedFile()
    {
        // Written by a version from before the per-instance split.
        WriteDomainResults("domain-results.json", "legacy.example", DateTime.UtcNow);

        var loaded = await DiskCacheService.LoadDomainResultsAsync(_dir);

        Assert.Contains("legacy.example", loaded!.Keys);
    }

    [Fact]
    public async Task LoadDomainResults_SkipsAnUnreadableVariantInsteadOfFailing()
    {
        WriteDomainResults("domain-results.poda.json", "good.example", DateTime.UtcNow);
        File.WriteAllText(Path.Combine(_dir, "domain-results.podb.json"), "not json {{{");

        var loaded = await DiskCacheService.LoadDomainResultsAsync(_dir);

        Assert.Contains("good.example", loaded!.Keys);
    }

    [Fact]
    public async Task SaveDomainResult_WritesOnlyThisInstancesFile()
    {
        var foreign = WriteDomainResults("domain-results.otherpod.json", "other.example", DateTime.UtcNow);
        var foreignBefore = File.ReadAllText(foreign);

        await DiskCacheService.SaveDomainResultAsync(_dir, "mine.example",
            new DomainResultSummary { ValidatedAtUtc = DateTime.UtcNow, PassCount = 2 });

        // The other instance's file is untouched — no cross-pod read-modify-write.
        Assert.Equal(foreignBefore, File.ReadAllText(foreign));

        // And both are visible on load.
        var loaded = await DiskCacheService.LoadDomainResultsAsync(_dir);
        Assert.Contains("other.example", loaded!.Keys);
        Assert.Contains("mine.example", loaded.Keys);
    }

    [Fact]
    public async Task LoadAsync_SweepsFilesFromInstancesThatAreGone()
    {
        var stale = WriteDomainResults("domain-results.deadpod.json", "stale.example", DateTime.UtcNow);
        var live = WriteDomainResults("domain-results.livepod.json", "live.example", DateTime.UtcNow);
        File.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddHours(-48)); // every entry long expired

        await DiskCacheService.LoadAsync(_dir, TimeSpan.FromHours(24),
            new SmtpProbeService(), new HttpProbeService(), new DnsResolverService());

        Assert.False(File.Exists(stale), "a dead instance's expired file should be swept");
        Assert.True(File.Exists(live), "a recently written file must be kept");
    }

    [Fact]
    public async Task LoadAsync_SweepsTheLegacySharedFileOnceItHasAgedOut()
    {
        var legacy = WriteDomainResults("domain-results.json", "legacy.example", DateTime.UtcNow);
        File.SetLastWriteTimeUtc(legacy, DateTime.UtcNow.AddHours(-48));

        await DiskCacheService.LoadAsync(_dir, TimeSpan.FromHours(24),
            new SmtpProbeService(), new HttpProbeService(), new DnsResolverService());

        Assert.False(File.Exists(legacy));
    }

    [Fact]
    public void Clear_RemovesEveryInstancesFiles()
    {
        WriteDomainResults("domain-results.poda1.json", "a.example", DateTime.UtcNow);
        WriteDomainResults("domain-results.podb.json", "b.example", DateTime.UtcNow);
        WriteDomainResults("domain-results.json", "legacy.example", DateTime.UtcNow);
        File.WriteAllText(Path.Combine(_dir, "dns-queries.podc.json"), "{}");
        File.WriteAllText(Path.Combine(_dir, "unrelated.json"), "keep me");

        DiskCacheService.Clear(_dir);

        Assert.Empty(Directory.GetFiles(_dir, "domain-results*.json"));
        Assert.Empty(Directory.GetFiles(_dir, "dns-queries*.json"));
        Assert.True(File.Exists(Path.Combine(_dir, "unrelated.json")));
    }

    [Fact]
    public async Task VariantMatching_RequiresADotAfterTheCacheTypeName()
    {
        // A variant is "{type}.{instance}.json" and nothing else. Prefix-only
        // matching would make "http-get" swallow "http-get-headers" — two types
        // with different entry shapes — so the separator is load-bearing.
        WriteDomainResults("domain-results.poda.json", "real.example", DateTime.UtcNow);
        WriteDomainResults("domain-results-decoy.podb.json", "decoy.example", DateTime.UtcNow);

        var loaded = await DiskCacheService.LoadDomainResultsAsync(_dir);

        Assert.Contains("real.example", loaded!.Keys);
        Assert.DoesNotContain("decoy.example", loaded.Keys);
    }
}
