using System.Text.Json;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The one-file-per-cache-type layout is no longer written, but it is still read, so
/// upgrading does not throw away the cache the previous version left behind. These
/// tests write those files directly — including with a foreign instance suffix, to
/// stand in for another pod — and check they still load and still age out.
/// </summary>
public sealed class DiskCacheLegacyFormatTests : IDisposable
{
    private readonly string _dir;

    public DiskCacheLegacyFormatTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"ednsv-legacy-{Guid.NewGuid():N}");
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

    private async Task<DomainResultStore> LoadAsync(TimeSpan? ttl = null)
    {
        var store = new DomainResultStore(TimeSpan.FromHours(24));
        await DiskCacheService.LoadAsync(_dir, ttl ?? TimeSpan.FromHours(24),
            new SmtpProbeService(), new HttpProbeService(), new DnsResolverService(),
            retryErrors: false, domainResults: store);
        return store;
    }

    [Fact]
    public async Task DomainResults_MergeAcrossInstances()
    {
        WriteDomainResults("domain-results.poda.json", "a.example", DateTime.UtcNow);
        WriteDomainResults("domain-results.podb.json", "b.example", DateTime.UtcNow);

        var store = await LoadAsync();

        Assert.Contains("a.example", store.Results.Keys);
        Assert.Contains("b.example", store.Results.Keys);
    }

    [Fact]
    public async Task DomainResults_NewestValidationWinsPerDomain()
    {
        var older = DateTime.UtcNow.AddHours(-2);
        var newer = DateTime.UtcNow;
        WriteDomainResults("domain-results.poda.json", "same.example", older);
        WriteDomainResults("domain-results.podb.json", "same.example", newer);

        var store = await LoadAsync();

        Assert.Equal(newer, store.Results["same.example"].ValidatedAtUtc, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task DomainResults_StillReadTheLegacySharedFile()
    {
        // Written by a version from before the per-instance split.
        WriteDomainResults("domain-results.json", "legacy.example", DateTime.UtcNow);

        var store = await LoadAsync();

        Assert.Contains("legacy.example", store.Results.Keys);
    }

    [Fact]
    public async Task DomainResults_SkipAnUnreadableVariantInsteadOfFailing()
    {
        WriteDomainResults("domain-results.poda.json", "good.example", DateTime.UtcNow);
        File.WriteAllText(Path.Combine(_dir, "domain-results.podb.json"), "not json {{{");

        var store = await LoadAsync();

        Assert.Contains("good.example", store.Results.Keys);
    }

    [Fact]
    public async Task DomainResults_AreNowExpired()
    {
        // The old reader had no TTL filter at all, so recheck decisions could rest on
        // month-old records. Expiry is applied on the way in now.
        WriteDomainResults("domain-results.poda.json", "fresh.example", DateTime.UtcNow);
        WriteDomainResults("domain-results.podb.json", "ancient.example", DateTime.UtcNow.AddDays(-30));

        var store = await LoadAsync();

        Assert.Contains("fresh.example", store.Results.Keys);
        Assert.DoesNotContain("ancient.example", store.Results.Keys);
    }

    [Fact]
    public async Task VariantMatching_RequiresADotAfterTheCacheTypeName()
    {
        // A variant is "{type}.{instance}.json" and nothing else. Prefix-only
        // matching would make "http-get" swallow "http-get-headers" — two types
        // with different entry shapes — so the separator is load-bearing.
        WriteDomainResults("domain-results.poda.json", "real.example", DateTime.UtcNow);
        WriteDomainResults("domain-results-decoy.podb.json", "decoy.example", DateTime.UtcNow);

        var store = await LoadAsync();

        Assert.Contains("real.example", store.Results.Keys);
        Assert.DoesNotContain("decoy.example", store.Results.Keys);
    }

    [Fact]
    public async Task Sweep_DeletesLegacyFilesOnceTheyHaveAgedOut()
    {
        var stale = WriteDomainResults("domain-results.deadpod.json", "stale.example", DateTime.UtcNow);
        var legacy = WriteDomainResults("domain-results.json", "legacy.example", DateTime.UtcNow);
        var live = WriteDomainResults("domain-results.livepod.json", "live.example", DateTime.UtcNow);
        File.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddHours(-48)); // every entry long expired
        File.SetLastWriteTimeUtc(legacy, DateTime.UtcNow.AddHours(-48));

        await LoadAsync();

        Assert.False(File.Exists(stale), "a dead instance's expired file should be swept");
        Assert.False(File.Exists(legacy), "the pre-split shared file should be swept too");
        Assert.True(File.Exists(live), "a recently written file must be kept");
    }

    [Fact]
    public async Task Sweep_KeepsEverythingWhenTheTtlIsZero()
    {
        // Zero means "no expiry", not "everything expired". Treating the cutoff as
        // now would delete the whole cache on the first sweep.
        var legacy = WriteDomainResults("domain-results.json", "legacy.example", DateTime.UtcNow);
        File.SetLastWriteTimeUtc(legacy, DateTime.UtcNow.AddDays(-365));

        await LoadAsync(TimeSpan.Zero);

        Assert.True(File.Exists(legacy));
    }
}
