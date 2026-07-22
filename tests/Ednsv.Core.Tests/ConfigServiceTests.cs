using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

public sealed class ConfigServiceTests : IDisposable
{
    private readonly string _dir;

    public ConfigServiceTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"ednsv-config-test-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private static AppConfig Seed() => new() { EnableSmtpProbes = true, KnownDomains = new() { "example.com" } };

    [Fact]
    public void SeedsBaselineRevisionOnFirstLoad()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(Seed());

        var revs = svc.ListRevisions();
        Assert.Single(revs);
        Assert.Equal("(initial)", revs[0].SavedBy);
    }

    [Fact]
    public void ReplaceRecordsRevisionWithUserNewestFirst()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(Seed());

        svc.Replace(new AppConfig { EnableSmtpProbes = false }, "alice@contoso.com");
        svc.Replace(new AppConfig { EnableHttpProbes = false }, "bob@contoso.com");

        var revs = svc.ListRevisions();
        Assert.Equal(3, revs.Count);                 // baseline + 2 changes
        Assert.Equal("bob@contoso.com", revs[0].SavedBy);   // newest first
        Assert.Equal("alice@contoso.com", revs[1].SavedBy);
        Assert.Equal("(initial)", revs[2].SavedBy);
        // Ids are strictly increasing in save order.
        Assert.True(revs[0].Id > revs[1].Id && revs[1].Id > revs[2].Id);
    }

    [Fact]
    public void GetRevisionReturnsThatConfig()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(Seed());
        svc.Replace(new AppConfig { EnableSmtpProbes = false, KnownDomains = new() { "changed.test" } }, "alice");

        var newest = svc.ListRevisions()[0];
        var cfg = svc.GetRevision(newest.Id);
        Assert.NotNull(cfg);
        Assert.False(cfg!.EnableSmtpProbes);
        Assert.Contains("changed.test", cfg.KnownDomains);

        Assert.Null(svc.GetRevision(999999));
    }

    [Fact]
    public void HistoryPersistsAcrossReload()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(Seed());
        svc.Replace(new AppConfig { EnableDnsbl = false }, "carol");

        // New instance over the same dir reads config-history.json back.
        var reloaded = new ConfigService(_dir);
        reloaded.LoadOrSeed(Seed());
        var revs = reloaded.ListRevisions();
        Assert.Equal(2, revs.Count);
        Assert.Equal("carol", revs[0].SavedBy);

        // Ids keep climbing — no collision with restored history.
        reloaded.Replace(new AppConfig(), "dave");
        var after = reloaded.ListRevisions();
        Assert.Equal("dave", after[0].SavedBy);
        Assert.True(after[0].Id > revs[0].Id);
    }

    [Fact]
    public void HistoryIsCappedAtMaxRevisions()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(Seed());

        for (var i = 0; i < ConfigService.MaxRevisions + 25; i++)
            svc.Replace(new AppConfig { DefaultDkimSelectors = new() { $"sel{i}" } }, $"user{i}");

        var revs = svc.ListRevisions();
        Assert.Equal(ConfigService.MaxRevisions, revs.Count);
        // Oldest (including the baseline) were trimmed; newest is retained.
        Assert.Equal($"user{ConfigService.MaxRevisions + 24}", revs[0].SavedBy);
    }
}
