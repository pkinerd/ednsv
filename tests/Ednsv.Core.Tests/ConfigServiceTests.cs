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

    // Regression: revisions saved BEFORE the history-storage split (bodies were
    // embedded inline in config-history.json, no per-revision files) used to 404
    // on load because GetRevision only looked for config-rev-{id}.json. LoadHistory
    // now migrates inline bodies to their own files on load.
    [Fact]
    public void LegacyInlineHistoryIsMigratedAndLoadable()
    {
        Directory.CreateDirectory(_dir);
        // Legacy single-file format: metadata AND full config body inline, no
        // config-history/ directory, no per-revision files.
        var legacy = """
        {
          "nextId": 3,
          "revisions": [
            { "id": 1, "savedAt": "2026-07-01T00:00:00Z", "savedBy": "(initial)",
              "config": { "enableSmtpProbes": true, "knownDomains": ["legacy-one.test"] } },
            { "id": 2, "savedAt": "2026-07-02T00:00:00Z", "savedBy": "alice",
              "config": { "enableSmtpProbes": false, "knownDomains": ["legacy-two.test"] } }
          ]
        }
        """;
        File.WriteAllText(Path.Combine(_dir, "config-history.json"), legacy);

        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(Seed());

        // Both legacy revisions are listed AND their bodies load (no 404).
        var revs = svc.ListRevisions();
        Assert.Equal(2, revs.Count);

        var rev1 = svc.GetRevision(1);
        Assert.NotNull(rev1);
        Assert.Contains("legacy-one.test", rev1!.KnownDomains);

        var rev2 = svc.GetRevision(2);
        Assert.NotNull(rev2);
        Assert.False(rev2!.EnableSmtpProbes);
        Assert.Contains("legacy-two.test", rev2.KnownDomains);

        // Migration wrote per-revision body files and collapsed the index to the
        // body-less format (so it doesn't re-migrate every load).
        Assert.True(File.Exists(Path.Combine(_dir, "config-history", "config-rev-1.json")));
        Assert.True(File.Exists(Path.Combine(_dir, "config-history", "config-rev-2.json")));
        var rewritten = File.ReadAllText(Path.Combine(_dir, "config-history.json"));
        Assert.DoesNotContain("\"config\"", rewritten);

        // A fresh instance over the migrated dir still loads the revisions.
        var reloaded = new ConfigService(_dir);
        reloaded.LoadOrSeed(Seed());
        Assert.NotNull(reloaded.GetRevision(1));
        Assert.NotNull(reloaded.GetRevision(2));
    }
}
