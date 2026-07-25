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

    // ── Guarding an existing config.json against the seed path ──────────────
    // LoadOrSeed's seed branch writes to disk. Treating an unreadable file as
    // "no config yet" would replace the operator's saved settings with env-var
    // defaults, so anything that exists and has content must abort startup instead.

    [Fact]
    public void LoadOrSeed_MalformedConfigThrowsAndLeavesFileIntact()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "config.json");
        const string original = "{ this is not valid json";
        File.WriteAllText(path, original);

        var svc = new ConfigService(_dir);
        Assert.Throws<ConfigUnreadableException>(() => svc.LoadOrSeed(Seed()));
        Assert.Equal(original, File.ReadAllText(path));
    }

    [Fact]
    public void LoadOrSeed_ConfigParsingToNullThrowsAndLeavesFileIntact()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "config.json");
        File.WriteAllText(path, "null");

        var svc = new ConfigService(_dir);
        Assert.Throws<ConfigUnreadableException>(() => svc.LoadOrSeed(Seed()));
        Assert.Equal("null", File.ReadAllText(path));
    }

    [Fact]
    public void LoadOrSeed_EmptyConfigStillSeeds()
    {
        // Nothing to lose in a zero-byte file, so this keeps the self-healing path.
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "config.json"), "   ");

        var svc = new ConfigService(_dir);
        var cfg = svc.LoadOrSeed(Seed());

        Assert.True(cfg.EnableSmtpProbes);
        Assert.Contains("example.com", cfg.KnownDomains);
    }

    [Fact]
    public void LoadOrSeed_ValidConfigIsPreferredOverSeed()
    {
        var first = new ConfigService(_dir);
        first.LoadOrSeed(Seed());
        first.Replace(new AppConfig { EnableSmtpProbes = false }, "alice@contoso.com");

        var reopened = new ConfigService(_dir);
        var cfg = reopened.LoadOrSeed(Seed());

        Assert.False(cfg.EnableSmtpProbes); // saved value wins, seed is ignored
    }

    [Fact]
    public void LoadOrSeed_SweepsStaleTempFiles()
    {
        Directory.CreateDirectory(_dir);
        var stale = Path.Combine(_dir, "config.json.deadbeef.tmp");
        File.WriteAllText(stale, "orphaned by a killed writer");
        File.SetLastWriteTimeUtc(stale, DateTime.UtcNow.AddHours(-2));

        new ConfigService(_dir).LoadOrSeed(Seed());

        Assert.False(File.Exists(stale));
    }

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

    // Regression: revisions saved BEFORE the history-storage split embedded their
    // body inline in config-history.json. Once the index was rewritten body-less
    // that inline body was gone, leaving metadata with no loadable body file — the
    // picker offered those revisions and loading them 404'd. ListRevisions now
    // filters to revisions whose body file actually exists.
    [Fact]
    public void RevisionsWithoutABodyFileAreNotListed()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(Seed());                                          // rev 1 (baseline)
        svc.Replace(new AppConfig { EnableDnsbl = false }, "alice");     // rev 2
        svc.Replace(new AppConfig { EnableHttpProbes = false }, "bob");  // rev 3

        var all = svc.ListRevisions();
        Assert.Equal(3, all.Count);

        // Orphan the oldest revision the way the pre-split → split upgrade did to
        // every legacy revision: metadata stays, body file is gone.
        var orphanId = all.Min(r => r.Id);
        File.Delete(Path.Combine(_dir, "config-history", $"config-rev-{orphanId}.json"));

        var listed = svc.ListRevisions();
        Assert.Equal(2, listed.Count);
        Assert.DoesNotContain(listed, r => r.Id == orphanId);
        // Every revision still listed has a body that loads (no 404 from the picker).
        foreach (var r in listed)
            Assert.NotNull(svc.GetRevision(r.Id));
    }
}
