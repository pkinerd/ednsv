using System.Net.Http.Headers;
using DnsClient;
using Ednsv.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Ednsv.Web.Tests;

/// <summary>
/// <c>CacheDir</c> is one path-shaped knob rather than a path plus a boolean: it
/// points the disk tier somewhere, or it is the string "none" and there is no disk
/// tier at all.
/// </summary>
public sealed class CacheDirSettingTests
{
    private static async Task<bool> SeedACacheableFetchAsync(EdnsvAppFactory factory)
    {
        var dns = factory.Services.GetRequiredService<DnsResolverService>();
        var response = await dns.QueryAsync("example.com", QueryType.A);
        if (response.HasError)
        {
            Console.WriteLine("SKIPPED: no outbound DNS");
            return false;
        }
        return true;
    }

    private static string[] CacheFiles(string dir) => Directory.Exists(dir)
        ? Directory.GetFiles(dir, "*.jsonl", SearchOption.AllDirectories)
        : Array.Empty<string>();

    private static async Task WithFactoryAsync(Dictionary<string, string?> settings, string dataDir,
        Func<EdnsvAppFactory, Task> body)
    {
        settings["DataDir"] = dataDir;
        settings["FlushIntervalSeconds"] = "3600"; // only shutdown may write
        var factory = EdnsvAppFactory.WithTokenAuth(settings);
        try
        {
            var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);
            await body(factory);
        }
        finally
        {
            try { factory.Dispose(); } catch { /* already disposed */ }
            try { Directory.Delete(dataDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task UnsetResolvesToTheDataDirectorySoUpgradesAreUnchanged()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-cachedir-{Guid.NewGuid():N}");
        var seeded = false;

        await WithFactoryAsync(new Dictionary<string, string?>(), dataDir, async f =>
        {
            seeded = await SeedACacheableFetchAsync(f);
            if (!seeded) return;
            f.Dispose(); // the shutdown flush is the only writer here
            Assert.NotEmpty(CacheFiles(Path.Combine(dataDir, "cache")));
        });

        _ = seeded; // self-skips without outbound DNS
    }

    [Fact]
    public async Task BlankIsTreatedAsUnsetRatherThanAsDisabled()
    {
        // The trap this guards: GetValue<string> returns the EMPTY STRING for a JSON
        // null, so a settings file that merely mentions CacheDir would silently turn
        // the disk cache off for an existing deployment. Only the word "none" disables.
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-cachedir-{Guid.NewGuid():N}");
        var seeded = false;

        await WithFactoryAsync(new Dictionary<string, string?> { ["CacheDir"] = "" }, dataDir, async f =>
        {
            seeded = await SeedACacheableFetchAsync(f);
            if (!seeded) return;
            f.Dispose();
            Assert.NotEmpty(CacheFiles(Path.Combine(dataDir, "cache")));
        });

        _ = seeded;
    }

    [Fact]
    public async Task APathOutsideTheDataDirectoryIsUsedAsGiven()
    {
        // The pod-local case: an emptyDir volume, nowhere near the shared mount.
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-cachedir-{Guid.NewGuid():N}");
        var localCache = Path.Combine(Path.GetTempPath(), $"ednsv-localcache-{Guid.NewGuid():N}");
        var seeded = false;

        try
        {
            await WithFactoryAsync(new Dictionary<string, string?> { ["CacheDir"] = localCache }, dataDir, async f =>
            {
                seeded = await SeedACacheableFetchAsync(f);
                if (!seeded) return;
                f.Dispose();
                Assert.NotEmpty(CacheFiles(localCache));
                Assert.Empty(CacheFiles(Path.Combine(dataDir, "cache")));
            });
        }
        finally
        {
            try { Directory.Delete(localCache, recursive: true); } catch { /* best effort */ }
        }

        _ = seeded;
    }

    [Fact]
    public async Task NoneWritesNothingAndLeavesTheBagsEmpty()
    {
        // The gate has to reach the caches themselves, not just the flusher: with
        // nothing draining them, bags nobody writes out would grow for the life of
        // the process.
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-cachedir-{Guid.NewGuid():N}");
        var seeded = false;

        await WithFactoryAsync(new Dictionary<string, string?> { ["CacheDir"] = "none" }, dataDir, async f =>
        {
            seeded = await SeedACacheableFetchAsync(f);
            if (!seeded) return;

            var dns = f.Services.GetRequiredService<DnsResolverService>();
            Assert.True(dns.CacheSize > 0, "results should still be cached in memory");
            Assert.Empty(dns.CollectPendingWrites().SelectMany(p => p.Records));

            f.Dispose();
            Assert.Empty(CacheFiles(Path.Combine(dataDir, "cache")));
        });

        _ = seeded;
    }

    [Fact]
    public async Task NoneWithoutRedisWarnsThatNothingSurvivesARestart()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-cachedir-{Guid.NewGuid():N}");

        await WithFactoryAsync(new Dictionary<string, string?> { ["CacheDir"] = "none" }, dataDir, f =>
        {
            var warned = f.LogSnapshot().Any(l =>
                l.Message.Contains("Disk cache disabled", StringComparison.Ordinal)
                && l.Message.Contains("no Redis", StringComparison.Ordinal));

            Assert.True(warned, "an L1-only configuration should say so at startup");
            return Task.CompletedTask;
        });
    }

    [Fact]
    public async Task NoneWithRedisDoesNotWarn()
    {
        // `none` alongside Redis is the *recommended* multi-pod shape, so warning
        // about it would be actively misleading — and would teach operators to
        // ignore the warning that does matter. A dead endpoint is enough here:
        // RedisConnection.Enabled reflects whether a connection string was
        // configured, not whether a server answers.
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-cachedir-{Guid.NewGuid():N}");

        await WithFactoryAsync(new Dictionary<string, string?>
        {
            ["CacheDir"] = "none",
            ["Redis:ConnectionString"] = "127.0.0.1:6399,abortConnect=false,connectTimeout=150,syncTimeout=150,connectRetry=0"
        }, dataDir, f =>
        {
            var logs = f.LogSnapshot();

            Assert.DoesNotContain(logs, l =>
                l.Level == LogLevel.Warning
                && l.Message.Contains("Disk cache disabled", StringComparison.Ordinal));

            // Still announced, just not as a problem.
            Assert.Contains(logs, l =>
                l.Level == LogLevel.Information
                && l.Message.Contains("Disk cache disabled", StringComparison.Ordinal)
                && l.Message.Contains("shared Redis cache only", StringComparison.Ordinal));

            return Task.CompletedTask;
        });
    }
}
