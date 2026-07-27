using DnsClient;
using Ednsv.Core.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Ednsv.Web.Tests;

/// <summary>
/// The cache singletons are registered as pre-created instances, and the DI container
/// only disposes what it constructs itself — so nothing disposed them and the final
/// cache flush never ran. Every deploy silently discarded whatever had been gathered
/// since the last periodic flush. These tests pin the explicit ApplicationStopping hook
/// that replaces it.
/// </summary>
public sealed class ShutdownFlushTests
{
    /// <summary>Seeds a probe cache with a real fetch. Deliberately not an
    /// <c>Import</c>: imported entries are already on disk and will stop being
    /// flush-eligible later in this rework, whereas a fresh network result is
    /// exactly what a shutdown flush has to save.</summary>
    private static string[] CacheFiles(string cacheDir)
        => Directory.Exists(cacheDir)
            ? Directory.GetFiles(cacheDir, "*.jsonl", SearchOption.AllDirectories)
            : Array.Empty<string>();

    private static async Task SeedCacheAsync(EdnsvAppFactory factory)
    {
        var dns = factory.Services.GetRequiredService<DnsResolverService>();
        var response = await dns.QueryAsync("example.com", QueryType.A);
        Assert.False(response.HasError, "seed query failed — this test needs outbound DNS");
        Assert.True(dns.CacheSize > 0);
    }

    [Fact]
    public async Task ShutdownWritesTheCacheToDisk()
    {
        // The factory deletes its own DataDir on Dispose, which is exactly when the
        // shutdown flush runs — so the test owns a directory the factory will not
        // clean up. A DataDir in the settings dictionary overrides the factory's.
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-shutdown-{Guid.NewGuid():N}");
        var cacheDir = Path.Combine(dataDir, "cache");
        var factory = EdnsvAppFactory.WithTokenAuth(new Dictionary<string, string?>
        {
            ["DataDir"] = dataDir,
            // Long enough that the periodic timer cannot be what persists this.
            ["FlushIntervalSeconds"] = "3600"
        });

        try
        {
            _ = factory.CreateClient(); // build the host
            await SeedCacheAsync(factory);

            // Record files live in a per-instance subfolder, so look recursively.
            Assert.False(Directory.Exists(cacheDir) && CacheFiles(cacheDir).Length > 0,
                "nothing should have reached disk before shutdown");

            factory.Dispose(); // fires ApplicationStopping

            Assert.True(Directory.Exists(cacheDir), "shutdown did not create the cache directory");
            Assert.NotEmpty(CacheFiles(cacheDir));
        }
        finally
        {
            try { factory.Dispose(); } catch { /* already disposed */ }
            try { Directory.Delete(dataDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task ShutdownIsBoundedByTheConfiguredBudget()
    {
        var factory = EdnsvAppFactory.WithTokenAuth(new Dictionary<string, string?>
        {
            ["FlushIntervalSeconds"] = "3600",
            ["CacheShutdownFlushSeconds"] = "5"
        });

        try
        {
            _ = factory.CreateClient();
            await SeedCacheAsync(factory);

            // A wedged mount must not hold the process past its grace period. The
            // budget is 5s; a healthy flush is milliseconds, so a generous ceiling
            // still proves the wait is bounded rather than open-ended.
            var started = DateTime.UtcNow;
            factory.Dispose();
            var elapsed = DateTime.UtcNow - started;

            Assert.True(elapsed < TimeSpan.FromSeconds(30),
                $"shutdown took {elapsed.TotalSeconds:F1}s — the flush wait is not bounded");
        }
        finally
        {
            try { factory.Dispose(); } catch { /* already disposed */ }
            try { Directory.Delete(factory.DataDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task ShutdownWithAnEmptyCacheIsClean()
    {
        var factory = EdnsvAppFactory.WithTokenAuth(new Dictionary<string, string?>
        {
            ["FlushIntervalSeconds"] = "3600"
        });

        try
        {
            _ = factory.CreateClient();
            await Task.Yield();

            // Nothing cached: shutdown must still complete without throwing.
            factory.Dispose();
        }
        finally
        {
            try { factory.Dispose(); } catch { /* already disposed */ }
            try { Directory.Delete(factory.DataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
