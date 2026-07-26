using System.Net.Http.Headers;
using System.Text.Json;
using Ednsv.Core.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Ednsv.Web.Tests;

/// <summary>
/// The disk cache is loaded on a background task rather than awaited before the app
/// runs. Awaiting it made startup latency scale with replica count — on a shared
/// mount every instance reads every other instance's files, and a rolling deploy has
/// all of them doing it at once against one endpoint.
/// </summary>
public sealed class BackgroundCacheLoadTests
{
    /// <summary>Plants a record file as though a previous run of this instance had
    /// flushed it. A PTR entry, because it needs no live network to construct and
    /// lands somewhere observable.</summary>
    private static void SeedPtrRecord(string cacheDir, string ip, string name)
    {
        var dir = DiskCacheService.InstanceFolder(cacheDir);
        Directory.CreateDirectory(dir);
        var now = DateTime.UtcNow;
        var record = new CacheRecord
        {
            Type = CacheTypes.Ptr,
            Key = $"ptr:{ip}",
            WrittenUtc = now,
            ExpiresUtc = now.AddHours(1),
            Value = JsonSerializer.SerializeToNode(new List<string> { name })
        };
        File.WriteAllText(
            Path.Combine(dir, $"cache.{now:yyyyMMdd'T'HHmmssfff}Z.{Guid.NewGuid().ToString("N")[..8]}.jsonl"),
            JsonSerializer.Serialize(record) + "\n");
    }

    [Fact]
    public async Task TheCacheIsLoadedAfterTheAppStartsServing()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-bgload-{Guid.NewGuid():N}");
        var cacheDir = Path.Combine(dataDir, "cache");
        SeedPtrRecord(cacheDir, "8.8.8.8", "dns.google.");

        var factory = EdnsvAppFactory.WithTokenAuth(new Dictionary<string, string?>
        {
            ["DataDir"] = dataDir,
            ["FlushIntervalSeconds"] = "3600"
        });

        try
        {
            var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);

            // Serving does not wait on the load.
            var health = await client.GetAsync("/health/live");
            Assert.True(health.IsSuccessStatusCode, $"health/live -> {(int)health.StatusCode} {await health.Content.ReadAsStringAsync()}");

            // And the load does happen, just behind it.
            var dns = factory.Services.GetRequiredService<DnsResolverService>();
            for (var i = 0; i < 100 && dns.CacheSize == 0; i++) await Task.Delay(50);

            Assert.True(dns.CacheSize > 0, "the background load never populated the cache");
        }
        finally
        {
            try { factory.Dispose(); } catch { /* already disposed */ }
            try { Directory.Delete(dataDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task AGarbageCacheFileDoesNotStopTheGoodOnesLoading()
    {
        // Files on a shared mount can be truncated by a killed writer or left over
        // from a version that wrote something else. One unreadable file must cost
        // its own entries and nothing more.
        var dataDir = Path.Combine(Path.GetTempPath(), $"ednsv-bgload-{Guid.NewGuid():N}");
        var cacheDir = Path.Combine(dataDir, "cache");
        File.WriteAllText(
            Path.Combine(Directory.CreateDirectory(DiskCacheService.InstanceFolder(cacheDir)).FullName,
                $"cache.{DateTime.UtcNow:yyyyMMdd'T'HHmmssfff}Z.garbage1.jsonl"),
            "this is not a record\n{ half an object");
        SeedPtrRecord(cacheDir, "8.8.4.4", "dns.google.");

        var factory = EdnsvAppFactory.WithTokenAuth(new Dictionary<string, string?>
        {
            ["DataDir"] = dataDir,
            ["FlushIntervalSeconds"] = "3600"
        });

        try
        {
            var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);

            var health = await client.GetAsync("/health/live");
            Assert.True(health.IsSuccessStatusCode, $"health/live -> {(int)health.StatusCode}");

            var dns = factory.Services.GetRequiredService<DnsResolverService>();
            for (var i = 0; i < 100 && dns.CacheSize == 0; i++) await Task.Delay(50);

            Assert.True(dns.CacheSize > 0, "the good file's entries should still have loaded");
        }
        finally
        {
            try { factory.Dispose(); } catch { /* already disposed */ }
            try { Directory.Delete(dataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
