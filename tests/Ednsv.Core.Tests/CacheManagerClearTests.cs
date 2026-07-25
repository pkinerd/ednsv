using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Covers the disk side of an admin cache-clear. The ordering hazard this guards
/// is that a flush which sampled the in-memory caches before the clear is still
/// writing them out afterwards: clearing memory alone does not stop that write,
/// so the delete has to happen under the flusher's lock. These tests pin the
/// resulting contract — after ClearAllAsync no cache file survives — rather than
/// trying to reproduce the timing window.
/// </summary>
public sealed class CacheManagerClearTests : IDisposable
{
    private readonly string _cacheDir;

    public CacheManagerClearTests()
    {
        _cacheDir = Path.Combine(Path.GetTempPath(), $"ednsv-clear-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_cacheDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_cacheDir, recursive: true); } catch { /* best effort */ }
    }

    private CacheManager NewManager() => new(
        _cacheDir, TimeSpan.FromHours(1),
        new DnsResolverService(), new SmtpProbeService(), new HttpProbeService());

    private void SeedCacheFiles()
    {
        File.WriteAllText(Path.Combine(_cacheDir, "dns-queries.json"), "{}");
        File.WriteAllText(Path.Combine(_cacheDir, "http-get.json"), "{}");
        File.WriteAllText(Path.Combine(_cacheDir, "domain-results.json"), "{}");
        File.WriteAllText(Path.Combine(_cacheDir, "dns-queries.json.deadbeef.tmp"), "{}");
    }

    private void AssertCacheFilesGone()
    {
        Assert.False(File.Exists(Path.Combine(_cacheDir, "dns-queries.json")));
        Assert.False(File.Exists(Path.Combine(_cacheDir, "http-get.json")));
        Assert.False(File.Exists(Path.Combine(_cacheDir, "domain-results.json")));
        Assert.False(File.Exists(Path.Combine(_cacheDir, "dns-queries.json.deadbeef.tmp")));
    }

    [Fact]
    public async Task ClearAllAsync_WithBackgroundFlusher_RemovesDiskCacheFiles()
    {
        SeedCacheFiles();

        await using var mgr = NewManager();
        // Long interval so the timer never fires; the point is the lock, not the timer.
        mgr.StartBackgroundFlusher(TimeSpan.FromMinutes(10));

        await mgr.ClearAllAsync();

        AssertCacheFilesGone();
    }

    [Fact]
    public async Task ClearAllAsync_WithoutFlusher_RemovesDiskCacheFiles()
    {
        SeedCacheFiles();

        await using var mgr = NewManager();
        await mgr.ClearAllAsync();

        AssertCacheFilesGone();
    }

    [Fact]
    public async Task ClearAllAsync_ConcurrentFlushDoesNotResurrectFiles()
    {
        SeedCacheFiles();

        await using var mgr = NewManager();
        mgr.StartBackgroundFlusher(TimeSpan.FromMinutes(10));

        // Whichever order these interleave in, the in-memory caches are already
        // empty, so a flush that wins the lock has nothing to write back.
        var clear = mgr.ClearAllAsync();
        mgr.RequestFlush();
        await clear;

        AssertCacheFilesGone();
    }

    [Fact]
    public async Task ClearAllAsync_LeavesUnrelatedFilesAlone()
    {
        SeedCacheFiles();
        var unrelated = Path.Combine(_cacheDir, "unrelated.txt");
        File.WriteAllText(unrelated, "keep me");

        await using var mgr = NewManager();
        await mgr.ClearAllAsync();

        Assert.True(File.Exists(unrelated));
    }
}
