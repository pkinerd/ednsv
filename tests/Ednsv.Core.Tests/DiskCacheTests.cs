using DnsClient;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Verifies disk cache round-trip: save services to disk, load into fresh
/// services, and confirm the cached entries are restored and served.
/// Now uses directory-based cache with per-entry timestamps.
/// </summary>
public class DiskCacheTests : IDisposable
{
    private readonly string _cacheDir;

    public DiskCacheTests()
    {
        _cacheDir = Path.Combine(Path.GetTempPath(), $"ednsv-test-{Guid.NewGuid():N}");
    }

    public void Dispose()
    {
        if (Directory.Exists(_cacheDir))
            Directory.Delete(_cacheDir, true);
    }

    // ── Round-trip tests ─────────────────────────────────────────────────

    [Fact]
    public async Task DnsCache_RoundTrip_RestoresEntries()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        // Populate DNS cache with a live query
        await dns1.QueryAsync("example.com", QueryType.A);
        Assert.True(dns1.CacheSize > 0);

        // Save to disk
        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);
        Assert.True(Directory.Exists(_cacheDir));
        Assert.True(File.Exists(Path.Combine(_cacheDir, "dns-queries.json")));

        // Load into fresh services
        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();
        dns2.ResetErrors();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2);
        Assert.NotNull(loadResult);
        Assert.True(loadResult!.DnsQueries > 0, "Expected DNS entries to be loaded from cache");

        // Query again — should come from loaded cache (hit, not miss)
        await dns2.QueryAsync("example.com", QueryType.A);
        Assert.Equal(1, dns2.CacheHits);
        Assert.Equal(0, dns2.CacheMisses);
    }

    [Fact]
    public async Task HttpCache_RoundTrip_RestoresEntries()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        // Populate HTTP cache
        var original = await http1.GetAsync("http://example.com");

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        // Load into fresh services
        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2);
        Assert.NotNull(loadResult);
        Assert.True(loadResult!.HttpRequests > 0);

        // Should return cached result without making a new request
        var restored = await http2.GetAsync("http://example.com");
        Assert.Equal(original.statusCode, restored.statusCode);
        Assert.Equal(original.success, restored.success);
    }

    [Fact]
    public async Task SmtpProbeCache_RoundTrip_RestoresEntries()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        // Populate SMTP cache (connection failure, fast)
        var original = await smtp1.ProbeSmtpAsync("localhost", 60025);

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2);
        Assert.NotNull(loadResult);
        Assert.True(loadResult!.SmtpProbes > 0);

        var restored = await smtp2.ProbeSmtpAsync("localhost", 60025);
        Assert.Equal(original.Connected, restored.Connected);
        Assert.Equal(original.Error, restored.Error);
    }

    [Fact]
    public async Task PortCache_RoundTrip_RestoresEntries()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        await smtp1.ProbePortAsync("localhost", 60025);

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2);
        Assert.NotNull(loadResult);
        Assert.True(loadResult!.PortProbes > 0);
    }

    [Fact]
    public async Task RcptCache_RoundTrip_RestoresEntries()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        await smtp1.ProbeRcptDetailedAsync("localhost", "test@example.com");

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2);
        Assert.NotNull(loadResult);
        Assert.True(loadResult!.RcptProbes > 0);
    }

    [Fact]
    public async Task PtrCache_RoundTrip_RestoresEntries()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        await dns1.ResolvePtrAsync("8.8.8.8");

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2);
        Assert.NotNull(loadResult);
        Assert.True(loadResult!.PtrLookups > 0);

        // Should come from cache
        var ptrs = await dns2.ResolvePtrAsync("8.8.8.8");
        Assert.NotEmpty(ptrs);
    }

    // ── Per-entry TTL expiry ────────────────────────────────────────────

    [Fact]
    public async Task LoadAsync_ExpiredEntries_FilteredOut()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        await dns1.QueryAsync("example.com", QueryType.A);
        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        // Load with zero TTL — all entries should be expired
        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.Zero, smtp2, http2, dns2);
        Assert.Null(loadResult);
    }

    [Fact]
    public async Task LoadAsync_MissingDirectory_ReturnsNull()
    {
        var dns = new DnsResolverService();
        var smtp = new SmtpProbeService();
        var http = new HttpProbeService();

        var result = await DiskCacheService.LoadAsync(
            Path.Combine(_cacheDir, "nonexistent"),
            TimeSpan.FromHours(1), smtp, http, dns);

        Assert.Null(result);
    }

    [Fact]
    public async Task LoadAsync_CorruptFile_ReturnsNull()
    {
        Directory.CreateDirectory(_cacheDir);
        await File.WriteAllTextAsync(Path.Combine(_cacheDir, "dns-queries.json"), "this is not valid json {{{");

        var dns = new DnsResolverService();
        var smtp = new SmtpProbeService();
        var http = new HttpProbeService();

        var result = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp, http, dns);
        Assert.Null(result);
    }

    // ── Separate files per cache type ────────────────────────────────────

    [Fact]
    public async Task SaveAsync_CreatesPerTypeFiles()
    {
        var dns = new DnsResolverService();
        var smtp = new SmtpProbeService();
        var http = new HttpProbeService();

        await dns.QueryAsync("example.com", QueryType.A);
        await http.GetAsync("http://example.com");
        await smtp.ProbePortAsync("localhost", 60025);

        await DiskCacheService.SaveAsync(_cacheDir, smtp, http, dns);

        Assert.True(File.Exists(Path.Combine(_cacheDir, "dns-queries.json")));
        Assert.True(File.Exists(Path.Combine(_cacheDir, "http-get.json")));
        Assert.True(File.Exists(Path.Combine(_cacheDir, "port-probes.json")));
    }

    // ── Merge behavior ──────────────────────────────────────────────────

    [Fact]
    public async Task SaveAsync_MergesWithExistingEntries()
    {
        // First save: DNS only
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();
        await dns1.QueryAsync("example.com", QueryType.A);
        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        // Second save: HTTP only (different service instances)
        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();
        await http2.GetAsync("http://example.com");
        await DiskCacheService.SaveAsync(_cacheDir, smtp2, http2, dns2);

        // Load: should have both DNS and HTTP entries
        var dns3 = new DnsResolverService();
        var smtp3 = new SmtpProbeService();
        var http3 = new HttpProbeService();
        var result = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp3, http3, dns3);
        Assert.NotNull(result);
        Assert.True(result!.DnsQueries > 0, "DNS entries from first save should be preserved");
        Assert.True(result.HttpRequests > 0, "HTTP entries from second save should be present");
    }

    // ── --retry-errors filtering ─────────────────────────────────────────

    [Fact]
    public async Task RetryErrors_FiltersOutFailedSmtpProbes()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        // This will fail (no SMTP on localhost:60025) — creates a cached error
        await smtp1.ProbeSmtpAsync("localhost", 60025);

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        // Load with retryErrors=true — failed SMTP probe should be filtered out
        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2, retryErrors: true);
        // May be null if all entries are filtered out, or have 0 SMTP probes
        Assert.True(loadResult == null || loadResult.SmtpProbes == 0);
    }

    [Fact]
    public async Task RetryErrors_FiltersOutClosedPorts()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        await smtp1.ProbePortAsync("localhost", 60025);

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2, retryErrors: true);
        Assert.True(loadResult == null || loadResult.PortProbes == 0);
    }

    [Fact]
    public async Task RetryErrors_FiltersOutFailedRcpt()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        await smtp1.ProbeRcptDetailedAsync("localhost", "test@example.com");

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2, retryErrors: true);
        Assert.True(loadResult == null || loadResult.RcptProbes == 0);
    }

    [Fact]
    public async Task RetryErrors_KeepsSuccessfulEntries()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        // DNS query to example.com should succeed (not HasError)
        var response = await dns1.QueryAsync("example.com", QueryType.A);
        Assert.False(response.HasError);

        // HTTP to example.com should succeed
        var httpResult = await http1.GetAsync("http://example.com");
        Assert.True(httpResult.success);

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var loadResult = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2, retryErrors: true);
        Assert.NotNull(loadResult);
        Assert.True(loadResult!.DnsQueries > 0, "Successful DNS entries should survive --retry-errors");
        Assert.True(loadResult!.HttpRequests > 0, "Successful HTTP entries should survive --retry-errors");
    }

    // ── Cache entry counts ───────────────────────────────────────────────

    [Fact]
    public async Task SaveAndLoad_AllCacheTypes_CountsMatch()
    {
        var dns1 = new DnsResolverService();
        var smtp1 = new SmtpProbeService();
        var http1 = new HttpProbeService();

        // Populate all cache types
        await dns1.QueryAsync("example.com", QueryType.A);
        await dns1.QueryAsync("example.com", QueryType.MX);
        await dns1.ResolvePtrAsync("8.8.8.8");
        await http1.GetAsync("http://example.com");
        await smtp1.ProbeSmtpAsync("localhost", 60025);
        await smtp1.ProbePortAsync("localhost", 60025);
        await smtp1.ProbeRcptDetailedAsync("localhost", "test@example.com");

        await DiskCacheService.SaveAsync(_cacheDir, smtp1, http1, dns1);

        var dns2 = new DnsResolverService();
        var smtp2 = new SmtpProbeService();
        var http2 = new HttpProbeService();

        var result = await DiskCacheService.LoadAsync(_cacheDir, TimeSpan.FromHours(1), smtp2, http2, dns2);
        Assert.NotNull(result);
        Assert.True(result!.DnsQueries >= 2, $"DNS: expected >= 2, got {result.DnsQueries}");
        Assert.True(result.PtrLookups >= 1, $"PTR: expected >= 1, got {result.PtrLookups}");
        Assert.True(result.HttpRequests >= 1, $"HTTP: expected >= 1, got {result.HttpRequests}");
        Assert.True(result.SmtpProbes >= 1, $"SMTP: expected >= 1, got {result.SmtpProbes}");
        Assert.True(result.PortProbes >= 1, $"Port: expected >= 1, got {result.PortProbes}");
        Assert.True(result.RcptProbes >= 1, $"RCPT: expected >= 1, got {result.RcptProbes}");
        Assert.True(result.Total >= 7, $"Total: expected >= 7, got {result.Total}");
    }
}
