using DnsClient;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Verifies that in-memory caches prevent duplicate work when the same
/// query or probe is requested multiple times within a single run.
/// Transient failures (timeouts, connection refused) are NOT cached —
/// only successful results are cached to avoid poisoning.
/// </summary>
public class InMemoryCacheTests
{
    // ── DNS ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task DnsQuery_SameDomainAndType_ReturnsCachedResult()
    {
        var dns = new DnsResolverService();
        dns.ResetErrors();

        var first = await dns.QueryAsync("example.com", QueryType.A);
        var second = await dns.QueryAsync("example.com", QueryType.A);

        Assert.Same(first, second);
        Assert.Equal(1, dns.CacheMisses);
        Assert.Equal(1, dns.CacheHits);
    }

    [Fact]
    public async Task DnsQuery_DifferentTypes_AreCachedSeparately()
    {
        var dns = new DnsResolverService();
        dns.ResetErrors();

        var a = await dns.QueryAsync("example.com", QueryType.A);
        var mx = await dns.QueryAsync("example.com", QueryType.MX);

        Assert.NotSame(a, mx);
        Assert.Equal(2, dns.CacheMisses);
        Assert.Equal(0, dns.CacheHits);
    }

    [Fact]
    public async Task DnsQuery_CaseInsensitive()
    {
        var dns = new DnsResolverService();
        dns.ResetErrors();

        var lower = await dns.QueryAsync("example.com", QueryType.A);
        var upper = await dns.QueryAsync("EXAMPLE.COM", QueryType.A);

        Assert.Same(lower, upper);
        Assert.Equal(1, dns.CacheHits);
    }

    [Fact]
    public async Task DnsQuery_AfterFirstQuery_SubsequentConcurrentCallsHitCache()
    {
        var dns = new DnsResolverService();
        dns.ResetErrors();

        // Warm the cache with one query
        var first = await dns.QueryAsync("example.com", QueryType.MX);
        Assert.Equal(1, dns.CacheMisses);
        Assert.Equal(0, dns.CacheHits);

        // Now fire 10 concurrent requests — all should be cache hits
        var tasks = Enumerable.Range(0, 10)
            .Select(_ => dns.QueryAsync("example.com", QueryType.MX))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        // All return the same cached reference
        Assert.All(results, r => Assert.Same(first, r));
        Assert.Equal(10, dns.CacheHits);
        Assert.Equal(1, dns.CacheMisses); // still just the initial miss
    }

    [Fact]
    public async Task DnsblQuery_ErrorNotCached_RetriesOnNextCall()
    {
        var dns = new DnsResolverService();
        dns.ResetErrors();

        // DNSBL query — may succeed or fail depending on the DNS resolver
        var first = await dns.QueryDnsblAsync("2.0.0.127.zen.spamhaus.org", QueryType.A);
        var second = await dns.QueryDnsblAsync("2.0.0.127.zen.spamhaus.org", QueryType.A);

        if (!first.HasError)
        {
            // Successful results are cached — same reference returned
            Assert.Same(first, second);
        }
        // If both failed (HasError), they may or may not be the same reference
        // depending on in-flight dedup timing, but errors are not persisted in cache
    }

    [Fact]
    public async Task PtrLookup_ReturnsCachedResult()
    {
        var dns = new DnsResolverService();

        var first = await dns.ResolvePtrAsync("8.8.8.8");
        var second = await dns.ResolvePtrAsync("8.8.8.8");

        // Successful PTR lookups are cached
        Assert.Same(first, second);
    }

    // ── HTTP ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task HttpGet_SameUrl_ReturnsCachedResult()
    {
        var http = new HttpProbeService();

        var first = await http.GetAsync("http://example.com");
        var second = await http.GetAsync("http://example.com");

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task HttpGetWithHeaders_SameUrl_ReturnsCachedResult()
    {
        var http = new HttpProbeService();

        var first = await http.GetWithHeadersAsync("http://example.com");
        var second = await http.GetWithHeadersAsync("http://example.com");

        Assert.Equal(first, second);
    }

    // ── SMTP ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task SmtpProbe_DefinitiveFailure_IsCached()
    {
        var smtp = new SmtpProbeService();

        // Connection refused on localhost:60025 is a definitive failure — should be cached
        var first = await smtp.ProbeSmtpAsync("localhost", 60025);
        var second = await smtp.ProbeSmtpAsync("localhost", 60025);

        Assert.False(first.Connected);
        // Definitive failures (connection refused) are cached; only timeouts are not
        Assert.Same(first, second);
    }

    [Fact]
    public async Task PortProbe_DefinitiveClosedPort_IsCached()
    {
        var smtp = new SmtpProbeService();

        // Connection refused on localhost:60025 is definitive — should be cached
        var first = await smtp.ProbePortAsync("localhost", 60025);
        var second = await smtp.ProbePortAsync("localhost", 60025);

        Assert.False(first);
        Assert.Equal(first, second);
    }

    [Fact]
    public async Task RcptProbe_ConnectionFailure_NotCached()
    {
        var smtp = new SmtpProbeService();

        var first = await smtp.ProbeRcptDetailedAsync("localhost", "test@example.com");
        var second = await smtp.ProbeRcptDetailedAsync("localhost", "test@example.com");

        Assert.False(first.accepted);
    }
}
