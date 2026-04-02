using DnsClient;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Verifies that in-memory caches prevent duplicate work when the same
/// query or probe is requested multiple times within a single run.
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
    public async Task DnsQuery_ConcurrentSameDomain_OnlyOneMiss()
    {
        var dns = new DnsResolverService();
        dns.ResetErrors();

        // Fire 10 concurrent requests for the same domain+type
        var tasks = Enumerable.Range(0, 10)
            .Select(_ => dns.QueryAsync("example.com", QueryType.MX))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        // All should return the same reference (one query, rest from cache)
        var distinct = results.Distinct().Count();
        Assert.Equal(1, distinct);
        // At most 1 miss (the concurrent race may allow a second, but no more than a few)
        Assert.True(dns.CacheMisses <= 2, $"Expected at most 2 misses but got {dns.CacheMisses}");
        Assert.True(dns.CacheHits >= 8, $"Expected at least 8 hits but got {dns.CacheHits}");
    }

    [Fact]
    public async Task DnsblQuery_ReturnsCachedResult()
    {
        var dns = new DnsResolverService();
        dns.ResetErrors();

        // Use a non-existent DNSBL query that will fail fast
        var first = await dns.QueryDnsblAsync("2.0.0.127.zen.spamhaus.org", QueryType.A);
        var second = await dns.QueryDnsblAsync("2.0.0.127.zen.spamhaus.org", QueryType.A);

        Assert.Same(first, second);
        Assert.Equal(1, dns.CacheHits);
    }

    [Fact]
    public async Task PtrLookup_ReturnsCachedResult()
    {
        var dns = new DnsResolverService();

        var first = await dns.ResolvePtrAsync("8.8.8.8");
        var second = await dns.ResolvePtrAsync("8.8.8.8");

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
    public async Task SmtpProbe_SameHost_ReturnsCachedResult()
    {
        var smtp = new SmtpProbeService();

        // Use a host that will fail fast (connection refused)
        var first = await smtp.ProbeSmtpAsync("localhost", 60025);
        var second = await smtp.ProbeSmtpAsync("localhost", 60025);

        Assert.Same(first, second);
    }

    [Fact]
    public async Task SmtpProbe_CaseInsensitive()
    {
        var smtp = new SmtpProbeService();

        var lower = await smtp.ProbeSmtpAsync("localhost", 60025);
        var upper = await smtp.ProbeSmtpAsync("LOCALHOST", 60025);

        Assert.Same(lower, upper);
    }

    [Fact]
    public async Task PortProbe_SameHostAndPort_ReturnsCachedResult()
    {
        var smtp = new SmtpProbeService();

        var first = await smtp.ProbePortAsync("localhost", 60025);
        var second = await smtp.ProbePortAsync("localhost", 60025);

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task RcptProbe_SameHostAndAddress_ReturnsCachedResult()
    {
        var smtp = new SmtpProbeService();

        var first = await smtp.ProbeRcptDetailedAsync("localhost", "test@example.com");
        var second = await smtp.ProbeRcptDetailedAsync("localhost", "test@example.com");

        Assert.Equal(first, second);
    }

    [Fact]
    public async Task RcptProbe_CaseInsensitive()
    {
        var smtp = new SmtpProbeService();

        var first = await smtp.ProbeRcptDetailedAsync("localhost", "test@example.com");
        var second = await smtp.ProbeRcptDetailedAsync("LOCALHOST", "TEST@EXAMPLE.COM");

        Assert.Equal(first, second);
    }
}
