using System.Net;
using System.Collections.Concurrent;
using System.Reflection;
using System.Text.Json;
using DnsClient;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Every cache a probe service holds honours <c>CacheTtlHours</c>, not just the ones
/// behind a <c>ProbeCache</c>. Six of them used to be plain dictionaries with no expiry
/// at all: RCPT probes, relay tests, AXFR verdicts, AXFR responses, unreachable-server
/// counts and domain summaries — plus the per-server <c>LookupClient</c> pool, which is
/// keyed by nameserver IP and so grows with the domains checked.
/// </summary>
public sealed class ServiceCacheExpiryTests
{
    private static readonly TimeSpan Brief = TimeSpan.FromMilliseconds(150);
    private const int PastBrief = 400;

    private static SmtpProbeService Smtp() => new(cacheTtl: Brief);
    private static DnsResolverService Dns() => new(nameservers: null, cacheTtl: Brief);

    // ── The structural guarantee ─────────────────────────────────────────

    [Fact]
    public void NoServiceHoldsCachedResultsInAPlainDictionary()
    {
        // The regression this exists to catch is not a wrong TTL, it is someone adding
        // the seventh unbounded dictionary. A plain map of probe results has no expiry
        // and nothing prunes it, so it holds every distinct key the process ever sees.
        var offenders = new List<string>();

        foreach (var type in new[]
                 {
                     typeof(DnsResolverService), typeof(SmtpProbeService),
                     typeof(HttpProbeService), typeof(DomainResultStore)
                 })
        {
            foreach (var field in type.GetFields(
                         BindingFlags.Instance | BindingFlags.Static
                         | BindingFlags.Public | BindingFlags.NonPublic))
            {
                var ft = field.FieldType;
                if (!ft.IsGenericType) continue;

                var def = ft.GetGenericTypeDefinition();
                if (def == typeof(ConcurrentDictionary<,>) || def == typeof(Dictionary<,>))
                    offenders.Add($"{type.Name}.{field.Name}");
            }
        }

        Assert.Empty(offenders);
    }

    [Fact]
    public void EveryExpiringMapAServiceHoldsIsBuiltWithTheConfiguredTtl()
    {
        // Deliberately white-box, because the alternative does not exist: the live
        // write paths into these maps (a RCPT probe, a relay test, a zone transfer,
        // a failed server query) all need the network, so nothing else here can tell a
        // map built with the cache TTL from one built with null — and a null TTL is
        // precisely the leak this work closes. Reading the field is the only way to
        // pin the wiring for all seven maps, including the AXFR response cache, which
        // cannot be populated at all without a real zone transfer.
        var ttl = TimeSpan.FromMinutes(7);

        var services = new (string Name, object Instance)[]
        {
            ("DnsResolverService", new DnsResolverService(nameservers: null, cacheTtl: ttl)),
            ("SmtpProbeService", new SmtpProbeService(cacheTtl: ttl)),
            ("HttpProbeService", new HttpProbeService(cacheTtl: ttl)),
            ("DomainResultStore", new DomainResultStore(ttl))
        };

        var checked_ = 0;
        foreach (var (name, instance) in services)
        {
            foreach (var field in instance.GetType().GetFields(
                         BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public))
            {
                if (!field.FieldType.IsGenericType
                    || field.FieldType.GetGenericTypeDefinition() != typeof(ExpiringMap<,>))
                    continue;

                var map = field.GetValue(instance);
                Assert.NotNull(map);

                var ttlField = map!.GetType().GetField("_ttl", BindingFlags.Instance | BindingFlags.NonPublic);
                Assert.NotNull(ttlField);

                Assert.Equal(ttl, (TimeSpan?)ttlField!.GetValue(map));
                checked_++;
            }
        }

        // Fails loudly if a rename or a refactor quietly empties this test out.
        Assert.Equal(7, checked_);
    }

    // ── SMTP: RCPT probes and relay tests ────────────────────────────────
    //
    // These assert through a *read*, not through a count. Since these caches became a
    // MemoryCache, Count reports what is held — expired entries included until the
    // platform's sweep gets to them — so the only honest question is whether the value
    // is still served. Answering that needs somewhere for the refetch to land, which is
    // what the stub is for.

    [Fact]
    public async Task RcptProbesExpire()
    {
        using var stub = SmtpStubServer.Start("250 refetched");
        var smtp = new SmtpProbeService(cacheTtl: Brief, timeoutSeconds: 2, smtpPort: stub.Port);
        Assert.True(Import(smtp, CacheTypes.Rcpt, "127.0.0.1|user@example.com",
            new RcptCacheEntry { Accepted = true, Response = "250 cached" }));

        var served = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "user@example.com");
        Assert.Equal("250 cached", served.response);
        Assert.Equal(0, stub.Connections);

        await Task.Delay(PastBrief);

        var refetched = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "user@example.com");
        Assert.Equal("250 refetched", refetched.response);
        Assert.Equal(1, stub.Connections);
    }

    [Fact]
    public async Task RelayTestsExpire()
    {
        using var stub = SmtpStubServer.Start("250 relayed");
        var smtp = new SmtpProbeService(cacheTtl: Brief, timeoutSeconds: 2, smtpPort: stub.Port);
        Assert.True(Import(smtp, CacheTypes.Relay, "relay:127.0.0.1|example.com",
            new RelayCacheEntry { IsRelay = false, Description = "cached verdict" }));

        Assert.Equal("cached verdict", (await smtp.TestRelayAsync("127.0.0.1", "example.com")).description);
        Assert.Equal(0, stub.Connections);

        await Task.Delay(PastBrief);

        Assert.True((await smtp.TestRelayAsync("127.0.0.1", "example.com")).isRelay);
        Assert.Equal(1, stub.Connections);
    }

    [Fact]
    public async Task AnImportDoesNotGetAFreshFullTtl()
    {
        // A record with 150ms left must live 150ms, not the cache's two hours.
        using var stub = SmtpStubServer.Start("250 refetched");
        var smtp = new SmtpProbeService(cacheTtl: TimeSpan.FromHours(2), timeoutSeconds: 2,
            smtpPort: stub.Port);
        Assert.True(Import(smtp, CacheTypes.Rcpt, "127.0.0.1|user@example.com",
            new RcptCacheEntry { Accepted = true, Response = "250 cached" },
            DateTime.UtcNow.Add(Brief)));

        Assert.Equal("250 cached", (await smtp.ProbeRcptDetailedAsync("127.0.0.1", "user@example.com")).response);

        await Task.Delay(PastBrief);

        Assert.Equal("250 refetched",
            (await smtp.ProbeRcptDetailedAsync("127.0.0.1", "user@example.com")).response);
    }

    // ── DNS: AXFR verdicts and unreachable-server counts ─────────────────

    [Fact]
    public async Task AxfrVerdictsExpire()
    {
        // A listener that hangs up is enough: the assertion is that the transfer was
        // attempted again at all, which a still-cached verdict would have skipped.
        using var ns = TcpConnectionCounter.TryStart(53);
        if (ns == null) return;

        var dns = Dns();
        Assert.True(Import(dns, CacheTypes.Axfr, "127.0.0.1|example.com", true));

        Assert.True(await dns.TestZoneTransferAsync(IPAddress.Loopback, "example.com"));
        Assert.Equal(0, ns.Connections);

        await Task.Delay(PastBrief);

        Assert.False(await dns.TestZoneTransferAsync(IPAddress.Loopback, "example.com"));
        Assert.True(ns.Connections > 0, "the expired verdict should have been refetched");
    }

    [Fact]
    public async Task UnreachableServerCountsExpire()
    {
        // These already decayed in *meaning* after five minutes — the skip stopped
        // applying — but the entry itself stayed for the life of the process. Observed
        // through the skip, since that is the only thing the count does.
        var dns = new DnsResolverService(nameservers: null, cacheTtl: Brief,
            tuning: new DnsTuning { QueryTimeoutSeconds = 0.3, QueryRetries = 0 });
        Assert.True(Import(dns, CacheTypes.Unreachable, "127.0.0.1", 99));

        var before = dns.ResponsesReceived;
        await dns.QueryServerAsync(IPAddress.Loopback, "example.com", QueryType.A);
        Assert.Equal(before, dns.ResponsesReceived); // skipped, nothing asked

        await Task.Delay(PastBrief);

        await dns.QueryServerAsync(IPAddress.Loopback, "example.com", QueryType.A);
        Assert.True(dns.ResponsesReceived > before, "the expired count should stop the skip");
    }

    // ── An import keeps the expiry stamped on its record ─────────────────

    [Fact]
    public void AnImportPastItsExpiryIsRefusedRatherThanResurrected()
    {
        var smtp = Smtp();
        var dns = Dns();
        var expired = DateTime.UtcNow.AddMinutes(-1);

        // Still "ours", so the record is claimed and not offered to another service —
        // it is simply not stored. Nothing is written at all, so the counts are exact
        // here: there is no expired entry waiting to be swept.
        Assert.True(Import(smtp, CacheTypes.Rcpt, "mx.example|user@example.com",
            new RcptCacheEntry { Accepted = true, Response = "250 OK" }, expired));
        Assert.True(Import(dns, CacheTypes.Axfr, "192.0.2.1|example.com", false, expired));
        Assert.True(Import(dns, CacheTypes.Unreachable, "192.0.2.1", 3, expired));

        Assert.Equal(0, smtp.RcptCacheCount);
        Assert.Equal(0, dns.AxfrCacheCount);
        Assert.Equal(0, dns.UnreachableServerCount);
    }

    // ── The per-server client pool ───────────────────────────────────────
    //
    // Covered by construction rather than behaviour: a rebuilt LookupClient is not
    // observable from outside the service, so the TTL wiring test above pins that
    // _serverClients gets the configured TTL, and ExpiringMapTests pins that GetOrAdd
    // rebuilds once it has elapsed.

    // ── Domain result summaries ──────────────────────────────────────────

    [Fact]
    public async Task DomainSummariesExpire()
    {
        // These drive recheck decisions, so a summary outliving the probe results it
        // was derived from would target a recheck using evidence nobody can see.
        var store = new DomainResultStore(Brief);
        store.Set("example.com", new DomainResultSummary { ValidatedAtUtc = DateTime.UtcNow, PassCount = 1 });

        Assert.True(store.TryGet("example.com", out _));

        await Task.Delay(PastBrief);

        Assert.False(store.TryGet("example.com", out _));
    }

    [Fact]
    public void WithoutATtlNothingExpiresAnywhere()
    {
        // CacheTtlHours=0 keeps its documented meaning: no expiry, in these caches as
        // in every other.
        var smtp = new SmtpProbeService(cacheTtl: null);
        var store = new DomainResultStore(null);

        Assert.True(Import(smtp, CacheTypes.Rcpt, "mx.example|user@example.com",
            new RcptCacheEntry { Accepted = true, Response = "250 OK" },
            DateTime.MaxValue));
        store.Set("example.com", new DomainResultSummary { ValidatedAtUtc = DateTime.UtcNow });

        Thread.Sleep(PastBrief);

        Assert.Equal(1, smtp.RcptCacheCount);
        Assert.True(store.TryGet("example.com", out _));
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static bool Import<T>(SmtpProbeService smtp, string type, string key, T value,
        DateTime? expiresUtc = null)
        => smtp.TryImportRecord(type, key, JsonSerializer.SerializeToNode(value),
            expiresUtc ?? DateTime.UtcNow.Add(Brief));

    private static bool Import<T>(DnsResolverService dns, string type, string key, T value,
        DateTime? expiresUtc = null)
        => dns.TryImportRecord(type, key, JsonSerializer.SerializeToNode(value),
            expiresUtc ?? DateTime.UtcNow.Add(Brief));
}
