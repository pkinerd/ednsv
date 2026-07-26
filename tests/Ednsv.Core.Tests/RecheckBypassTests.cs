using System.Net;
using System.Text.Json;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The recheck bypass reaching the caches that are not a <c>ProbeCache</c>.
///
/// <para><c>RecheckHelper</c> maps check categories to <c>CacheDep</c> flags, and the
/// caches are supposed to return a miss for the flags the current validation carries.
/// Four of them did not: <c>CacheDep.Rcpt</c> was declared by the Postmaster and Abuse
/// categories and read by nothing at all; the relay verdict was reused through a
/// <c>CacheDep.Smtp</c> recheck that refreshed the handshake beside it; the AXFR caches
/// had no flag; and the unreachable-server breaker sat in front of the server-query
/// cache, skipping the very servers a <c>ServerDns</c> recheck wanted retried.</para>
///
/// <para>These probe <c>127.0.0.1</c>, where the connection is refused immediately: no
/// network, and the refusal is a different answer from the cached one, which is exactly
/// what a bypass has to produce. The cases that need a <i>definitive</i> answer — the
/// ones proving the refetched value replaces the cached one — point the probe at a stub
/// on an ephemeral port instead.</para>
/// </summary>
public sealed class RecheckBypassTests : IDisposable
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    public void Dispose() => RecheckHelper.CurrentRecheckDeps.Value = RecheckHelper.CacheDep.None;

    private static void Rechecking(RecheckHelper.CacheDep deps)
        => RecheckHelper.CurrentRecheckDeps.Value = deps;

    // ── RCPT probes: CacheDep.Rcpt was declared and never read ───────────

    private static SmtpProbeService SmtpWithCachedRcpt(string host, string address, string response)
    {
        var smtp = new SmtpProbeService(cacheTtl: Ttl, timeoutSeconds: 0.5);
        Assert.True(smtp.TryImportRecord(CacheTypes.Rcpt, $"{host}|{address}",
            JsonSerializer.SerializeToNode(new RcptCacheEntry { Accepted = true, Response = response }),
            DateTime.UtcNow.Add(Ttl)));
        return smtp;
    }

    [Fact]
    public async Task WithoutARecheckACachedRcptVerdictIsServed()
    {
        var smtp = SmtpWithCachedRcpt("127.0.0.1", "postmaster@example.com", "250 cached");

        var (accepted, response) = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");

        Assert.True(accepted);
        Assert.Equal("250 cached", response);
    }

    [Fact]
    public async Task RecheckingRcptRefetchesInsteadOfServingTheCachedVerdict()
    {
        var smtp = SmtpWithCachedRcpt("127.0.0.1", "postmaster@example.com", "250 cached");
        Rechecking(RecheckHelper.CacheDep.Rcpt);

        var (_, response) = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");

        Assert.NotEqual("250 cached", response);
    }

    [Fact]
    public async Task RecheckingSomethingElseLeavesTheRcptVerdictAlone()
    {
        // The bypass is per cache type: a DNS recheck must not re-probe RCPT.
        var smtp = SmtpWithCachedRcpt("127.0.0.1", "postmaster@example.com", "250 cached");
        Rechecking(RecheckHelper.CacheDep.Dns | RecheckHelper.CacheDep.Http);

        var (_, response) = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");

        Assert.Equal("250 cached", response);
    }

    [Fact]
    public async Task AFreshRcptVerdictReplacesTheOneTheBypassSkipped()
    {
        // The half of the fix that is easy to miss. Bypassing the read is not enough:
        // the write was add-if-absent, so the refetched answer would be handed to the
        // caller and dropped, leaving the entry the recheck existed to replace — every
        // recheck paying for a probe and changing nothing.
        //
        // Needs a definitive answer, which a refused connection is not, so this one
        // wants a server.
        using var stub = SmtpStubServer.Start("250 first answer", "550 second answer", "999 third answer");
        var smtp = new SmtpProbeService(cacheTtl: Ttl, timeoutSeconds: 2, smtpPort: stub.Port);

        var first = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");
        Assert.Equal("250 first answer", first.response);

        // Served from cache: the stub is not contacted a second time.
        var cached = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");
        Assert.Equal("250 first answer", cached.response);
        Assert.Equal(1, stub.Connections);

        Rechecking(RecheckHelper.CacheDep.Rcpt);
        var rechecked = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");
        Assert.Equal("550 second answer", rechecked.response);
        Assert.Equal(2, stub.Connections);

        // And the new answer is what everyone else now gets — served from cache, which
        // the stub's distinct third answer is what proves.
        Rechecking(RecheckHelper.CacheDep.None);
        var after = await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");
        Assert.Equal("550 second answer", after.response);
        Assert.Equal(2, stub.Connections);
    }

    [Fact]
    public async Task AFreshRelayVerdictReplacesTheOneTheBypassSkipped()
    {
        using var stub = SmtpStubServer.Start("250 relayed", "550 refused", "250 relayed again");
        var smtp = new SmtpProbeService(cacheTtl: Ttl, timeoutSeconds: 2, smtpPort: stub.Port);

        var first = await smtp.TestRelayAsync("127.0.0.1", "example.com");
        Assert.True(first.isRelay);

        Rechecking(RecheckHelper.CacheDep.Smtp);
        var rechecked = await smtp.TestRelayAsync("127.0.0.1", "example.com");
        Assert.False(rechecked.isRelay);

        Rechecking(RecheckHelper.CacheDep.None);
        var after = await smtp.TestRelayAsync("127.0.0.1", "example.com");
        Assert.False(after.isRelay);
        Assert.Equal(2, stub.Connections);
    }

    [Fact]
    public async Task ARefetchedVerdictIsQueuedForDiskAsWellAsMemory()
    {
        // A recheck that refreshes memory but not the write bag would leave the stale
        // verdict on disk, so the next process start would load it back.
        using var stub = SmtpStubServer.Start("250 first answer", "550 second answer");
        var smtp = new SmtpProbeService(cacheTtl: Ttl, timeoutSeconds: 2, smtpPort: stub.Port);
        await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");
        foreach (var pending in smtp.CollectPendingWrites()) pending.Commit(); // drain

        Rechecking(RecheckHelper.CacheDep.Rcpt);
        await smtp.ProbeRcptDetailedAsync("127.0.0.1", "postmaster@example.com");

        var queued = smtp.CollectPendingWrites()
            .SelectMany(p => p.Records)
            .Where(r => r.Type == CacheTypes.Rcpt)
            .ToList();

        Assert.Single(queued);
        Assert.Contains("second answer", queued[0].Value!.ToJsonString());
    }

    // ── Relay tests: refreshed by CacheDep.Smtp, like the handshake ──────

    [Fact]
    public async Task RecheckingSmtpRefetchesTheRelayVerdict()
    {
        var smtp = new SmtpProbeService(cacheTtl: Ttl, timeoutSeconds: 0.5);
        Assert.True(smtp.TryImportRecord(CacheTypes.Relay, "relay:127.0.0.1|example.com",
            JsonSerializer.SerializeToNode(new RelayCacheEntry { IsRelay = true, Description = "cached verdict" }),
            DateTime.UtcNow.Add(Ttl)));

        var before = await smtp.TestRelayAsync("127.0.0.1", "example.com");
        Assert.Equal("cached verdict", before.description);

        Rechecking(RecheckHelper.CacheDep.Smtp);
        var after = await smtp.TestRelayAsync("127.0.0.1", "example.com");

        Assert.NotEqual("cached verdict", after.description);
    }

    // ── AXFR: its own flag, and both caches behind it ────────────────────

    [Fact]
    public void ZoneTransferDeclaresTheAxfrFlag()
    {
        // A flag nothing sets is the bug this whole file is about, so pin the mapping
        // as well as the read.
        var deps = RecheckHelper.GetDependencies(Ednsv.Core.Models.CheckCategory.ZoneTransfer);

        Assert.True(deps.HasFlag(RecheckHelper.CacheDep.Axfr));
        Assert.True(RecheckHelper.CacheDep.All.HasFlag(RecheckHelper.CacheDep.Axfr));
    }

    [Fact]
    public void OnlyZoneTransferPullsInTheAxfrFlag()
    {
        // Riding on CacheDep.Dns would have every recheck of anything re-run zone
        // transfers against every nameserver.
        foreach (var category in Enum.GetValues<Ednsv.Core.Models.CheckCategory>())
        {
            if (category == Ednsv.Core.Models.CheckCategory.ZoneTransfer) continue;
            Assert.False(RecheckHelper.GetDependencies(category).HasFlag(RecheckHelper.CacheDep.Axfr),
                $"{category} should not force zone transfers");
        }
    }

    [Fact]
    public async Task RecheckingAxfrRetriesTheTransferInsteadOfServingTheVerdict()
    {
        var dns = new DnsResolverService(nameservers: null, cacheTtl: Ttl);
        Assert.True(dns.TryImportRecord(CacheTypes.Axfr, "127.0.0.1|example.com",
            JsonSerializer.SerializeToNode(true), DateTime.UtcNow.Add(Ttl)));

        Assert.True(await dns.TestZoneTransferAsync(IPAddress.Loopback, "example.com"));

        Rechecking(RecheckHelper.CacheDep.Axfr);
        Assert.False(await dns.TestZoneTransferAsync(IPAddress.Loopback, "example.com"));
    }

    [Fact]
    public async Task AFailedTransferDoesNotOverwriteTheVerdictItCouldNotCheck()
    {
        // The flip side of writing rather than adding: a refused TCP attempt reduces to
        // "no answers", which is indistinguishable from a refused *transfer* once it is
        // a bool. Recording it would turn a real finding into "not vulnerable".
        var dns = new DnsResolverService(nameservers: null, cacheTtl: Ttl);
        Assert.True(dns.TryImportRecord(CacheTypes.Axfr, "127.0.0.1|example.com",
            JsonSerializer.SerializeToNode(true), DateTime.UtcNow.Add(Ttl)));

        Rechecking(RecheckHelper.CacheDep.Axfr);
        Assert.False(await dns.TestZoneTransferAsync(IPAddress.Loopback, "example.com"));
        Rechecking(RecheckHelper.CacheDep.None);

        Assert.True(await dns.TestZoneTransferAsync(IPAddress.Loopback, "example.com"),
            "a transfer that never happened must not be cached as a verdict");
    }

    [Fact]
    public async Task RecheckingAxfrDoesNotSkipSelectorDiscoveryOnAStaleDenial()
    {
        // "AXFR was denied here" is what makes DKIM selector discovery skip the TCP
        // attempt. On a recheck that shortcut has to go too, or the recheck reduces to
        // reading the same cached denial.
        //
        // Both outcomes find no selectors, so the assertion has to be whether the
        // transfer was attempted at all — hence a listener that counts connections.
        using var ns = TcpConnectionCounter.TryStart(53);
        if (ns == null) return;

        var dns = new DnsResolverService(nameservers: null, cacheTtl: Ttl);
        Assert.True(dns.TryImportRecord(CacheTypes.Axfr, "127.0.0.1|example.com",
            JsonSerializer.SerializeToNode(false), DateTime.UtcNow.Add(Ttl)));

        Assert.Empty(await dns.ExtractDkimSelectorsFromAxfrAsync(IPAddress.Loopback, "example.com"));
        Assert.Equal(0, ns.Connections); // the cached denial short-circuits it

        Rechecking(RecheckHelper.CacheDep.Axfr);
        Assert.Empty(await dns.ExtractDkimSelectorsFromAxfrAsync(IPAddress.Loopback, "example.com"));

        Assert.True(ns.Connections > 0, "the recheck should have re-attempted the transfer");
    }

    // ── The unreachable-server breaker in front of the cache ─────────────

    [Fact]
    public async Task RecheckingServerDnsRetriesAServerMarkedUnreachable()
    {
        // The breaker short-circuits before the cache is even consulted, so a recheck
        // of a delegation or NS finding would return the same answer without a query.
        var dns = new DnsResolverService(nameservers: null, cacheTtl: Ttl,
            tuning: new DnsTuning { QueryTimeoutSeconds = 0.3, QueryRetries = 0 });

        // Marked unreachable a moment ago — well inside the five-minute decay window.
        Assert.True(dns.TryImportRecord(CacheTypes.Unreachable, "127.0.0.1",
            JsonSerializer.SerializeToNode(99), DateTime.UtcNow.Add(Ttl)));

        var before = dns.ResponsesReceived;
        await dns.QueryServerAsync(IPAddress.Loopback, "example.com", DnsClient.QueryType.A);
        Assert.Equal(before, dns.ResponsesReceived); // skipped without asking anything

        Rechecking(RecheckHelper.CacheDep.ServerDns);
        await dns.QueryServerAsync(IPAddress.Loopback, "example.com", DnsClient.QueryType.A);

        Assert.True(dns.ResponsesReceived > before, "the recheck should have retried the server");
    }
}
