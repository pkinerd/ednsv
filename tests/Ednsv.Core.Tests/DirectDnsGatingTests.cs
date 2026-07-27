using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// <c>EnableDirectDns</c> covering every check that bypasses the configured resolver.
///
/// <para>The option exists for environments where outbound raw DNS to arbitrary internet
/// IPs is blocked: the checks that query specific authoritative nameservers or public
/// resolvers report themselves skipped instead of timing out. Seven checks are named in
/// the flag's help text, the web tooltips and the docs — but <c>ZoneTransferCheck</c>
/// read only <c>EnableAxfr</c>, so <c>--axfr --no-direct-dns</c> (and the
/// <c>--restricted-network</c> preset, which implies the latter) still sent raw TCP/53
/// zone transfers at every nameserver, which is the one direct-DNS probe that most looks
/// like reconnaissance in someone else's logs.</para>
///
/// <para>These touch no network. The AXFR pair seeds the transfer verdict into the
/// resolver's cache, so the check reaches a definitive "vulnerable" answer without a
/// socket — which is what makes the negative case meaningful: the skip has to come from
/// the gate, not from an empty context that had nothing to report either way.</para>
/// </summary>
public sealed class DirectDnsGatingTests
{
    private const string Domain = "example.com";
    private const string NsHost = "ns1.example.com";
    private const string NsIp = "192.0.2.1";          // TEST-NET-1: never routable
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);

    /// <summary>
    /// A context whose AXFR verdict for <see cref="NsIp"/> is already cached as
    /// vulnerable, so <c>ZoneTransferCheck</c> can reach a finding offline.
    /// </summary>
    private static CheckContext ContextWithCachedTransfer(bool enableDirectDns)
    {
        var dns = new DnsResolverService(nameservers: null, cacheTtl: Ttl);
        Assert.True(dns.TryImportRecord(CacheTypes.Axfr, $"{NsIp}|{Domain}",
            JsonSerializer.SerializeToNode(true), DateTime.UtcNow.Add(Ttl)));

        return new CheckContext
        {
            Dns = dns,
            Options = new ValidationOptions { EnableAxfr = true, EnableDirectDns = enableDirectDns },
            NsHosts = new[] { NsHost },
            NsHostIps = new ConcurrentDictionary<string, List<string>>
            {
                [NsHost] = new() { NsIp }
            }
        };
    }

    [Fact]
    public async Task ZoneTransferIsSkippedWhenDirectDnsIsDisabled()
    {
        var results = await new ZoneTransferCheck()
            .RunAsync(Domain, ContextWithCachedTransfer(enableDirectDns: false));

        var result = Assert.Single(results);
        Assert.Equal(CheckSeverity.Info, result.Severity);
        Assert.Contains("direct DNS", result.Summary);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task ZoneTransferStillRunsWhenDirectDnsIsEnabled()
    {
        // The control for the case above: same context, gate open, and the check reports
        // the transfer it was always meant to report. Without this, a check that silently
        // stopped finding anything would pass the skip assertion just as well.
        var results = await new ZoneTransferCheck()
            .RunAsync(Domain, ContextWithCachedTransfer(enableDirectDns: true));

        var result = Assert.Single(results);
        Assert.Equal(CheckSeverity.Critical, result.Severity);
        Assert.Contains(result.Errors, e => e.Contains("AXFR") && e.Contains(NsIp));
    }

    public static TheoryData<string, ICheck> DirectDnsChecks() => new()
    {
        { "propagation",       new DnsPropagationCheck() },
        { "lame delegation",   new NsLameDelegationCheck() },
        { "SOA serial",        new SoaSerialConsistencyCheck() },
        { "glue records",      new NsGlueRecordCheck() },
        { "parent delegation", new DelegationConsistencyCheck() },
        { "open resolver",     new OpenRecursiveResolverCheck() },
        { "AXFR",              new ZoneTransferCheck() },
    };

    [Theory]
    [MemberData(nameof(DirectDnsChecks))]
    public async Task EveryDirectDnsCheckReportsItselfSkipped(string label, ICheck check)
    {
        // The list the CLI's --no-direct-dns help, both web tooltips and docs/configuration.md
        // all promise. Each has to bail before its first query — Dns is left null here, so a
        // check that reaches the network at all fails with a NullReferenceException.
        var ctx = new CheckContext
        {
            Options = new ValidationOptions
            {
                EnableDirectDns = false,
                // Both opt-in probes on, so neither is skipped for the lesser reason.
                EnableAxfr = true,
                EnableOpenResolver = true,
                // DoH substitutes for the propagation check specifically; off, or it
                // would legitimately run without direct DNS.
                EnableDoh = false,
            },
            NsHosts = new[] { NsHost },
            NsHostIps = new ConcurrentDictionary<string, List<string>>
            {
                [NsHost] = new() { NsIp }
            }
        };

        var result = Assert.Single(await check.RunAsync(Domain, ctx));

        Assert.Equal(CheckSeverity.Info, result.Severity);
        Assert.True(result.Summary.StartsWith("Skipped:", StringComparison.Ordinal),
            $"{label} ({check.Name}) did not skip: {result.Summary}");
    }
}
