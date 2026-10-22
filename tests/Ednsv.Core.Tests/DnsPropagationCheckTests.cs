using System.Diagnostics;
using System.Net;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The propagation check on a network that blocks the public resolvers.
///
/// <para>Reported from a real deployment: the check ran for 3m 38s, then passed with
/// "DNS answers consistent across resolvers" over three lines of <c>A=[] MX=[]</c>.
/// Two defects. A resolver that never answered was read as one that answered "nothing",
/// so three failures agreed with each other and the check passed. And the six queries
/// ran one after another on the tuned default of 15s with two retries, ignoring the
/// check's cancellation token, so a firewall cost about 45s per query.</para>
///
/// <para>Neither resolver here can answer: loopback:53 refuses (nothing listens there,
/// in a sandbox or in CI), and 192.0.2.1 is TEST-NET-1, which nothing routes, so its
/// packets vanish and only a timeout ends the wait — the firewall case.</para>
/// </summary>
public sealed class DnsPropagationCheckTests
{
    private static CheckContext Context(ValidationOptions options) => new()
    {
        Dns = new DnsResolverService(new[] { IPAddress.Loopback }),
        Options = options,
    };

    private static ValidationOptions Unreachable() => new()
    {
        PropagationResolvers = new() { "127.0.0.1|Refusing", "192.0.2.1|Blackhole" },
    };

    [Fact]
    public async Task UnreachableResolvers_WarnInsteadOfPassing_AndDoNotTakeMinutes()
    {
        var sw = Stopwatch.StartNew();
        var r = Assert.Single(await new DnsPropagationCheck().RunAsync("example.com", Context(Unreachable())));
        sw.Stop();

        Assert.Equal(CheckSeverity.Warning, r.Severity);
        Assert.Equal("No public resolver reachable over UDP/53 — propagation not checked", r.Summary);
        Assert.Contains("Refusing (127.0.0.1): no response", r.Details);
        Assert.Contains("Blackhole (192.0.2.1): no response", r.Details);
        // One short-capped round in parallel: a few seconds. The old sequential path
        // spent ~45s on each query to the blackhole alone.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"took {sw.Elapsed.TotalSeconds:F1}s");
    }

    [Fact]
    public async Task PublicResolversOff_SkipsOnlyThisCheck()
    {
        var options = Unreachable();
        options.EnablePublicResolvers = false;
        var r = Assert.Single(await new DnsPropagationCheck().RunAsync("example.com", Context(options)));

        Assert.Equal(CheckSeverity.Info, r.Severity);
        Assert.StartsWith("Skipped: public resolvers", r.Summary);
    }

    [Fact]
    public async Task DirectDnsOff_StillSkipsRegardlessOfTheNewFlag()
    {
        // The new flag narrows the old one. A caller that only knows EnableDirectDns —
        // an older client, a config written before the split — must keep skipping.
        var options = Unreachable();
        options.EnableDirectDns = false;
        var r = Assert.Single(await new DnsPropagationCheck().RunAsync("example.com", Context(options)));

        Assert.StartsWith("Skipped: direct DNS to public resolvers disabled", r.Summary);
    }
}

/// <summary>
/// Resolvers that answer, seeded into the server-query cache through the same import
/// path the disk and Redis tiers use, so the check sees real answers with no DNS server.
///
/// <para>The interception case is the one that matters: a firewall that answers for
/// the public resolvers instead of dropping their packets returns a prompt NXDOMAIN
/// from all of them. They agree, so it used to pass. Checked against the configured
/// resolver's view, which saw the domain's MX, it is a warning.</para>
/// </summary>
public sealed class DnsPropagationAnswerTests
{
    private const string Domain = "example.com";
    private static readonly string[] Resolvers = { "192.0.2.10", "192.0.2.11" };

    private static void Seed(DnsResolverService dns, string ip, string type, int rcode, params DnsCacheRecord[] answers)
    {
        var entry = new DnsCacheEntry { ResponseCode = rcode, HasError = rcode != 0, Answers = answers.ToList() };
        Assert.True(dns.TryImportRecord(CacheTypes.DnsServer, $"sq:{ip}:{Domain}:{type}",
            System.Text.Json.JsonSerializer.SerializeToNode(entry), DateTime.UtcNow.AddMinutes(10)));
    }

    private static DnsCacheRecord A(string ip) => new() { Name = Domain, Type = "A", Ttl = 300, Data = { ["Address"] = ip } };
    private static DnsCacheRecord Mx(string host) => new()
        { Name = Domain, Type = "MX", Ttl = 300, Data = { ["Preference"] = "10", ["Exchange"] = host } };

    private static async Task<CheckResult> RunAsync(DnsResolverService dns, params string[] mxHosts)
    {
        var ctx = new CheckContext
        {
            Dns = dns,
            MxHosts = mxHosts,
            Options = new ValidationOptions { PropagationResolvers = Resolvers.Select(r => $"{r}|R{r[^2..]}").ToList() },
        };
        return Assert.Single(await new DnsPropagationCheck().RunAsync(Domain, ctx));
    }

    [Fact]
    public async Task InterceptedNxdomain_WhileTheConfiguredResolverSeesMx_Warns()
    {
        var dns = new DnsResolverService(new[] { IPAddress.Loopback });
        foreach (var ip in Resolvers) { Seed(dns, ip, "A", 3); Seed(dns, ip, "MX", 3); }

        var r = await RunAsync(dns, "mx.example.com");

        Assert.Equal(CheckSeverity.Warning, r.Severity);
        Assert.Equal("Public resolvers return no A or MX records, but the configured resolver does", r.Summary);
    }

    [Fact]
    public async Task NothingPublishedAnywhere_IsInfoNotPass()
    {
        var dns = new DnsResolverService(new[] { IPAddress.Loopback });
        foreach (var ip in Resolvers) { Seed(dns, ip, "A", 3); Seed(dns, ip, "MX", 3); }

        var r = await RunAsync(dns);

        Assert.Equal(CheckSeverity.Info, r.Severity);
        Assert.Equal("No A or MX records from any resolver — nothing to compare", r.Summary);
    }

    [Fact]
    public async Task MatchingAnswers_Pass()
    {
        var dns = new DnsResolverService(new[] { IPAddress.Loopback });
        foreach (var ip in Resolvers) { Seed(dns, ip, "A", 0, A("192.0.2.80")); Seed(dns, ip, "MX", 0, Mx("mx.example.com")); }

        var r = await RunAsync(dns, "mx.example.com");

        Assert.Equal(CheckSeverity.Pass, r.Severity);
        Assert.Equal("DNS answers consistent across resolvers (UDP/53)", r.Summary);
    }

    [Fact]
    public async Task OneResolverDown_OthersAgree_IsPartialNotInconsistent()
    {
        var dns = new DnsResolverService(new[] { IPAddress.Loopback });
        Seed(dns, Resolvers[0], "A", 0, A("192.0.2.80"));
        Seed(dns, Resolvers[0], "MX", 0, Mx("mx.example.com"));
        Seed(dns, Resolvers[1], "A", 2);   // SERVFAIL: answered, but not with an answer
        Seed(dns, Resolvers[1], "MX", 2);

        var r = await RunAsync(dns, "mx.example.com");

        Assert.Equal(CheckSeverity.Warning, r.Severity);
        Assert.Equal("DNS answers consistent across the reachable resolvers (UDP/53)", r.Summary);
        Assert.Contains(r.Warnings, w => w.StartsWith("Only 1/2 public resolvers responded", StringComparison.Ordinal));
    }
}
