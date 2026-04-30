using System.Collections.Concurrent;
using DnsClient;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public interface ICheck
{
    string Name { get; }
    CheckCategory Category { get; }
    Task<List<CheckResult>> RunAsync(string domain, CheckContext context, CancellationToken cancellationToken = default);
}

public class CheckContext
{
    public Services.DnsResolverService Dns { get; set; } = null!;
    public Services.SmtpProbeService Smtp { get; set; } = null!;
    public Services.HttpProbeService Http { get; set; } = null!;

    // Options
    public ValidationOptions Options { get; set; } = new();

    // Shared state between checks — written by foundation (sequential),
    // read-only during concurrent phase. IReadOnlyList ensures concurrent
    // checks cannot accidentally mutate shared state. Foundation checks
    // build a local List then assign the completed list to these properties.
    public IReadOnlyList<string> MxHosts { get; set; } = Array.Empty<string>();
    public ConcurrentDictionary<string, List<string>> MxHostIps { get; set; } = new();
    public IReadOnlyList<string> NsHosts { get; set; } = Array.Empty<string>();
    public ConcurrentDictionary<string, List<string>> NsHostIps { get; set; } = new();
    public string? SpfRecord { get; set; }
    public string? DmarcRecord { get; set; }
    public IReadOnlyList<string> DomainARecords { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> DomainAAAARecords { get; set; } = Array.Empty<string>();

    // Flags indicating whether foundation lookups had transient failures
    // (SERVFAIL/timeout) vs simply returned empty results or NXDOMAIN.
    // When true, downstream checks report Warning (uncertain) instead of
    // Info (definitively absent). NXDOMAIN is treated as definitive absence
    // (the domain doesn't exist), NOT as a transient lookup failure.
    public bool MxLookupFailed { get; set; }
    public bool NsLookupFailed { get; set; }
    public bool SpfLookupFailed { get; set; }
    public bool DmarcLookupFailed { get; set; }

    /// <summary>
    /// Returns Warning if the lookup for this prerequisite had a transient
    /// failure (SERVFAIL/timeout), or Info if the record is simply absent.
    /// NXDOMAIN does NOT set lookupFailed — it's a definitive answer.
    /// </summary>
    public CheckSeverity SeverityForMissing(bool lookupFailed) =>
        lookupFailed ? CheckSeverity.Warning : CheckSeverity.Info;

    /// <summary>
    /// Returns true if the DNS response indicates the domain does not exist
    /// (NXDOMAIN / RCODE 3). This is a definitive answer, not a transient
    /// failure — checks should report Error, not Warning.
    /// </summary>
    public static bool IsNxDomain(IDnsQueryResponse response)
    {
        if (!response.HasError) return false;
        try
        {
            return response.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain;
        }
        catch
        {
            // CachedDnsResponse doesn't implement Header — check ErrorMessage
            return response.ErrorMessage?.Contains("NotExistentDomain", StringComparison.OrdinalIgnoreCase) == true
                || response.ErrorMessage?.Contains("Non-Existent", StringComparison.OrdinalIgnoreCase) == true;
        }
    }

    // Cached SMTP probe results (avoid probing same host multiple times).
    // ConcurrentDictionary because concurrent checks may read/write simultaneously.
    // Populated during prefetch; checks should use GetOrProbeSmtpAsync().
    public ConcurrentDictionary<string, Services.SmtpProbeResult> SmtpProbeCache { get; set; } = new();

    /// <summary>
    /// Get an SMTP probe result from the per-validation cache, or probe and cache it.
    /// All checks should use this instead of calling Smtp.ProbeSmtpAsync directly
    /// to avoid redundant probes — especially during recheck where the service-level
    /// MemoryCache is bypassed.
    /// </summary>
    public async Task<Services.SmtpProbeResult> GetOrProbeSmtpAsync(string host, int port = 25)
    {
        var key = port == 25 ? host : $"{host}:{port}";
        if (SmtpProbeCache.TryGetValue(key, out var cached))
        {
            Smtp.Trace?.Invoke($"[SMTP] CTX-CACHE HIT {host}:{port}");
            return cached;
        }
        Smtp.Trace?.Invoke($"[SMTP] CTX-CACHE MISS {host}:{port} (will probe)");
        var probe = await Smtp.ProbeSmtpAsync(host, port);
        SmtpProbeCache.TryAdd(key, probe);
        return probe;
    }

    // Per-validation recheck context — when set, service cache lookups bypass
    // MemoryCache for matching cache types, forcing fresh queries without
    // clearing shared cache entries that other concurrent users depend on.
    // Uses AsyncLocal so it flows through async calls to singleton services.
    public Services.RecheckHelper.CacheDep RecheckDeps { get; set; }

    // Per-validation diagnostic counters — thread-safe, not shared across validations.
    public ConcurrentBag<string> QueryErrors { get; } = new();

    /// <summary>
    /// Build a single Info-severity result indicating a check was skipped because
    /// its network category is disabled (--no-smtp / --no-http / --no-dnsbl).
    /// </summary>
    public static List<CheckResult> SkippedResult(ICheck check, string reason) =>
        new() { new CheckResult { CheckName = check.Name, Category = check.Category, Severity = CheckSeverity.Info, Summary = reason } };
}

public class ValidationOptions
{
    public bool EnableAxfr { get; set; } = false;
    public bool EnableCatchAll { get; set; } = false;
    public bool EnableOpenRelay { get; set; } = false;
    public bool EnableOpenResolver { get; set; } = false;
    public string OpenResolverTestDomain { get; set; } = "www.google.com";
    public List<string> AdditionalDkimSelectors { get; set; } = new();
    /// <summary>
    /// Include blocklists that require a private/registered DNS resolver
    /// (e.g. Spamhaus, Barracuda, SURBL, URIBL). These return false positives
    /// or refuse queries from public resolvers like Google/Cloudflare.
    /// </summary>
    public bool EnablePrivateDnsbl { get; set; } = false;

    // Network-category toggles (default ON; flip off in restricted environments
    // where outbound SMTP / HTTP / public DNSBL queries are blocked).
    public bool EnableSmtpProbes { get; set; } = true;
    public bool EnableHttpProbes { get; set; } = true;
    public bool EnableDnsbl { get; set; } = true;
}
