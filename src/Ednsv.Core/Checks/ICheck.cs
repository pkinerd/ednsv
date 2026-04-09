using System.Collections.Concurrent;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public interface ICheck
{
    string Name { get; }
    CheckCategory Category { get; }
    Task<List<CheckResult>> RunAsync(string domain, CheckContext context);
}

public class CheckContext
{
    public Services.DnsResolverService Dns { get; set; } = null!;
    public Services.SmtpProbeService Smtp { get; set; } = null!;
    public Services.HttpProbeService Http { get; set; } = null!;

    // Options
    public ValidationOptions Options { get; set; } = new();

    // Shared state between checks — written by foundation (sequential),
    // read-only during concurrent phase. Thread-safe collections used as
    // a safety net even though the write→read ordering is guaranteed.
    public List<string> MxHosts { get; set; } = new();
    public ConcurrentDictionary<string, List<string>> MxHostIps { get; set; } = new();
    public List<string> NsHosts { get; set; } = new();
    public ConcurrentDictionary<string, List<string>> NsHostIps { get; set; } = new();
    public string? SpfRecord { get; set; }
    public string? DmarcRecord { get; set; }
    public List<string> DomainARecords { get; set; } = new();
    public List<string> DomainAAAARecords { get; set; } = new();

    // Flags indicating whether foundation lookups failed (DNS error/timeout)
    // vs simply returned empty results (record not configured). When true,
    // downstream checks should report Warning instead of Info.
    public bool MxLookupFailed { get; set; }
    public bool NsLookupFailed { get; set; }
    public bool SpfLookupFailed { get; set; }
    public bool DmarcLookupFailed { get; set; }

    /// <summary>
    /// Returns Warning if the lookup for this prerequisite failed (DNS error),
    /// or Info if the record simply doesn't exist.
    /// </summary>
    public CheckSeverity SeverityForMissing(bool lookupFailed) =>
        lookupFailed ? CheckSeverity.Warning : CheckSeverity.Info;

    // Cached SMTP probe results (avoid probing same host multiple times).
    // ConcurrentDictionary because concurrent checks may read/write simultaneously.
    public ConcurrentDictionary<string, Services.SmtpProbeResult> SmtpProbeCache { get; set; } = new();

    // Per-validation recheck context — when set, service cache lookups bypass
    // MemoryCache for matching cache types, forcing fresh queries without
    // clearing shared cache entries that other concurrent users depend on.
    // Uses AsyncLocal so it flows through async calls to singleton services.
    public Services.RecheckHelper.CacheDep RecheckDeps { get; set; }

    // Per-validation diagnostic counters — thread-safe, not shared across validations.
    public ConcurrentBag<string> QueryErrors { get; } = new();
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
}
