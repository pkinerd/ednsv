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

    // Shared state between checks
    public List<string> MxHosts { get; set; } = new();
    public Dictionary<string, List<string>> MxHostIps { get; set; } = new();
    public List<string> NsHosts { get; set; } = new();
    public Dictionary<string, List<string>> NsHostIps { get; set; } = new();
    public string? SpfRecord { get; set; }
    public string? DmarcRecord { get; set; }
    public List<string> DomainARecords { get; set; } = new();
    public List<string> DomainAAAARecords { get; set; } = new();
    // Cached SMTP probe results (avoid probing same host multiple times)
    public Dictionary<string, Services.SmtpProbeResult> SmtpProbeCache { get; set; } = new();
}

public class ValidationOptions
{
    public bool EnableAxfr { get; set; } = true;
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
