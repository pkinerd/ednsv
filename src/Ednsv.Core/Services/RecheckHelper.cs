using Ednsv.Core.Models;

namespace Ednsv.Core.Services;

/// <summary>
/// Orchestrates selective cache bypass for the --recheck feature.
/// Maps check categories to cache dependencies. In multi-user mode (web API),
/// services bypass MemoryCache for the current validation's recheck deps
/// without clearing shared entries that other users depend on.
/// </summary>
public static class RecheckHelper
{
    /// <summary>
    /// Per-async-flow recheck context. Set by DomainValidator at validation start,
    /// read by service cache lookups. Flows through async calls automatically.
    /// Each concurrent validation has its own value — no cross-user bleed.
    /// </summary>
    public static readonly AsyncLocal<CacheDep> CurrentRecheckDeps = new();
    [Flags]
    public enum CacheDep
    {
        None = 0,
        Dns = 1,
        ServerDns = 2,
        Ptr = 4,
        Smtp = 8,
        Port = 16,
        Rcpt = 32,
        Http = 64,
        All = Dns | ServerDns | Ptr | Smtp | Port | Rcpt | Http
    }

    /// <summary>
    /// Maps a check category to the cache types it depends on.
    /// </summary>
    public static CacheDep GetDependencies(CheckCategory category) => category switch
    {
        CheckCategory.Delegation => CacheDep.Dns | CacheDep.ServerDns | CacheDep.Ptr,
        CheckCategory.SOA => CacheDep.Dns | CacheDep.ServerDns,
        CheckCategory.NS => CacheDep.Dns | CacheDep.ServerDns,
        CheckCategory.CNAME => CacheDep.Dns,
        CheckCategory.A => CacheDep.Dns,
        CheckCategory.AAAA => CacheDep.Dns,
        CheckCategory.MX => CacheDep.Dns | CacheDep.Smtp | CacheDep.Ptr,
        CheckCategory.SPF => CacheDep.Dns,
        CheckCategory.DMARC => CacheDep.Dns,
        CheckCategory.DKIM => CacheDep.Dns,
        CheckCategory.PTR => CacheDep.Dns | CacheDep.Ptr,
        CheckCategory.FCrDNS => CacheDep.Dns | CacheDep.Ptr,
        CheckCategory.DNSBL => CacheDep.Dns,
        CheckCategory.DomainBL => CacheDep.Dns,
        CheckCategory.DNSSEC => CacheDep.Dns,
        CheckCategory.MTASTS => CacheDep.Dns | CacheDep.Http,
        CheckCategory.TLSRPT => CacheDep.Dns,
        CheckCategory.BIMI => CacheDep.Dns | CacheDep.Http,
        CheckCategory.DANE => CacheDep.Dns | CacheDep.Smtp,
        CheckCategory.SMTP => CacheDep.Dns | CacheDep.Smtp | CacheDep.Port,
        CheckCategory.SRV => CacheDep.Dns,
        CheckCategory.Autodiscover => CacheDep.Dns | CacheDep.Http,
        CheckCategory.CAA => CacheDep.Dns,
        CheckCategory.IPv6 => CacheDep.Dns | CacheDep.Smtp,
        CheckCategory.Postmaster => CacheDep.Rcpt,
        CheckCategory.Abuse => CacheDep.Rcpt,
        CheckCategory.Wildcard => CacheDep.Dns,
        CheckCategory.TTL => CacheDep.Dns,
        CheckCategory.ZoneTransfer => CacheDep.Dns,
        CheckCategory.SecurityTxt => CacheDep.Http,
        CheckCategory.TXT => CacheDep.Dns,
        _ => CacheDep.Dns
    };

    /// <summary>
    /// Determines which cache types need clearing for a domain based on its
    /// previous check results and the recheck severity threshold.
    /// </summary>
    public static CacheDep GetDependenciesForIssues(DomainResultSummary summary, CheckSeverity minSeverity)
    {
        var deps = CacheDep.None;
        foreach (var issue in summary.IssueChecks)
        {
            if (Enum.TryParse<CheckCategory>(issue.Category, out var cat) &&
                Enum.TryParse<CheckSeverity>(issue.Severity, out var sev) &&
                sev >= minSeverity)
            {
                deps |= GetDependencies(cat);
            }
        }
        return deps;
    }

    /// <summary>
    /// Clears cache entries for a domain based on the cache dependency flags.
    /// When importedOnly is true (default, used by CLI), only entries loaded from
    /// disk are cleared — entries generated during the current process run are
    /// preserved. When false (used by web API), all matching entries are cleared
    /// including those from previous requests in the same long-lived process.
    /// </summary>
    public static void ClearEntriesForDomain(
        string domain, CacheDep deps,
        DnsResolverService dns, SmtpProbeService smtp, HttpProbeService http,
        bool importedOnly = true)
    {
        var domainLower = domain.ToLowerInvariant();

        // Collect MX hosts and IPs before clearing DNS (needed for SMTP/Port/RCPT/PTR clearing)
        var mxHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var mxIps = new HashSet<string>();

        if (deps.HasFlag(CacheDep.Smtp) || deps.HasFlag(CacheDep.Port) ||
            deps.HasFlag(CacheDep.Rcpt) || deps.HasFlag(CacheDep.Ptr))
        {
            foreach (var host in dns.GetCachedMxHosts(domain))
            {
                mxHosts.Add(host);
                foreach (var ip in dns.GetCachedIps(host))
                    mxIps.Add(ip);
            }
            // Also include the domain itself (A/AAAA records)
            foreach (var ip in dns.GetCachedIps(domain))
                mxIps.Add(ip);
        }

        // DNS query cache: clear entries where the query domain matches or is a subdomain
        if (deps.HasFlag(CacheDep.Dns))
        {
            dns.RemoveQueryEntries((d, _) =>
                d.Equals(domainLower, StringComparison.OrdinalIgnoreCase) ||
                d.EndsWith("." + domainLower, StringComparison.OrdinalIgnoreCase) ||
                d.EndsWith("._domainkey." + domainLower, StringComparison.OrdinalIgnoreCase),
                importedOnly);
        }

        // Server-specific DNS queries
        if (deps.HasFlag(CacheDep.ServerDns))
        {
            dns.RemoveServerQueryEntries((_, d, _2) =>
                d.Equals(domainLower, StringComparison.OrdinalIgnoreCase) ||
                d.EndsWith("." + domainLower, StringComparison.OrdinalIgnoreCase),
                importedOnly);
        }

        // PTR lookups for MX IPs
        if (deps.HasFlag(CacheDep.Ptr) && mxIps.Count > 0)
        {
            dns.RemovePtrEntries(ip => mxIps.Contains(ip), importedOnly);
        }

        // SMTP probes for MX hosts (keyed as "host:port")
        if (deps.HasFlag(CacheDep.Smtp) && mxHosts.Count > 0)
        {
            smtp.RemoveProbeEntries(key =>
                mxHosts.Any(h => key.StartsWith(h + ":", StringComparison.OrdinalIgnoreCase)),
                importedOnly);
            smtp.RemoveRelayEntries(key =>
                key.Contains("|" + domainLower, StringComparison.OrdinalIgnoreCase) ||
                mxHosts.Any(h => key.Contains(h, StringComparison.OrdinalIgnoreCase)),
                importedOnly);
        }

        // Port probes for MX hosts
        if (deps.HasFlag(CacheDep.Port) && mxHosts.Count > 0)
        {
            smtp.RemovePortEntries(key =>
                mxHosts.Any(h => key.StartsWith(h + ":", StringComparison.OrdinalIgnoreCase)),
                importedOnly);
        }

        // RCPT probes (keyed as "host:email")
        if (deps.HasFlag(CacheDep.Rcpt))
        {
            smtp.RemoveRcptEntries(key =>
                key.Contains("@" + domainLower, StringComparison.OrdinalIgnoreCase) ||
                (mxHosts.Count > 0 && mxHosts.Any(h => key.StartsWith(h + ":", StringComparison.OrdinalIgnoreCase))),
                importedOnly);
        }

        // HTTP entries for URLs containing the domain
        if (deps.HasFlag(CacheDep.Http))
        {
            http.RemoveGetEntries(url =>
                url.Contains(domainLower, StringComparison.OrdinalIgnoreCase),
                importedOnly);
            http.RemoveGetWithHeadersEntries(url =>
                url.Contains(domainLower, StringComparison.OrdinalIgnoreCase),
                importedOnly);
        }
    }

    /// <summary>
    /// Backward-compatible alias — clears only imported (from-disk) entries.
    /// </summary>
    public static void ClearImportedEntriesForDomain(
        string domain, CacheDep deps,
        DnsResolverService dns, SmtpProbeService smtp, HttpProbeService http)
        => ClearEntriesForDomain(domain, deps, dns, smtp, http, importedOnly: true);
}
