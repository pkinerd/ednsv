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

}
