namespace Ednsv.Core.Models;

public enum CheckSeverity
{
    Info,
    Pass,
    Warning,
    Error,
    Critical
}

public enum CheckCategory
{
    Delegation,
    SOA,
    NS,
    CNAME,
    A,
    AAAA,
    MX,
    SPF,
    DMARC,
    DKIM,
    PTR,
    FCrDNS,
    DNSBL,
    DomainBL,
    DNSSEC,
    MTASTS,
    TLSRPT,
    BIMI,
    DANE,
    SMTP,
    SRV,
    Autodiscover,
    CAA,
    IPv6,
    Postmaster,
    Abuse,
    Wildcard,
    TTL,
    ZoneTransfer,
    SecurityTxt,
    TXT
}

public class CheckResult
{
    public string CheckName { get; set; } = "";
    public CheckCategory Category { get; set; }
    public CheckSeverity Severity { get; set; }
    public string Summary { get; set; } = "";
    public List<string> Details { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> Errors { get; set; } = new();

    /// <summary>
    /// If this check would report Pass but some or all hosts were unreachable,
    /// downgrades to Warning. Call this after setting Severity and Summary.
    /// </summary>
    public void AdjustForUnreachableHosts(int totalHosts, int unreachableCount)
    {
        if (unreachableCount <= 0 || totalHosts <= 0) return;

        if (unreachableCount >= totalHosts && Severity == CheckSeverity.Pass)
        {
            Severity = CheckSeverity.Warning;
            Summary = $"Could not connect to any MX host — {Summary}";
        }
        else if (unreachableCount > 0 && Severity == CheckSeverity.Pass)
        {
            Severity = CheckSeverity.Warning;
            Summary = $"{unreachableCount}/{totalHosts} MX host(s) unreachable — {Summary}";
        }
    }
}

public class ValidationReport
{
    public string Domain { get; set; } = "";
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public TimeSpan Duration { get; set; }
    public List<CheckResult> Results { get; set; } = new();

    public int PassCount => Results.Count(r => r.Severity == CheckSeverity.Pass);
    public int WarningCount => Results.Count(r => r.Severity == CheckSeverity.Warning);
    public int ErrorCount => Results.Count(r => r.Severity == CheckSeverity.Error);
    public int CriticalCount => Results.Count(r => r.Severity == CheckSeverity.Critical);
}
