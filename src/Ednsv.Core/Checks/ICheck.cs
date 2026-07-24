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

    /// <summary>
    /// Caller-supplied DKIM selector list. By default this is used only when
    /// the domain has no per-domain entry in <see cref="PerDomainDkimSelectors"/>;
    /// set <see cref="ForceDkimSelectors"/> to make it win even over per-domain config.
    /// When non-empty it replaces the built-in/default list rather than augmenting it.
    /// </summary>
    public List<string> AdditionalDkimSelectors { get; set; } = new();

    /// <summary>
    /// When true, <see cref="AdditionalDkimSelectors"/> overrides any per-domain
    /// DKIM config. When false (default), per-domain config wins.
    /// </summary>
    public bool ForceDkimSelectors { get; set; } = false;

    /// <summary>
    /// Per-domain DKIM selector overrides keyed by lowercase bare domain name.
    /// When the domain being validated has an entry, those selectors are used
    /// instead of the default list.
    /// </summary>
    public Dictionary<string, List<string>> PerDomainDkimSelectors { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

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

    /// <summary>
    /// Allow checks to talk directly to specific authoritative nameservers and
    /// public resolvers (propagation, lame delegation, SOA-serial consistency,
    /// glue records, parent-side delegation, open-recursive-resolver, AXFR).
    /// When false, those checks are skipped and the regular configured resolver
    /// is the only DNS path used.
    /// </summary>
    public bool EnableDirectDns { get; set; } = true;

    /// <summary>
    /// When true, the public-resolver propagation check (Google + Cloudflare)
    /// uses DNS-over-HTTPS instead of raw UDP/53. Routes through HTTPS_PROXY
    /// when configured. The other direct-DNS checks have no DoH equivalent.
    /// </summary>
    public bool EnableDoh { get; set; } = false;

    // ── Configurable probe data lists (web-admin editable) ───────────────
    // Each defaults to an empty list; checks fall back to their built-in
    // defaults when empty, so an unset option preserves original behaviour.
    // Labeled entries use the "value|label" convention (e.g. "8.8.8.8|Google");
    // the label is the display name used in report output. Plain lists carry
    // just the value on each line.

    /// <summary>Public resolvers compared by the propagation check ("ip|label").</summary>
    public List<string> PropagationResolvers { get; set; } = new();
    /// <summary>DoH JSON endpoints for the propagation check ("url|label").</summary>
    public List<string> PropagationDohResolvers { get; set; } = new();
    /// <summary>Basic IP DNSBL zones queryable via public resolvers ("zone|label").</summary>
    public List<string> IpBlocklistsPublic { get; set; } = new();
    /// <summary>Basic IP DNSBL zones needing a private resolver ("zone|label").</summary>
    public List<string> IpBlocklistsPrivate { get; set; } = new();
    /// <summary>Extended IP DNSBL zones queryable via public resolvers ("zone|label").</summary>
    public List<string> ExtendedIpBlocklistsPublic { get; set; } = new();
    /// <summary>Extended IP DNSBL zones needing a private resolver ("zone|label").</summary>
    public List<string> ExtendedIpBlocklistsPrivate { get; set; } = new();
    /// <summary>RHSBL/domain blocklist zones (private resolver required).</summary>
    public List<string> DomainBlocklists { get; set; } = new();
    /// <summary>Selector names probed for ARC/DKIM keys.</summary>
    public List<string> ArcSelectors { get; set; } = new();
    /// <summary>Subdomains probed for their own DMARC records.</summary>
    public List<string> DmarcDiscoverySubdomains { get; set; } = new();
    /// <summary>Subdomains surveyed for mail-related DNS records.</summary>
    public List<string> MailSurveySubdomains { get; set; } = new();
    /// <summary>Mail-sending subdomains checked for SPF coverage gaps.</summary>
    public List<string> SpfSubdomains { get; set; } = new();
    /// <summary>SRV service labels probed for mail service discovery.</summary>
    public List<string> SrvServiceNames { get; set; } = new();
    /// <summary>CA names recognised as authorised BIMI VMC issuers.</summary>
    public List<string> VmcIssuers { get; set; } = new();
    /// <summary>Base URL of the Certificate Transparency (crt.sh) endpoint.</summary>
    public string? CrtShBaseUrl { get; set; }
}

/// <summary>
/// Helpers for resolving a configurable probe list against a built-in default.
/// An empty/absent configured list falls back to the default, so unset options
/// preserve original behaviour.
/// </summary>
public static class ProbeList
{
    /// <summary>
    /// Parse "value|label" lines into tuples. Lines without a '|' use the value
    /// as its own label. Falls back to <paramref name="fallback"/> when the
    /// configured list is empty or contains no usable entries.
    /// </summary>
    public static List<(string value, string label)> Labeled(
        IReadOnlyList<string>? configured, IReadOnlyList<string> fallback)
    {
        var parsed = ParseLabeled(configured);
        return parsed.Count > 0 ? parsed : ParseLabeled(fallback);
    }

    private static List<(string value, string label)> ParseLabeled(IReadOnlyList<string>? src)
    {
        var list = new List<(string value, string label)>();
        if (src == null) return list;
        foreach (var line in src)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var idx = line.IndexOf('|');
            var value = (idx < 0 ? line : line[..idx]).Trim();
            var label = (idx < 0 ? line : line[(idx + 1)..]).Trim();
            if (value.Length == 0) continue;
            list.Add((value, label.Length == 0 ? value : label));
        }
        return list;
    }

    /// <summary>Return the configured plain list, or the fallback when empty.</summary>
    public static IReadOnlyList<string> OrDefault(IReadOnlyList<string>? configured, IReadOnlyList<string> fallback)
        => configured != null && configured.Count > 0 ? configured : fallback;

    /// <summary>Normalise a configured crt.sh base URL (fallback when blank, always trailing '/').</summary>
    public static string CrtShBase(string? configured)
    {
        var b = string.IsNullOrWhiteSpace(configured) ? ProbeDefaults.CrtShBaseUrl : configured.Trim();
        return b.EndsWith('/') ? b : b + "/";
    }
}

/// <summary>
/// Built-in default probe data lists — the single source of truth shared by the
/// checks (as the fallback when an option is unset) and by the web
/// <c>AppConfig</c> seed (so the admin UI shows the real defaults). Labeled
/// lists use the "value|label" convention.
/// </summary>
public static class ProbeDefaults
{
    public static readonly IReadOnlyList<string> PropagationResolvers = new[]
        { "8.8.8.8|Google", "1.1.1.1|Cloudflare", "9.9.9.9|Quad9" };

    public static readonly IReadOnlyList<string> PropagationDohResolvers = new[]
        { "https://dns.google/resolve|Google (DoH)", "https://cloudflare-dns.com/dns-query|Cloudflare (DoH)" };

    public static readonly IReadOnlyList<string> IpBlocklistsPublic = new[] { "bl.spamcop.net" };

    public static readonly IReadOnlyList<string> IpBlocklistsPrivate = new[]
        { "zen.spamhaus.org", "b.barracudacentral.org" };

    public static readonly IReadOnlyList<string> ExtendedIpBlocklistsPublic = new[]
    {
        "all.s5h.net|S5H",
        "dnsbl.sorbs.net|SORBS Combined",
        "spam.dnsbl.sorbs.net|SORBS Spam",
        "bl.mailspike.net|Mailspike",
        "dnsbl-1.uceprotect.net|UCEProtect L1",
        "dnsbl-2.uceprotect.net|UCEProtect L2",
        "dnsbl-3.uceprotect.net|UCEProtect L3",
        "psbl.surriel.com|PSBL",
        "dyna.spamrats.com|SpamRATS Dyna",
        "noptr.spamrats.com|SpamRATS NoPtr",
        "spam.spamrats.com|SpamRATS Spam",
        "dnsbl.dronebl.org|DroneBL",
        "rbl.interserver.net|InterServer",
        "bogons.cymru.com|Cymru Bogons",
        "bl.blocklist.de|Blocklist.de",
        "bl.nordspam.com|NordSpam BL",
        "dnsbl.inps.de|INPS",
        "ix.dnsbl.manitu.net|NiX Spam",
        "truncate.gbudb.net|Truncate/GBUdb",
        "z.mailspike.net|Mailspike Z",
        "spambot.bls.digibase.ca|Digibase SpamBot",
    };

    public static readonly IReadOnlyList<string> ExtendedIpBlocklistsPrivate = new[]
    {
        "cbl.abuseat.org|CBL",
        "db.wpbl.info|WPBL",
        "bl.spamcannibal.org|SpamCannibal",
        "access.redhawk.org|Redhawk",
        "combined.abuse.ch|abuse.ch Combined",
        "rbl.abuse.net|abuse.net",
        "singular.ttk.pte.hu|Singular",
        "uribl.swinog.ch|SwiNOG URIBL",
        "bl.fmb.la|FMB",
        "dnsbl.rv-soft.info|RV-Soft",
    };

    public static readonly IReadOnlyList<string> DomainBlocklists = new[]
        { "dbl.spamhaus.org", "multi.surbl.org", "black.uribl.com" };

    public static readonly IReadOnlyList<string> ArcSelectors = new[]
        { "arc", "s1", "s2", "google", "selector1", "selector2", "default" };

    public static readonly IReadOnlyList<string> DmarcDiscoverySubdomains = new[]
        { "mail", "smtp", "email", "www", "newsletter", "marketing", "bounce", "send", "outbound" };

    public static readonly IReadOnlyList<string> MailSurveySubdomains = new[]
    {
        "mail", "smtp", "pop", "pop3", "imap", "webmail", "email",
        "mx", "mx1", "mx2", "mta", "relay", "outbound", "inbound",
        "bounce", "return", "send", "newsletter", "marketing"
    };

    public static readonly IReadOnlyList<string> SpfSubdomains = new[]
    {
        "mail", "smtp", "email", "newsletter", "marketing",
        "bounce", "send", "outbound", "notifications", "transactional"
    };

    public static readonly IReadOnlyList<string> SrvServiceNames = new[]
        { "_submission._tcp", "_imap._tcp", "_imaps._tcp", "_pop3s._tcp", "_jmap._tcp" };

    public static readonly IReadOnlyList<string> VmcIssuers = new[]
        { "DigiCert", "Entrust", "GlobalSign" };

    public const string CrtShBaseUrl = "https://crt.sh/";
}
