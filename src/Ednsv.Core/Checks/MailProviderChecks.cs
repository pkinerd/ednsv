using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Checks;

/// <summary>What a provider does with the mail that reaches it.</summary>
public enum MailProviderRole
{
    /// <summary>Hosts the mailboxes itself (it may filter too, as Microsoft 365 does).</summary>
    Mailbox,
    /// <summary>Filters and relays onward — the mailboxes are somewhere else.</summary>
    Gateway,
    /// <summary>Rewrites the recipient and forwards to an address elsewhere.</summary>
    Forwarding,
    /// <summary>Hands the message to an application (webhook, bucket), not a mailbox.</summary>
    InboundProcessing,
}

/// <summary>
/// One row of the provider catalogue. A hostname belongs to a provider when it equals
/// one of <see cref="HostSuffixes"/> or ends with "." + one of them; the other suffix
/// lists are matched the same way against the include/CNAME targets they name.
/// </summary>
public sealed record MailProvider(string Name, MailProviderRole Role, params string[] HostSuffixes)
{
    /// <summary>Required leading label, for providers whose suffix is shared with
    /// unrelated services (amazonaws.com is also every EC2 instance's PTR).</summary>
    public string? HostPrefix { get; init; }
    public string[] SpfIncludes { get; init; } = Array.Empty<string>();
    public string[] DkimCnameSuffixes { get; init; } = Array.Empty<string>();
    /// <summary>Selectors whose directly-published key points at this provider —
    /// a default the provider chooses, so weaker than a CNAME into its zone.</summary>
    public string[] DkimKeySelectors { get; init; } = Array.Empty<string>();
    public string[] AutodiscoverSuffixes { get; init; } = Array.Empty<string>();
    public (string Prefix, int Weight)[] VerificationTxt { get; init; } = Array.Empty<(string, int)>();

    public bool MatchesHost(string host) =>
        MailProviderCatalog.HasSuffix(host, HostSuffixes)
        && (HostPrefix == null || host.StartsWith(HostPrefix, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Everything the inference reads, gathered up front so the reasoning can be exercised
/// without a network. Each list is what public DNS or the SMTP greeting already shows.
/// </summary>
public sealed class MailProviderSignals
{
    public List<MxHostSignals> MxHosts { get; } = new();
    /// <summary>include:/redirect= targets, nested ones included.</summary>
    public List<string> SpfIncludes { get; } = new();
    public List<(string Selector, string Target)> DkimCnames { get; } = new();
    /// <summary>Selectors that publish a key directly (no CNAME).</summary>
    public List<string> DkimKeySelectors { get; } = new();
    public List<string> AutodiscoverTargets { get; } = new();
    public List<string> ApexTxt { get; } = new();
    public bool SmtpProbed { get; set; }
}

public sealed class MxHostSignals
{
    public string Host { get; init; } = "";
    public List<string> CnameTargets { get; } = new();
    public List<string> PtrNames { get; } = new();
    public string? Banner { get; set; }
    public List<string> CertNames { get; } = new();
}

public static class MailProviderCatalog
{
    // Weights for mailbox evidence. The thresholds in Describe() are written against
    // these: one strong signal, or two medium ones, is enough to call a provider likely;
    // weak signals alone never reach the summary.
    public const int Strong = 3, Medium = 2, Weak = 1;

    /// <summary>Banner text Exchange Server prints. Exchange Online prints it too, but
    /// its hosts match the Microsoft 365 suffixes first, so reaching this means the
    /// greeting came from an Exchange server somebody runs themselves.</summary>
    public const string ExchangeBannerMarker = "Microsoft ESMTP MAIL Service";
    public const string ExchangeOnPremName = "Microsoft Exchange Server (self-hosted)";
    public const string Microsoft365Name = "Microsoft 365 (Exchange Online)";

    public static readonly IReadOnlyList<MailProvider> Providers = new List<MailProvider>
    {
        // ── Mailbox providers ──────────────────────────────────────────────
        new(Microsoft365Name, MailProviderRole.Mailbox,
            "protection.outlook.com", "mx.microsoft", "protection.office365.us", "protection.partner.outlook.cn")
        {
            SpfIncludes = new[] { "spf.protection.outlook.com", "spf.protection.office365.us", "spf.protection.partner.outlook.cn" },
            // selectorN-<domain>._domainkey.<tenant>.onmicrosoft.com, and since 2025
            // selectorN-<domain>._domainkey.<tenant>.<x>-v1.dkim.mail.microsoft
            DkimCnameSuffixes = new[] { "onmicrosoft.com", "dkim.mail.microsoft", "onmicrosoft.us", "partner.onmschina.cn" },
            AutodiscoverSuffixes = new[] { "outlook.com", "office365.us", "partner.outlook.cn" },
            VerificationTxt = new[] { ("MS=ms", Medium) },
        },
        new("Google Workspace", MailProviderRole.Mailbox, "google.com", "googlemail.com")
        {
            SpfIncludes = new[] { "_spf.google.com" },
            DkimKeySelectors = new[] { "google" },
            // Site verification is shared by every Google product, Search Console above all.
            VerificationTxt = new[] { ("google-site-verification=", Weak) },
        },
        new("Zoho Mail", MailProviderRole.Mailbox,
            "zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zoho.jp", "zoho.com.cn", "zoho.sa", "zohomail.com")
        {
            SpfIncludes = new[] { "zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zoho.jp", "zohomail.com", "zohomail.eu" },
            DkimKeySelectors = new[] { "zoho" },
            VerificationTxt = new[] { ("zoho-verification=", Medium) },
        },
        new("Fastmail", MailProviderRole.Mailbox, "messagingengine.com")
        {
            SpfIncludes = new[] { "messagingengine.com" },
            DkimCnameSuffixes = new[] { "messagingengine.com" },
        },
        new("Proton Mail", MailProviderRole.Mailbox, "protonmail.ch", "proton.ch")
        {
            SpfIncludes = new[] { "protonmail.ch" },
            DkimCnameSuffixes = new[] { "protonmail.ch", "proton.ch" },
            VerificationTxt = new[] { ("protonmail-verification=", Medium) },
        },
        new("iCloud Mail (custom domain)", MailProviderRole.Mailbox, "mail.icloud.com")
        {
            SpfIncludes = new[] { "icloud.com" },
            DkimCnameSuffixes = new[] { "icloudmailadmin.com" },
            VerificationTxt = new[] { ("apple-domain=", Medium) },
        },
        new("Yahoo / AOL", MailProviderRole.Mailbox, "yahoodns.net"),
        new("Yandex 360", MailProviderRole.Mailbox, "yandex.net", "yandex.ru")
        {
            SpfIncludes = new[] { "_spf.yandex.net" },
            VerificationTxt = new[] { ("yandex-verification:", Weak) },
        },
        new("Mail.ru for Business", MailProviderRole.Mailbox, "mail.ru") { SpfIncludes = new[] { "_spf.mail.ru" } },
        new("Tencent Exmail", MailProviderRole.Mailbox, "qq.com") { SpfIncludes = new[] { "spf.mail.qq.com" } },
        new("Alibaba Mail", MailProviderRole.Mailbox, "mxhichina.com") { SpfIncludes = new[] { "spf.mxhichina.com" } },
        new("NetEase Enterprise Mail", MailProviderRole.Mailbox, "163.com", "netease.com") { SpfIncludes = new[] { "spf.163.com" } },
        // Only the two mail hostnames: the rest of secureserver.net is GoDaddy's hosting,
        // whose PTRs would otherwise make every VPS on it look like a mailbox service.
        new("GoDaddy Email", MailProviderRole.Mailbox, "mailstore1.secureserver.net", "smtp.secureserver.net")
        {
            SpfIncludes = new[] { "secureserver.net" },
            AutodiscoverSuffixes = new[] { "secureserver.net" },
        },
        new("Rackspace Email", MailProviderRole.Mailbox, "emailsrvr.com")
        {
            SpfIncludes = new[] { "emailsrvr.com" },
            AutodiscoverSuffixes = new[] { "emailsrvr.com" },
        },
        new("IONOS Mail", MailProviderRole.Mailbox,
            "ionos.com", "ionos.de", "ionos.co.uk", "ionos.fr", "ionos.es", "ionos.it", "ionos.mx", "ionos.ca",
            "perfora.net", "kundenserver.de", "1and1.com", "1and1.co.uk")
        {
            SpfIncludes = new[] { "perfora.net", "kundenserver.de", "ionos.com", "ionos.de" },
        },
        // mail.ovh.net, not ovh.net: OVH's VPS and dedicated-server PTRs live under ovh.net.
        new("OVHcloud Mail", MailProviderRole.Mailbox, "mail.ovh.net") { SpfIncludes = new[] { "mx.ovh.com" } },
        new("Namecheap Private Email", MailProviderRole.Mailbox, "privateemail.com") { SpfIncludes = new[] { "spf.privateemail.com" } },
        new("Titan Email", MailProviderRole.Mailbox, "titan.email") { SpfIncludes = new[] { "titan.email" } },
        new("Hostinger Email", MailProviderRole.Mailbox, "hostinger.com") { SpfIncludes = new[] { "mail.hostinger.com" } },
        new("Migadu", MailProviderRole.Mailbox, "migadu.com") { SpfIncludes = new[] { "migadu.com" } },
        new("mailbox.org", MailProviderRole.Mailbox, "mailbox.org") { SpfIncludes = new[] { "mailbox.org" } },
        new("Tuta", MailProviderRole.Mailbox, "tutanota.de", "tuta.io") { SpfIncludes = new[] { "tutanota.de" } },
        new("Gandi Mail", MailProviderRole.Mailbox, "mail.gandi.net") { SpfIncludes = new[] { "_mailcust.gandi.net" } },
        new("Infomaniak Mail", MailProviderRole.Mailbox, "infomaniak.ch") { SpfIncludes = new[] { "spf.infomaniak.ch" } },
        new("OpenSRS / Tucows Hosted Email", MailProviderRole.Mailbox, "hostedemail.com") { SpfIncludes = new[] { "hostedemail.com" } },
        // WorkMail receives through the SES inbound endpoints listed below; only its
        // autodiscover tells the two apart.
        new("Amazon WorkMail", MailProviderRole.Mailbox) { AutodiscoverSuffixes = new[] { "awsapps.com" } },

        // ── Filtering gateways (mailboxes are elsewhere) ────────────────────
        new("Proofpoint (hosted)", MailProviderRole.Gateway, "pphosted.com"),
        new("Proofpoint Essentials", MailProviderRole.Gateway, "ppe-hosted.com"),
        new("Mimecast", MailProviderRole.Gateway, "mimecast.com", "mimecast.co.za", "mimecast-offshore.com"),
        new("Barracuda Email Protection", MailProviderRole.Gateway, "barracudanetworks.com"),
        new("Cisco Secure Email (IronPort)", MailProviderRole.Gateway, "iphmx.com"),
        new("Trend Micro Email Security", MailProviderRole.Gateway, "trendmicro.com", "trendmicro.eu", "trendmicro.co.jp"),
        new("Sophos Email", MailProviderRole.Gateway, "hydra.sophos.com"),
        new("Broadcom Email Security.cloud (Symantec)", MailProviderRole.Gateway, "messagelabs.com"),
        new("Forcepoint Email Security", MailProviderRole.Gateway, "mailcontrol.com"),
        new("Trellix Email Security (FireEye)", MailProviderRole.Gateway, "fireeyecloud.com"),
        new("Hornetsecurity", MailProviderRole.Gateway, "hornetsecurity.com"),
        new("SpamTitan", MailProviderRole.Gateway, "spamtitan.com"),
        new("N-able Mail Assure (SpamExperts)", MailProviderRole.Gateway, "spamexperts.com", "spamexperts.eu", "spamexperts.net", "antispamcloud.com"),
        new("AppRiver (OpenText)", MailProviderRole.Gateway, "arsmtp.com"),
        new("MailRoute", MailProviderRole.Gateway, "mailroute.net"),
        new("Fortinet FortiMail Cloud", MailProviderRole.Gateway, "fortimailcloud.com"),
        new("Cloudflare Email Security (Area 1)", MailProviderRole.Gateway, "mxrecord.io", "mxrecord.mx"),
        new("MailChannels Inbound", MailProviderRole.Gateway, "mailchannels.net"),
        new("Mailprotector", MailProviderRole.Gateway, "mailprotector.net"),

        // ── Forwarding services ─────────────────────────────────────────────
        new("Cloudflare Email Routing", MailProviderRole.Forwarding, "mx.cloudflare.net"),
        new("ImprovMX", MailProviderRole.Forwarding, "improvmx.com"),
        new("Forward Email", MailProviderRole.Forwarding, "forwardemail.net"),
        new("Namecheap Email Forwarding", MailProviderRole.Forwarding, "registrar-servers.com"),
        new("Porkbun Email Forwarding", MailProviderRole.Forwarding, "porkbun.com"),
        new("SimpleLogin", MailProviderRole.Forwarding, "simplelogin.co"),

        // ── Inbound-to-application services ─────────────────────────────────
        new("Amazon SES inbound (receipt rules or WorkMail)", MailProviderRole.InboundProcessing, "amazonaws.com")
            { HostPrefix = "inbound-smtp." },
        new("SendGrid Inbound Parse", MailProviderRole.InboundProcessing, "mx.sendgrid.net"),
        new("Mailgun Routes", MailProviderRole.InboundProcessing, "mailgun.org"),
        new("Postmark Inbound", MailProviderRole.InboundProcessing, "inbound.postmarkapp.com"),
    };

    /// <summary>MTA software named in a self-hosted server's greeting. Not a provider —
    /// only a hint that the unrecognised host is somebody's own server.</summary>
    private static readonly string[] MtaSoftware =
    {
        "Postfix", "Exim", "Sendmail", "hMailServer", "MDaemon", "Zimbra", "Kerio",
        "IceWarp", "SmarterMail", "Haraka", "Axigen", "Halon", "OpenSMTPD", "Courier",
    };

    /// <summary>Every DKIM selector the catalogue reads, so the check can query each once.</summary>
    public static IEnumerable<string> DkimSelectorsOfInterest =>
        new[] { "selector1", "selector2", "fm1", "protonmail", "sig1" }
            .Concat(Providers.SelectMany(p => p.DkimKeySelectors))
            .Distinct(StringComparer.OrdinalIgnoreCase);

    public static bool HasSuffix(string host, IEnumerable<string> suffixes)
    {
        var h = host.TrimEnd('.');
        foreach (var s in suffixes)
        {
            if (h.Equals(s, StringComparison.OrdinalIgnoreCase)
                || h.EndsWith("." + s, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static MailProvider? MatchHost(string host) =>
        string.IsNullOrWhiteSpace(host) ? null : Providers.FirstOrDefault(p => p.MatchesHost(host.Trim()));

    public static string? MtaSoftwareIn(string? banner) =>
        banner == null ? null : MtaSoftware.FirstOrDefault(s => banner.Contains(s, StringComparison.OrdinalIgnoreCase));

    /// <summary>The hostname a 220 greeting announces (RFC 5321 §4.3.1), if any.</summary>
    public static string? BannerHost(string? banner)
    {
        if (string.IsNullOrWhiteSpace(banner)) return null;
        var body = banner.StartsWith("220", StringComparison.Ordinal) ? banner[3..].TrimStart(' ', '-') : banner;
        var token = body.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return token != null && token.Contains('.') ? token.TrimEnd('.') : null;
    }

    public static string RoleLabel(MailProviderRole role) => role switch
    {
        MailProviderRole.Mailbox => "mailbox provider",
        MailProviderRole.Gateway => "filtering gateway",
        MailProviderRole.Forwarding => "forwarding service",
        MailProviderRole.InboundProcessing => "inbound mail to an application",
        _ => role.ToString(),
    };

    /// <summary>
    /// The Microsoft 365 tenant a DKIM CNAME names. Both target shapes carry it as the
    /// label after "_domainkey.": "&lt;tenant&gt;.onmicrosoft.com" and the 2025
    /// "&lt;tenant&gt;.&lt;x&gt;-v1.dkim.mail.microsoft".
    /// </summary>
    public static string? Microsoft365Tenant(string dkimTarget)
    {
        var labels = dkimTarget.TrimEnd('.').Split('.');
        var i = Array.FindIndex(labels, l => l.Equals("_domainkey", StringComparison.OrdinalIgnoreCase));
        if (i < 0 || i + 1 >= labels.Length) return null;
        return labels[i + 1].ToLowerInvariant() + ".onmicrosoft.com";
    }
}

/// <summary>What the inference concluded, before it is worded into a CheckResult.</summary>
public sealed class MailProviderAssessment
{
    public List<(string Host, MailProvider? Provider, string Via, string? Software)> Receiving { get; } = new();
    public List<(string Provider, int Weight, string Evidence)> MailboxEvidence { get; } = new();
    public string? Microsoft365Tenant { get; set; }

    /// <summary>Candidates by total weight; ties go to the provider an MX names.</summary>
    public List<(string Provider, int Score)> RankedMailbox() =>
        MailboxEvidence.GroupBy(e => e.Provider)
            .Select(g => (Provider: g.Key, Score: g.Sum(e => e.Weight)))
            .OrderByDescending(c => c.Score)
            .ThenByDescending(c => Receiving.Any(r => r.Provider?.Name == c.Provider))
            .ThenBy(c => c.Provider, StringComparer.Ordinal)
            .ToList();
}

/// <summary>
/// Identifies who receives the domain's mail (the MX tier — often a filtering gateway
/// such as Proofpoint or Mimecast) and who most likely hosts the mailboxes behind it.
/// Informational only: nothing here is a misconfiguration, and the mailbox side is an
/// inference from public DNS, so it is worded as likely/possible rather than asserted.
/// </summary>
public class MailProviderDetectionCheck : ICheck
{
    public string Name => "Mail Provider Detection";
    public CheckCategory Category => CheckCategory.MX;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category, Severity = CheckSeverity.Info };

        if (!ctx.MxHosts.Any())
        {
            result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
            result.Summary = ctx.MxLookupFailed
                ? "MX lookup failed — receiving provider not determined"
                : "No MX records — receiving provider not determined";
            return new List<CheckResult> { result };
        }
        // Null MX (RFC 7505) reaches here as a single empty exchange name.
        if (ctx.MxHosts.All(string.IsNullOrEmpty))
        {
            result.Summary = "Null MX — domain does not receive mail";
            return new List<CheckResult> { result };
        }

        try
        {
            var signals = await GatherAsync(domain, ctx, cancellationToken);
            Describe(Assess(signals), signals, result);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // An identification aid failing is not a finding about the domain.
            result.Summary = "Mail provider detection incomplete";
            result.Details.Add($"Detection failed: {ex.Message}");
        }

        return new List<CheckResult> { result };
    }

    // Every lookup below is one another check already makes — MX CNAME chains, MX PTRs,
    // the port-25 probe, the SPF include tree, the DKIM selector sweep, autodiscover —
    // so on a normal run this check is answered from cache rather than adding traffic.
    private static async Task<MailProviderSignals> GatherAsync(string domain, CheckContext ctx, CancellationToken ct)
    {
        var s = new MailProviderSignals { SmtpProbed = ctx.Options.EnableSmtpProbes };

        foreach (var host in ctx.MxHosts.Where(h => !string.IsNullOrEmpty(h)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            var mx = new MxHostSignals { Host = host };
            mx.CnameTargets.AddRange(CnameTargets(await ctx.Dns.ResolveCnameChainAsync(host)));

            if (ctx.MxHostIps.TryGetValue(host, out var ips))
            {
                // IPv4 only: those are the PTRs MX Records and the prefetch already resolved.
                foreach (var ip in ips.Where(i => !i.Contains(':')))
                    mx.PtrNames.AddRange(await ctx.Dns.ResolvePtrAsync(ip));
            }

            if (ctx.Options.EnableSmtpProbes)
            {
                var probe = await ctx.GetOrProbeSmtpAsync(host);
                if (probe.Connected)
                {
                    mx.Banner = probe.Banner;
                    if (probe.CertSans != null) mx.CertNames.AddRange(probe.CertSans);
                    var cn = probe.CertSubject?.Split(',')
                        .Select(p => p.Trim())
                        .FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
                    if (cn != null) mx.CertNames.Add(cn[3..]);
                }
            }
            s.MxHosts.Add(mx);
        }

        if (ctx.SpfRecord != null)
            await CollectSpfIncludesAsync(ctx, ctx.SpfRecord, s.SpfIncludes, new HashSet<string>(StringComparer.OrdinalIgnoreCase), 0);

        foreach (var selector in MailProviderCatalog.DkimSelectorsOfInterest)
        {
            ct.ThrowIfCancellationRequested();
            // A TXT query on a CNAMEd name returns the CNAME chain with the answer, so one
            // query (the same one the DKIM sweep makes) yields both kinds of signal.
            var resp = await ctx.Dns.QuerySpeculativeAsync($"{selector}._domainkey.{domain}", QueryType.TXT);
            var cname = resp.Answers.CnameRecords().LastOrDefault();
            if (cname != null)
                s.DkimCnames.Add((selector, cname.CanonicalName.Value.TrimEnd('.')));
            else if (resp.Answers.TxtRecords().Any(t => string.Join("", t.Text).Contains("p=", StringComparison.Ordinal)))
                s.DkimKeySelectors.Add(selector);
        }

        s.AutodiscoverTargets.AddRange(CnameTargets(await ctx.Dns.ResolveCnameChainAsync($"autodiscover.{domain}")));

        foreach (var txt in await ctx.Dns.GetTxtRecordsAsync(domain))
            s.ApexTxt.Add(string.Join("", txt.Text));

        return s;
    }

    /// <summary>ResolveCnameChainAsync renders each hop as "a -> b"; the targets are the b's.</summary>
    private static IEnumerable<string> CnameTargets(IEnumerable<string> chain) =>
        chain.Select(hop => hop.Split(" -> ").Last().Trim()).Where(t => t.Length > 0);

    // Depth and breadth are bounded well inside SPF's own 10-lookup limit: provider
    // includes sit at the top level or one below, and a pathological tree should cost
    // this informational check nothing beyond what SPF Recursive Expansion already paid.
    private static async Task CollectSpfIncludesAsync(CheckContext ctx, string record, List<string> into, HashSet<string> visited, int depth)
    {
        if (depth > 3 || visited.Count >= 10) return;
        foreach (var term in record.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = term.TrimStart('+', '-', '~', '?');
            string? target = t.StartsWith("include:", StringComparison.OrdinalIgnoreCase) ? t[8..]
                : t.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase) ? t[9..]
                : null;
            if (string.IsNullOrEmpty(target) || target.Contains('%') || !visited.Add(target)) continue;
            into.Add(target);
            if (visited.Count >= 10) return;

            var txts = await ctx.Dns.GetTxtRecordsAsync(target);
            var nested = txts.Select(x => string.Join("", x.Text)).FirstOrDefault(SpfHelpers.IsSpfRecord);
            if (nested != null)
                await CollectSpfIncludesAsync(ctx, nested, into, visited, depth + 1);
        }
    }

    public static MailProviderAssessment Assess(MailProviderSignals s)
    {
        var a = new MailProviderAssessment();
        var mailboxFromMx = new HashSet<string>();

        foreach (var mx in s.MxHosts)
        {
            // Strongest first: the name the domain owner chose, then where it CNAMEs,
            // then what the server says about itself, then who owns the IP.
            (MailProvider? p, string via) = (MailProviderCatalog.MatchHost(mx.Host), "MX hostname");
            foreach (var t in mx.CnameTargets)
                if (p == null && MailProviderCatalog.MatchHost(t) is { } byCname) (p, via) = (byCname, $"CNAME {t}");
            var bannerHost = MailProviderCatalog.BannerHost(mx.Banner);
            if (p == null && bannerHost != null && MailProviderCatalog.MatchHost(bannerHost) is { } byBanner)
                (p, via) = (byBanner, $"SMTP banner {bannerHost}");
            foreach (var c in mx.CertNames)
                if (p == null && MailProviderCatalog.MatchHost(c.TrimStart('*', '.')) is { } byCert) (p, via) = (byCert, $"TLS certificate {c}");
            foreach (var ptr in mx.PtrNames)
                if (p == null && MailProviderCatalog.MatchHost(ptr) is { } byPtr) (p, via) = (byPtr, $"PTR {ptr} (owner of the IP)");

            string? software = null;
            if (p == null && mx.Banner?.Contains(MailProviderCatalog.ExchangeBannerMarker, StringComparison.OrdinalIgnoreCase) == true)
            {
                software = "Microsoft Exchange";
                if (mailboxFromMx.Add(MailProviderCatalog.ExchangeOnPremName))
                    a.MailboxEvidence.Add((MailProviderCatalog.ExchangeOnPremName, MailProviderCatalog.Strong,
                        $"MX {mx.Host} greets as Exchange Server"));
            }
            else if (p == null)
                software = MailProviderCatalog.MtaSoftwareIn(mx.Banner);

            a.Receiving.Add((mx.Host, p, via, software));

            if (p is { Role: MailProviderRole.Mailbox } && mailboxFromMx.Add(p.Name))
                a.MailboxEvidence.Add((p.Name, MailProviderCatalog.Strong, $"MX {mx.Host} is {p.Name} ({via})"));
        }

        foreach (var p in MailProviderCatalog.Providers.Where(p => p.Role == MailProviderRole.Mailbox))
        {
            var spf = s.SpfIncludes.FirstOrDefault(i => MailProviderCatalog.HasSuffix(i, p.SpfIncludes));
            if (spf != null)
                a.MailboxEvidence.Add((p.Name, MailProviderCatalog.Medium, $"SPF authorises {spf}"));

            var dkim = s.DkimCnames.FirstOrDefault(d => MailProviderCatalog.HasSuffix(d.Target, p.DkimCnameSuffixes));
            if (dkim.Target != null)
            {
                a.MailboxEvidence.Add((p.Name, MailProviderCatalog.Strong, $"DKIM {dkim.Selector}._domainkey CNAME → {dkim.Target}"));
                if (p.Name == MailProviderCatalog.Microsoft365Name)
                    a.Microsoft365Tenant ??= MailProviderCatalog.Microsoft365Tenant(dkim.Target);
            }

            var key = s.DkimKeySelectors.FirstOrDefault(k => p.DkimKeySelectors.Contains(k, StringComparer.OrdinalIgnoreCase));
            if (key != null)
                a.MailboxEvidence.Add((p.Name, MailProviderCatalog.Medium, $"DKIM key at the provider's default selector '{key}'"));

            var auto = s.AutodiscoverTargets.FirstOrDefault(t => MailProviderCatalog.HasSuffix(t, p.AutodiscoverSuffixes));
            if (auto != null)
                a.MailboxEvidence.Add((p.Name, MailProviderCatalog.Strong, $"autodiscover CNAME → {auto}"));

            foreach (var (prefix, weight) in p.VerificationTxt)
            {
                if (s.ApexTxt.Any(t => t.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
                {
                    a.MailboxEvidence.Add((p.Name, weight, $"verification TXT {prefix}…"));
                    break;
                }
            }
        }

        return a;
    }

    public static void Describe(MailProviderAssessment a, MailProviderSignals s, CheckResult result)
    {
        result.Severity = CheckSeverity.Info;

        // ── Receiving tier ──
        result.Details.Add("Receiving (MX):");
        foreach (var (host, p, via, software) in a.Receiving)
        {
            var what = p != null
                ? $"{p.Name} — {MailProviderCatalog.RoleLabel(p.Role)} (via {via})"
                : software != null
                    ? $"unrecognised; greeting identifies {software} (likely self-hosted)"
                    : "unrecognised (self-hosted or a provider not in the catalogue)";
            result.Details.Add($"  {host}: {what}");
        }

        var receivingNames = a.Receiving
            .Select(r => r.Provider?.Name ?? (r.Software == "Microsoft Exchange" ? MailProviderCatalog.ExchangeOnPremName : "unrecognised"))
            .Distinct().ToList();
        var receiving = string.Join(" + ", receivingNames);

        // ── Mailbox tier ──
        var ranked = a.RankedMailbox();
        if (a.MailboxEvidence.Any())
        {
            result.Details.Add("Mailbox provider signals:");
            foreach (var (provider, score) in ranked)
            {
                result.Details.Add($"  {provider} (score {score}):");
                foreach (var e in a.MailboxEvidence.Where(e => e.Provider == provider))
                    result.Details.Add($"    {e.Evidence} [+{e.Weight}]");
            }
        }
        if (a.Microsoft365Tenant != null)
            result.Details.Add($"Microsoft 365 tenant (from DKIM CNAME): {a.Microsoft365Tenant}");

        var top = ranked.FirstOrDefault();
        string mailbox;
        if (top.Provider == null)
        {
            mailbox = a.Receiving.Any(r => r.Provider?.Role == MailProviderRole.Forwarding)
                ? "not determinable (mail is forwarded elsewhere)"
                : a.Receiving.Any(r => r.Provider?.Role == MailProviderRole.InboundProcessing)
                    ? "none (mail is handed to an application)"
                    : "not determinable from DNS";
        }
        else
        {
            // A Google site-verification record alone says nothing about mail, so a
            // weak-only candidate stays in the details and out of the headline.
            mailbox = top.Score >= MailProviderCatalog.Strong ? $"likely {top.Provider}"
                : top.Score >= MailProviderCatalog.Medium ? $"possibly {top.Provider}"
                : "not determinable from DNS";
            var runnerUp = ranked.Skip(1).FirstOrDefault();
            if (top.Score >= MailProviderCatalog.Medium && runnerUp.Provider != null && runnerUp.Score >= MailProviderCatalog.Strong)
                mailbox += $" (also signals for {runnerUp.Provider} — hybrid or migration?)";
        }

        // The MX tier is the mailbox tier: one provider, and the top candidate is it.
        var sameProvider = top.Provider != null && receivingNames.Count == 1 && receivingNames[0] == top.Provider;
        result.Summary = sameProvider
            ? $"Receiving and mailbox: {top.Provider}"
            : $"Receiving: {receiving}; mailbox: {mailbox}";

        // ── Notes worth knowing, none of them a finding ──
        var gateways = a.Receiving.Where(r => r.Provider?.Role == MailProviderRole.Gateway).Select(r => r.Provider!.Name).Distinct().ToList();
        if (gateways.Any() && receivingNames.Count > 1)
            result.Details.Add($"Note: MX hosts span several providers ({receiving}) — mail sent to a host outside {string.Join("/", gateways)} skips its filtering.");
        if (gateways.Any() && top.Provider == MailProviderCatalog.Microsoft365Name && top.Score >= MailProviderCatalog.Medium)
            result.Details.Add($"Note: with {string.Join("/", gateways)} in front of Microsoft 365, the tenant's own "
                + "*.mail.protection.outlook.com endpoint still accepts direct delivery unless inbound connectors "
                + "are restricted to the gateway's IPs; Enhanced Filtering for Connectors keeps SPF/DMARC meaningful behind it.");
        else if (gateways.Any() && top.Provider == "Google Workspace" && top.Score >= MailProviderCatalog.Medium)
            result.Details.Add($"Note: with {string.Join("/", gateways)} in front of Google Workspace, configure it as Gmail's "
                + "inbound gateway (and reject mail not from it) so direct delivery cannot bypass the filtering.");
        if (!s.SmtpProbed)
            result.Details.Add("SMTP probes disabled — banner and certificate signals not used.");
        result.Details.Add("Heuristic: inferred from MX/PTR names, SMTP greetings, SPF, DKIM, autodiscover and verification TXT records.");
    }
}
