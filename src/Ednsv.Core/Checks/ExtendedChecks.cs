using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

/// <summary>
/// Reports SMTP SIZE extension (max message size) from EHLO
/// </summary>
public class SmtpSizeCheck : ICheck
{
    public string Name => "SMTP Max Message Size";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.MxHosts.Any())
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No MX hosts";
            return new List<CheckResult> { result };
        }

        foreach (var mxHost in ctx.MxHosts)
        {
            var probe = await GetOrProbeAsync(ctx, mxHost);
            if (probe.SmtpMaxSize.HasValue)
            {
                var sizeMb = probe.SmtpMaxSize.Value / (1024.0 * 1024.0);
                result.Details.Add($"{mxHost}: SIZE {probe.SmtpMaxSize.Value} bytes ({sizeMb:F1} MB)");

                if (probe.SmtpMaxSize.Value < 10 * 1024 * 1024)
                    result.Warnings.Add($"{mxHost}: Max size {sizeMb:F1} MB is relatively small (< 10 MB)");
            }
            else if (probe.Connected)
            {
                result.Details.Add($"{mxHost}: SIZE not advertised (no limit or not reported)");
            }
            else
            {
                result.Details.Add($"{mxHost}: Could not connect");
            }
        }

        result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Info;
        result.Summary = "SMTP SIZE extension check completed";
        return new List<CheckResult> { result };
    }

    private static async Task<Services.SmtpProbeResult> GetOrProbeAsync(CheckContext ctx, string host)
    {
        if (ctx.SmtpProbeCache.TryGetValue(host, out var cached)) return cached;
        var probe = await ctx.Smtp.ProbeSmtpAsync(host, 25);
        ctx.SmtpProbeCache[host] = probe;
        return probe;
    }
}

/// <summary>
/// Detects overlapping/duplicate IP ranges in SPF
/// </summary>
public class SpfOverlapCheck : ICheck
{
    public string Name => "SPF IP Overlap Detection";
    public CheckCategory Category => CheckCategory.SPF;

    public Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (ctx.SpfRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No SPF record";
            return Task.FromResult(new List<CheckResult> { result });
        }

        var ip4Ranges = new List<string>();
        var ip6Ranges = new List<string>();

        var parts = ctx.SpfRecord.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var mech = part.TrimStart('+', '-', '~', '?');
            if (mech.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase))
                ip4Ranges.Add(mech.Substring(4));
            else if (mech.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase))
                ip6Ranges.Add(mech.Substring(4));
        }

        // Check for exact duplicates
        var ip4Dupes = ip4Ranges.GroupBy(r => r, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1).ToList();
        var ip6Dupes = ip6Ranges.GroupBy(r => r, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1).ToList();

        foreach (var d in ip4Dupes)
            result.Warnings.Add($"Duplicate ip4 range: {d.Key} (appears {d.Count()} times)");
        foreach (var d in ip6Dupes)
            result.Warnings.Add($"Duplicate ip6 range: {d.Key} (appears {d.Count()} times)");

        // Check for single IPs that fall within a CIDR
        var cidrs = ip4Ranges.Where(r => r.Contains('/')).ToList();
        var singles = ip4Ranges.Where(r => !r.Contains('/')).ToList();

        foreach (var single in singles)
        {
            if (!IPAddress.TryParse(single, out var singleAddr)) continue;
            foreach (var cidr in cidrs)
            {
                if (IsInCidr(singleAddr, cidr))
                {
                    result.Warnings.Add($"ip4:{single} is already covered by ip4:{cidr}");
                }
            }
        }

        result.Details.Add($"IPv4 ranges: {ip4Ranges.Count}, IPv6 ranges: {ip6Ranges.Count}");

        if (result.Warnings.Any())
        {
            result.Severity = CheckSeverity.Warning;
            result.Summary = "SPF contains overlapping/duplicate IP ranges";
        }
        else
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = "No SPF IP overlaps detected";
        }

        return Task.FromResult(new List<CheckResult> { result });
    }

    private static bool IsInCidr(IPAddress ip, string cidr)
    {
        try
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) ||
                !int.TryParse(parts[1], out var prefix)) return false;

            var ipBytes = ip.GetAddressBytes();
            var netBytes = network.GetAddressBytes();

            int fullBytes = prefix / 8;
            int remainingBits = prefix % 8;

            for (int i = 0; i < fullBytes; i++)
                if (ipBytes[i] != netBytes[i]) return false;

            if (remainingBits > 0 && fullBytes < ipBytes.Length)
            {
                var mask = (byte)(0xFF << (8 - remainingBits));
                if ((ipBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask)) return false;
            }

            return true;
        }
        catch { return false; }
    }
}

/// <summary>
/// Queries multiple public resolvers and compares answers for consistency
/// </summary>
public class DnsPropagationCheck : ICheck
{
    public string Name => "DNS Propagation Consistency";
    public CheckCategory Category => CheckCategory.NS;

    private static readonly (string ip, string name)[] PublicResolvers =
    {
        ("8.8.8.8", "Google"),
        ("1.1.1.1", "Cloudflare"),
        ("9.9.9.9", "Quad9"),
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        var resolverResults = new Dictionary<string, List<string>>();
        var mxResults = new Dictionary<string, List<string>>();

        foreach (var (ip, name) in PublicResolvers)
        {
            var addr = IPAddress.Parse(ip);

            var aResp = await ctx.Dns.QueryServerAsync(addr, domain, QueryType.A);
            var aRecords = aResp.Answers.ARecords().Select(a => a.Address.ToString()).OrderBy(x => x).ToList();
            resolverResults[name] = aRecords;

            var mxResp = await ctx.Dns.QueryServerAsync(addr, domain, QueryType.MX);
            var mxRecords = mxResp.Answers.MxRecords().Select(m => $"{m.Preference}:{m.Exchange.Value.TrimEnd('.')}").OrderBy(x => x).ToList();
            mxResults[name] = mxRecords;

            result.Details.Add($"{name} ({ip}): A=[{string.Join(", ", aRecords)}] MX=[{string.Join(", ", mxRecords)}]");
        }

        // Compare
        bool aConsistent = resolverResults.Values.All(v =>
            v.SequenceEqual(resolverResults.Values.First()));
        bool mxConsistent = mxResults.Values.All(v =>
            v.SequenceEqual(mxResults.Values.First()));

        if (!aConsistent)
            result.Warnings.Add("A record answers differ across resolvers - propagation may be in progress");
        if (!mxConsistent)
            result.Warnings.Add("MX record answers differ across resolvers - propagation may be in progress");

        result.Severity = (aConsistent && mxConsistent) ? CheckSeverity.Pass : CheckSeverity.Warning;
        result.Summary = (aConsistent && mxConsistent) ?
            "DNS answers consistent across resolvers" :
            "DNS propagation inconsistency detected";

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Checks for ARC (Authenticated Received Chain) DKIM selector records
/// </summary>
public class ArcCheck : ICheck
{
    public string Name => "ARC Selector Records";
    public CheckCategory Category => CheckCategory.DKIM;

    private static readonly string[] ArcSelectors = { "arc", "s1", "s2", "google", "selector1", "selector2", "default" };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        int found = 0;

        foreach (var selector in ArcSelectors)
        {
            var arcDomain = $"{selector}._domainkey.{domain}";
            var txts = await ctx.Dns.GetTxtRecordsAsync(arcDomain);
            var arcRec = txts.FirstOrDefault(t => t.Text.Any(s =>
                s.Contains("k=rsa", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("k=ed25519", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase)));

            if (arcRec != null)
            {
                found++;
                // ARC reuses DKIM key records, so just note the ones found
                result.Details.Add($"ARC/DKIM key at {selector}._domainkey.{domain}");
            }
        }

        result.Severity = found > 0 ? CheckSeverity.Info : CheckSeverity.Info;
        result.Summary = found > 0 ? $"{found} ARC-compatible DKIM key(s) found" : "No dedicated ARC selectors found (ARC uses DKIM keys)";

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Identifies well-known email provider verification TXT records
/// </summary>
public class ProviderVerificationTxtCheck : ICheck
{
    public string Name => "Email Provider Verification TXT";
    public CheckCategory Category => CheckCategory.TXT;

    private static readonly (string pattern, string provider)[] Patterns =
    {
        ("google-site-verification=", "Google Workspace"),
        ("MS=", "Microsoft 365"),
        ("v=verifydns", "Proofpoint"),
        ("atlassian-domain-verification=", "Atlassian"),
        ("docusign=", "DocuSign"),
        ("facebook-domain-verification=", "Facebook/Meta"),
        ("apple-domain-verification=", "Apple"),
        ("zoho-verification=", "Zoho"),
        ("_github-challenge-", "GitHub"),
        ("adobe-idp-site-verification=", "Adobe"),
        ("fastly-domain-delegation-", "Fastly"),
        ("stripe-verification=", "Stripe"),
        ("hubspot-developer-verification=", "HubSpot"),
        ("cisco-ci-domain-verification=", "Cisco/Webex"),
        ("miro-verification=", "Miro"),
        ("t-verify=", "Twilio/SendGrid"),
        ("dropbox-domain-verification=", "Dropbox"),
        ("have-i-been-pwned-verification=", "HIBP"),
        ("amazonses:", "Amazon SES"),
        ("mailru-verification:", "Mail.ru"),
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        var txts = await ctx.Dns.GetTxtRecordsAsync(domain);
        var found = new List<string>();

        foreach (var txt in txts)
        {
            var text = string.Join("", txt.Text);
            foreach (var (pattern, provider) in Patterns)
            {
                if (text.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    found.Add(provider);
                    result.Details.Add($"{provider}: {text.Substring(0, Math.Min(text.Length, 80))}{(text.Length > 80 ? "..." : "")}");
                    break;
                }
            }
        }

        result.Severity = CheckSeverity.Info;
        result.Summary = found.Any() ?
            $"Detected verification records: {string.Join(", ", found.Distinct())}" :
            "No provider verification TXT records detected";

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Checks if SMTP REQUIRETLS (RFC 8689) is supported
/// </summary>
public class SmtpRequireTlsCheck : ICheck
{
    public string Name => "SMTP REQUIRETLS (RFC 8689)";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.MxHosts.Any())
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No MX hosts";
            return new List<CheckResult> { result };
        }

        int supported = 0;
        foreach (var mxHost in ctx.MxHosts)
        {
            var probe = await GetOrProbeAsync(ctx, mxHost);
            if (probe.Connected && probe.SupportsRequireTls)
            {
                supported++;
                result.Details.Add($"{mxHost}: REQUIRETLS supported");
            }
            else if (probe.Connected)
            {
                result.Details.Add($"{mxHost}: REQUIRETLS not advertised");
            }
            else
            {
                result.Details.Add($"{mxHost}: Could not connect");
            }
        }

        result.Severity = supported > 0 ? CheckSeverity.Pass : CheckSeverity.Info;
        result.Summary = supported > 0 ?
            $"REQUIRETLS supported by {supported}/{ctx.MxHosts.Count} MX host(s)" :
            "REQUIRETLS not supported (optional RFC 8689 extension)";

        return new List<CheckResult> { result };
    }

    private static async Task<Services.SmtpProbeResult> GetOrProbeAsync(CheckContext ctx, string host)
    {
        if (ctx.SmtpProbeCache.TryGetValue(host, out var cached)) return cached;
        var probe = await ctx.Smtp.ProbeSmtpAsync(host, 25);
        ctx.SmtpProbeCache[host] = probe;
        return probe;
    }
}

/// <summary>
/// Validates NS glue records are present and correct at parent zone
/// </summary>
public class NsGlueRecordCheck : ICheck
{
    public string Name => "NS Glue Records";
    public CheckCategory Category => CheckCategory.Delegation;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            // Check if any NS hostnames are under the domain itself (requiring glue)
            var needsGlue = ctx.NsHosts.Where(ns =>
                ns.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase) ||
                ns.Equals(domain, StringComparison.OrdinalIgnoreCase)).ToList();

            if (!needsGlue.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No in-bailiwick NS (no glue records needed)";
                result.Details.Add("All NS hostnames are out-of-bailiwick - glue records not required");
                return new List<CheckResult> { result };
            }

            foreach (var nsHost in needsGlue)
            {
                // Query the parent for A records of this NS in the additional section
                var parts = domain.Split('.');
                if (parts.Length >= 2)
                {
                    var parent = string.Join('.', parts.Skip(1));
                    var parentNsResp = await ctx.Dns.QueryAsync(parent, QueryType.NS);
                    var parentNsHosts = parentNsResp.Answers.NsRecords().Select(n => n.NSDName.Value.TrimEnd('.')).ToList();

                    if (parentNsHosts.Any())
                    {
                        var parentIps = await ctx.Dns.ResolveAAsync(parentNsHosts.First());
                        if (parentIps.Any())
                        {
                            var glueResp = await ctx.Dns.QueryServerAsync(
                                IPAddress.Parse(parentIps.First()), domain, QueryType.NS);

                            var glueA = glueResp.Additionals.ARecords()
                                .Where(a => a.DomainName.Value.TrimEnd('.').Equals(nsHost, StringComparison.OrdinalIgnoreCase))
                                .ToList();

                            if (glueA.Any())
                            {
                                result.Details.Add($"{nsHost}: Glue record found ({string.Join(", ", glueA.Select(a => a.Address))})");
                            }
                            else
                            {
                                result.Warnings.Add($"{nsHost}: In-bailiwick NS but no glue record found at parent");
                            }
                        }
                    }
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"{needsGlue.Count} in-bailiwick NS hostname(s) checked for glue";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Surveys common mail-related subdomains for their DNS configuration
/// </summary>
public class MailSubdomainSurveyCheck : ICheck
{
    public string Name => "Mail Subdomain Survey";
    public CheckCategory Category => CheckCategory.MX;

    private static readonly string[] MailSubdomains =
    {
        "mail", "smtp", "pop", "pop3", "imap", "webmail", "email",
        "mx", "mx1", "mx2", "mta", "relay", "outbound", "inbound",
        "bounce", "return", "send", "newsletter", "marketing"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        int found = 0;

        foreach (var sub in MailSubdomains)
        {
            var fqdn = $"{sub}.{domain}";

            // Check CNAME first
            var chain = await ctx.Dns.ResolveCnameChainAsync(fqdn);
            if (chain.Any())
            {
                found++;
                result.Details.Add($"{fqdn}: CNAME -> {chain.Last().Split(" -> ").Last()}");
                continue;
            }

            // Check A
            var aRecs = await ctx.Dns.ResolveAAsync(fqdn);
            if (aRecs.Any())
            {
                found++;
                result.Details.Add($"{fqdn}: A -> {string.Join(", ", aRecs)}");
            }
        }

        result.Severity = CheckSeverity.Info;
        result.Summary = $"{found}/{MailSubdomains.Length} common mail subdomains resolve";

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Notes whether the domain appears in Certificate Transparency logs via crt.sh
/// </summary>
public class CertificateTransparencyCheck : ICheck
{
    public string Name => "Certificate Transparency";
    public CheckCategory Category => CheckCategory.CAA;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var url = $"https://crt.sh/?q={Uri.EscapeDataString(domain)}&output=json";
            var (success, content, statusCode) = await ctx.Http.GetAsync(url);

            if (success && content.Length > 10)
            {
                // Count unique issuers from JSON (simple parsing)
                var issuerMatches = Regex.Matches(content, "\"issuer_name\":\"([^\"]+)\"");
                var issuers = issuerMatches.Cast<Match>().Select(m => m.Groups[1].Value).Distinct().Take(10).ToList();
                var entryCount = Regex.Matches(content, "\"id\":").Count;

                result.Severity = CheckSeverity.Info;
                result.Summary = $"~{entryCount} certificate(s) in CT logs";
                result.Details.Add($"Certificates found in crt.sh for {domain}");
                if (issuers.Any())
                {
                    result.Details.Add($"Certificate Authorities: {string.Join(", ", issuers)}");
                }
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No CT log entries found (or crt.sh unreachable)";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "CT check skipped";
            result.Details.Add($"Could not query CT logs: {ex.Message}");
        }

        return new List<CheckResult> { result };
    }
}
