using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

/// <summary>
/// Flags MX records that resolve to private/reserved IP ranges
/// </summary>
public class MxPrivateIpCheck : ICheck
{
    public string Name => "MX Private IP Detection";
    public CheckCategory Category => CheckCategory.MX;

    private static readonly (byte[] prefix, int bits, string label)[] PrivateRanges =
    {
        (new byte[] { 10 }, 8, "RFC 1918 (10.0.0.0/8)"),
        (new byte[] { 172, 16 }, 12, "RFC 1918 (172.16.0.0/12)"),
        (new byte[] { 192, 168 }, 16, "RFC 1918 (192.168.0.0/16)"),
        (new byte[] { 127 }, 8, "Loopback (127.0.0.0/8)"),
        (new byte[] { 169, 254 }, 16, "Link-local (169.254.0.0/16)"),
        (new byte[] { 0 }, 8, "Current network (0.0.0.0/8)"),
        (new byte[] { 100, 64 }, 10, "CGNAT (100.64.0.0/10)"),
    };

    public Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        var privateFound = new List<string>();

        foreach (var kvp in ctx.MxHostIps)
        {
            foreach (var ip in kvp.Value)
            {
                if (!IPAddress.TryParse(ip, out var addr)) continue;
                if (addr.AddressFamily != AddressFamily.InterNetwork) continue;

                var bytes = addr.GetAddressBytes();
                foreach (var (prefix, bits, label) in PrivateRanges)
                {
                    bool match = true;
                    for (int i = 0; i < prefix.Length; i++)
                    {
                        if (bytes[i] != prefix[i]) { match = false; break; }
                    }
                    if (match)
                    {
                        privateFound.Add($"{kvp.Key} -> {ip} ({label})");
                        break;
                    }
                }
            }
        }

        if (privateFound.Any())
        {
            result.Severity = CheckSeverity.Error;
            result.Summary = $"{privateFound.Count} MX IP(s) resolve to private/reserved ranges";
            foreach (var p in privateFound)
                result.Errors.Add(p);
        }
        else if (ctx.MxHostIps.Any())
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = "No MX IPs in private/reserved ranges";
        }
        else
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No MX IPs to check";
        }

        return Task.FromResult(new List<CheckResult> { result });
    }
}

/// <summary>
/// Reports TLS protocol version negotiated with MX servers, warns on deprecated versions
/// </summary>
public class SmtpTlsVersionCheck : ICheck
{
    public string Name => "SMTP TLS Version";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.MxHosts.Any())
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No MX hosts to check TLS version";
            return new List<CheckResult> { result };
        }

        bool anyDeprecated = false;
        foreach (var mxHost in ctx.MxHosts)
        {
            var probe = await GetOrProbeAsync(ctx, mxHost);
            if (!probe.Connected || !probe.SupportsStartTls)
            {
                result.Details.Add($"{mxHost}: {(probe.Connected ? "No STARTTLS" : "Could not connect")}");
                continue;
            }

            var proto = probe.TlsProtocol;
            var cipher = probe.TlsCipherSuite ?? "unknown";

            result.Details.Add($"{mxHost}: {proto} ({cipher})");

#pragma warning disable SYSLIB0039, CS0618 // Intentionally checking for deprecated TLS protocols
            if (proto == SslProtocols.Tls || proto == SslProtocols.Tls11 ||
                proto == SslProtocols.Ssl3 || proto == SslProtocols.Ssl2)
            {
                anyDeprecated = true;
                result.Warnings.Add($"{mxHost}: Using deprecated {proto} - should support TLS 1.2 or higher");
            }
#pragma warning restore SYSLIB0039, CS0618

            if (proto == SslProtocols.Tls13)
                result.Details.Add($"  {mxHost}: TLS 1.3 supported (excellent)");
        }

        result.Severity = anyDeprecated ? CheckSeverity.Warning : CheckSeverity.Pass;
        result.Summary = anyDeprecated ? "Deprecated TLS version(s) detected" : "TLS versions acceptable";
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
/// Checks whether MX server IPs are covered by the SPF record (supports CIDR range matching)
/// </summary>
public class MxCoveredBySpfCheck : ICheck
{
    public string Name => "MX Hosts Covered by SPF";
    public CheckCategory Category => CheckCategory.SPF;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (ctx.SpfRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No SPF record to check MX coverage";
            return new List<CheckResult> { result };
        }

        if (!ctx.MxHostIps.Any())
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No MX IPs to check against SPF";
            return new List<CheckResult> { result };
        }

        // Collect all IPs and CIDR ranges authorized by SPF
        var authorizedIps = new HashSet<string>();
        var authorizedCidrs = new List<(IPAddress network, int prefixLen)>();
        await CollectSpfIps(ctx, domain, ctx.SpfRecord, authorizedIps, authorizedCidrs, new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        var uncovered = new List<string>();
        foreach (var kvp in ctx.MxHostIps)
        {
            foreach (var ip in kvp.Value)
            {
                if (authorizedIps.Contains(ip) || IsInAnyCidr(ip, authorizedCidrs))
                    result.Details.Add($"{kvp.Key} ({ip}): Covered by SPF");
                else
                    uncovered.Add($"{kvp.Key} ({ip})");
            }
        }

        if (uncovered.Any())
        {
            // MX hosts receive inbound mail; SPF authorizes outbound senders.
            // They are often different infrastructure, so non-overlap is normal.
            result.Severity = CheckSeverity.Info;
            result.Summary = $"{uncovered.Count} MX IP(s) not in SPF (normal - SPF covers outbound, MX covers inbound)";
            foreach (var u in uncovered)
                result.Details.Add($"{u}: Not in SPF authorized ranges (expected if MX and outbound servers differ)");
        }
        else
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = "All MX IPs covered by SPF";
        }

        return new List<CheckResult> { result };
    }

    private static bool IsInAnyCidr(string ipStr, List<(IPAddress network, int prefixLen)> cidrs)
    {
        if (!IPAddress.TryParse(ipStr, out var ip)) return false;
        foreach (var (network, prefixLen) in cidrs)
        {
            if (ip.AddressFamily != network.AddressFamily) continue;
            if (IsInCidr(ip, network, prefixLen)) return true;
        }
        return false;
    }

    private static bool IsInCidr(IPAddress ip, IPAddress network, int prefixLen)
    {
        var ipBytes = ip.GetAddressBytes();
        var netBytes = network.GetAddressBytes();
        if (ipBytes.Length != netBytes.Length) return false;

        int fullBytes = prefixLen / 8;
        int remainingBits = prefixLen % 8;

        for (int i = 0; i < fullBytes && i < ipBytes.Length; i++)
        {
            if (ipBytes[i] != netBytes[i]) return false;
        }

        if (remainingBits > 0 && fullBytes < ipBytes.Length)
        {
            int mask = 0xFF << (8 - remainingBits);
            if ((ipBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask)) return false;
        }

        return true;
    }

    private async Task CollectSpfIps(CheckContext ctx, string domain, string spf,
        HashSet<string> ips, List<(IPAddress network, int prefixLen)> cidrs, HashSet<string> visited)
    {
        if (!visited.Add(domain + "|" + spf)) return;
        var parts = spf.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var mech = part.TrimStart('+', '-', '~', '?');
            if (mech.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase))
            {
                var cidr = mech.Substring(4);
                ParseAndStoreCidr(cidr, 32, ips, cidrs);
            }
            else if (mech.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase))
            {
                var cidr = mech.Substring(4);
                ParseAndStoreCidr(cidr, 128, ips, cidrs);
            }
            else if (mech.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || mech == "a")
            {
                var target = mech.Length > 2 ? mech.Substring(2).Split('/')[0] : domain;
                foreach (var ip in await ctx.Dns.ResolveAAsync(target)) ips.Add(ip);
                foreach (var ip in await ctx.Dns.ResolveAAAAAsync(target)) ips.Add(ip);
            }
            else if (mech.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || mech == "mx")
            {
                var target = mech.Length > 3 ? mech.Substring(3).Split('/')[0] : domain;
                var mxRecs = await ctx.Dns.GetMxRecordsAsync(target);
                foreach (var mx in mxRecs)
                {
                    var host = mx.Exchange.Value.TrimEnd('.');
                    foreach (var ip in await ctx.Dns.ResolveAAsync(host)) ips.Add(ip);
                    foreach (var ip in await ctx.Dns.ResolveAAAAAsync(host)) ips.Add(ip);
                }
            }
            else if (mech.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
            {
                var target = mech.Substring(8);
                var txts = await ctx.Dns.GetTxtRecordsAsync(target);
                var childSpf = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)));
                if (childSpf != null)
                    await CollectSpfIps(ctx, target, string.Join("", childSpf.Text), ips, cidrs, visited);
            }
            else if (mech.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
            {
                var target = mech.Substring(9);
                var txts = await ctx.Dns.GetTxtRecordsAsync(target);
                var childSpf = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)));
                if (childSpf != null)
                    await CollectSpfIps(ctx, target, string.Join("", childSpf.Text), ips, cidrs, visited);
            }
        }
    }

    private static void ParseAndStoreCidr(string cidr, int defaultPrefix,
        HashSet<string> ips, List<(IPAddress network, int prefixLen)> cidrs)
    {
        var slashIdx = cidr.IndexOf('/');
        if (slashIdx >= 0)
        {
            var ipPart = cidr.Substring(0, slashIdx);
            if (IPAddress.TryParse(ipPart, out var addr) &&
                int.TryParse(cidr.Substring(slashIdx + 1), out var prefix))
            {
                cidrs.Add((addr, prefix));
            }
        }
        else
        {
            // Single IP, no CIDR - exact match
            ips.Add(cidr);
        }
    }
}

/// <summary>
/// Walks SPF includes to check for dangerous +all in included records
/// </summary>
public class SpfIncludesAllCheck : ICheck
{
    public string Name => "SPF +all in Includes";
    public CheckCategory Category => CheckCategory.SPF;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (ctx.SpfRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No SPF record";
            return new List<CheckResult> { result };
        }

        var dangerous = new List<string>();
        await CheckIncludesAsync(ctx, ctx.SpfRecord, dangerous, new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        if (dangerous.Any())
        {
            result.Severity = CheckSeverity.Error;
            result.Summary = $"{dangerous.Count} included SPF record(s) use +all";
            foreach (var d in dangerous)
                result.Errors.Add($"{d} has +all - allows any sender, undermines your SPF policy");
        }
        else
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = "No +all found in included SPF records";
        }

        return new List<CheckResult> { result };
    }

    private async Task CheckIncludesAsync(CheckContext ctx, string spf, List<string> dangerous, HashSet<string> visited)
    {
        var parts = spf.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var mech = part.TrimStart('+', '-', '~', '?');
            string? target = null;
            if (mech.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
                target = mech.Substring(8);
            else if (mech.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
                target = mech.Substring(9);

            if (target != null && visited.Add(target))
            {
                var txts = await ctx.Dns.GetTxtRecordsAsync(target);
                var childSpf = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)));
                if (childSpf != null)
                {
                    var text = string.Join("", childSpf.Text);
                    if (text.Split(' ').Any(p => p == "+all"))
                        dangerous.Add(target);
                    await CheckIncludesAsync(ctx, text, dangerous, visited);
                }
            }
        }
    }
}

/// <summary>
/// Warns if DMARC pct is less than 100 (partial enforcement)
/// </summary>
public class DmarcPctAnalysisCheck : ICheck
{
    public string Name => "DMARC Percentage (pct) Analysis";
    public CheckCategory Category => CheckCategory.DMARC;

    public Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (ctx.DmarcRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No DMARC record";
            return Task.FromResult(new List<CheckResult> { result });
        }

        var tags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
        tags.TryGetValue("p", out var policy);
        tags.TryGetValue("pct", out var pctStr);

        if (pctStr == null)
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = "DMARC pct not set (defaults to 100%)";
            result.Details.Add("All messages subject to DMARC policy");
            return Task.FromResult(new List<CheckResult> { result });
        }

        if (int.TryParse(pctStr, out var pct))
        {
            result.Details.Add($"pct={pct} with p={policy ?? "none"}");

            if (pct == 100)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "DMARC pct=100 (full enforcement)";
            }
            else if (pct == 0)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "DMARC pct=0 - policy not applied to any messages";
                result.Warnings.Add("pct=0 means the DMARC policy is effectively disabled");
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = $"DMARC pct={pct}% - partial enforcement (rollout in progress?)";
                result.Details.Add($"Only {pct}% of failing messages will have the {policy ?? "none"} policy applied");
                if (policy == "reject" || policy == "quarantine")
                    result.Details.Add("Consider increasing to pct=100 after monitoring");
            }
        }
        else
        {
            result.Severity = CheckSeverity.Error;
            result.Summary = "DMARC pct value is not a valid number";
            result.Errors.Add($"Invalid pct value: {pctStr}");
        }

        return Task.FromResult(new List<CheckResult> { result });
    }
}

/// <summary>
/// Checks additional DNSBL providers beyond the core three
/// </summary>
public class ExtendedDnsblCheck : ICheck
{
    public string Name => "Extended IP Blocklist Check";
    public CheckCategory Category => CheckCategory.DNSBL;

    private static readonly (string zone, string name)[] Blocklists =
    {
        ("all.s5h.net", "S5H"),
        ("dnsbl.sorbs.net", "SORBS"),
        ("spam.dnsbl.sorbs.net", "SORBS Spam"),
        ("bl.mailspike.net", "Mailspike"),
        ("dnsbl-1.uceprotect.net", "UCEProtect L1"),
    };

    // Same false-positive set as IpBlocklistCheck
    private static readonly HashSet<string> FalsePositiveResponses = new(StringComparer.Ordinal)
    {
        "127.255.255.254", "127.255.255.253", "127.255.255.252", "127.0.0.1"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        var allMxIps = ctx.MxHostIps.Values.SelectMany(v => v).Distinct()
            .Where(ip => IPAddress.TryParse(ip, out var a) && a.AddressFamily == AddressFamily.InterNetwork)
            .ToList();

        if (!allMxIps.Any())
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No MX IPv4 addresses to check";
            return new List<CheckResult> { result };
        }

        int listed = 0;
        foreach (var ip in allMxIps)
        {
            var octets = ip.Split('.').Reverse();
            var reversed = string.Join('.', octets);

            foreach (var (zone, name) in Blocklists)
            {
                var query = $"{reversed}.{zone}";
                var resp = await ctx.Dns.QueryAsync(query, QueryType.A);
                var aRecs = resp.Answers.ARecords().ToList();
                if (aRecs.Any())
                {
                    var responses = aRecs.Select(a => a.Address.ToString()).ToList();
                    var realListings = responses.Where(r => !FalsePositiveResponses.Contains(r)).ToList();
                    var falsePositives = responses.Where(r => FalsePositiveResponses.Contains(r)).ToList();

                    if (realListings.Any())
                    {
                        listed++;
                        result.Errors.Add($"{ip} is LISTED on {name} ({string.Join(", ", realListings)})");
                    }
                    if (falsePositives.Any())
                        result.Details.Add($"{ip}: {name} returned resolver/error code ({string.Join(", ", falsePositives)})");
                }
                else
                {
                    result.Details.Add($"{ip}: Not listed on {name}");
                }
            }
        }

        result.Severity = listed > 0 ? CheckSeverity.Warning : CheckSeverity.Pass;
        result.Summary = listed > 0 ? $"{listed} extended blocklist listing(s) found" : "Clean on all extended blocklists";
        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Warns if fewer than 2 NS records (RFC 1034 recommends at least 2)
/// </summary>
public class NsMinimumCountCheck : ICheck
{
    public string Name => "NS Minimum Count";
    public CheckCategory Category => CheckCategory.NS;

    public Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        var count = ctx.NsHosts.Count;

        if (count == 0)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No NS records (may be a subdomain)";
        }
        else if (count == 1)
        {
            result.Severity = CheckSeverity.Warning;
            result.Summary = "Only 1 nameserver - no redundancy";
            result.Warnings.Add("RFC 1034 recommends at least 2 nameservers for redundancy");
        }
        else
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = $"{count} nameservers (meets minimum of 2)";
        }

        return Task.FromResult(new List<CheckResult> { result });
    }
}
