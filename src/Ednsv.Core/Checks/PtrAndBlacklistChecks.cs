using System.Net;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class ReverseDnsCheck : ICheck
{
    public string Name => "Reverse DNS (PTR)";
    public CheckCategory Category => CheckCategory.PTR;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var allIps = ctx.DomainARecords.ToList();
            if (!allIps.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No A records to check PTR for";
                return new List<CheckResult> { result };
            }

            int matched = 0;
            foreach (var ip in allIps)
            {
                var ptrs = await ctx.Dns.ResolvePtrAsync(ip);
                if (ptrs.Any())
                {
                    var matchesDomain = ptrs.Any(p =>
                        p.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                        p.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
                    result.Details.Add($"{ip} -> {string.Join(", ", ptrs)} {(matchesDomain ? "(matches)" : "(no match)")}");
                    if (matchesDomain) matched++;
                }
                else
                {
                    result.Warnings.Add($"{ip}: No PTR record");
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"PTR check: {matched}/{allIps.Count} IPs have matching reverse DNS";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class ForwardConfirmedRdnsCheck : ICheck
{
    public string Name => "Forward-Confirmed rDNS (FCrDNS)";
    public CheckCategory Category => CheckCategory.FCrDNS;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var allMxIps = ctx.MxHostIps.Values.SelectMany(v => v).Distinct().ToList();
            if (!allMxIps.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX IPs to check FCrDNS";
                return new List<CheckResult> { result };
            }

            int passed = 0;
            foreach (var ip in allMxIps)
            {
                if (!IPAddress.TryParse(ip, out var addr)) continue;
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) continue; // skip IPv6 for simplicity

                var ptrs = await ctx.Dns.ResolvePtrAsync(ip);
                if (!ptrs.Any())
                {
                    result.Warnings.Add($"{ip}: No PTR record");
                    continue;
                }

                bool confirmed = false;
                foreach (var ptr in ptrs)
                {
                    var fwdIps = await ctx.Dns.ResolveAAsync(ptr);
                    if (fwdIps.Contains(ip))
                    {
                        confirmed = true;
                        result.Details.Add($"{ip} -> {ptr} -> {ip} (FCrDNS confirmed)");
                        break;
                    }
                }

                if (confirmed) passed++;
                else result.Warnings.Add($"{ip}: PTR {string.Join(",", ptrs)} does not resolve back to {ip}");
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"FCrDNS: {passed}/{allMxIps.Count} MX IPs confirmed";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class IpBlocklistCheck : ICheck
{
    public string Name => "IP Blocklist Check (DNSBL)";
    public CheckCategory Category => CheckCategory.DNSBL;

    private static readonly string[] Blocklists =
    {
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "bl.spamcop.net"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var allMxIps = ctx.MxHostIps.Values.SelectMany(v => v).Distinct()
                .Where(ip => IPAddress.TryParse(ip, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .ToList();

            if (!allMxIps.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX IPv4 addresses to check against blocklists";
                return new List<CheckResult> { result };
            }

            int listed = 0;
            foreach (var ip in allMxIps)
            {
                var octets = ip.Split('.').Reverse();
                var reversed = string.Join('.', octets);

                foreach (var bl in Blocklists)
                {
                    var query = $"{reversed}.{bl}";
                    var resp = await ctx.Dns.QueryAsync(query, QueryType.A);
                    var aRecs = resp.Answers.ARecords().ToList();
                    if (aRecs.Any())
                    {
                        listed++;
                        result.Errors.Add($"{ip} is LISTED on {bl} ({string.Join(", ", aRecs.Select(a => a.Address))})");
                    }
                    else
                    {
                        result.Details.Add($"{ip}: Not listed on {bl}");
                    }
                }
            }

            result.Severity = listed > 0 ? CheckSeverity.Critical : CheckSeverity.Pass;
            result.Summary = listed > 0 ? $"{listed} blocklist listing(s) found!" : "No IP blocklist listings";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class DomainBlocklistCheck : ICheck
{
    public string Name => "Domain Blocklist Check";
    public CheckCategory Category => CheckCategory.DomainBL;

    private static readonly string[] DomainBlocklists =
    {
        "dbl.spamhaus.org",
        "multi.surbl.org",
        "black.uribl.com"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            int listed = 0;
            foreach (var bl in DomainBlocklists)
            {
                var query = $"{domain}.{bl}";
                var resp = await ctx.Dns.QueryAsync(query, QueryType.A);
                var aRecs = resp.Answers.ARecords().ToList();
                if (aRecs.Any())
                {
                    var returnCodes = string.Join(", ", aRecs.Select(a => a.Address));
                    // Filter out NXDOMAIN-like responses (127.0.0.1 is often "not listed" for some)
                    listed++;
                    result.Errors.Add($"{domain} is LISTED on {bl} (response: {returnCodes})");
                }
                else
                {
                    result.Details.Add($"{domain}: Not listed on {bl}");
                }
            }

            result.Severity = listed > 0 ? CheckSeverity.Critical : CheckSeverity.Pass;
            result.Summary = listed > 0 ? $"Domain is listed on {listed} blocklist(s)!" : "Domain not on any blocklists";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}
