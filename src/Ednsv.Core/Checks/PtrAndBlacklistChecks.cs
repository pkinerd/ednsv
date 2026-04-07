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
            int checked_ = 0;
            foreach (var ip in allMxIps)
            {
                if (!IPAddress.TryParse(ip, out var addr)) continue;
                checked_++;

                var ptrs = await ctx.Dns.ResolvePtrAsync(ip);
                if (!ptrs.Any())
                {
                    result.Errors.Add($"{ip}: No PTR record — Gmail requires FCrDNS for all sending IPs");
                    continue;
                }

                bool confirmed = false;
                foreach (var ptr in ptrs)
                {
                    // Check both A and AAAA for forward confirmation
                    var fwdIps = await ctx.Dns.ResolveAAsync(ptr);
                    var fwdIpsV6 = await ctx.Dns.ResolveAAAAAsync(ptr);
                    if (fwdIps.Concat(fwdIpsV6).Contains(ip))
                    {
                        confirmed = true;
                        result.Details.Add($"{ip} -> {ptr} -> {ip} (FCrDNS confirmed)");
                        break;
                    }
                }

                if (confirmed) passed++;
                else result.Errors.Add($"{ip}: PTR {string.Join(",", ptrs)} does not resolve back to {ip}");
            }

            result.Severity = result.Errors.Any() ? CheckSeverity.Error : CheckSeverity.Pass;
            result.Summary = $"FCrDNS: {passed}/{checked_} MX IPs confirmed";
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

    // Lists that work reliably via public DNS resolvers
    private static readonly string[] PublicBlocklists =
    {
        "bl.spamcop.net"
    };

    // Lists that require a private/registered resolver — return false positives via public DNS
    private static readonly string[] PrivateBlocklists =
    {
        "zen.spamhaus.org",
        "b.barracudacentral.org"
    };

    // Well-known DNSBL responses that indicate resolver/query errors, not actual listings
    // Spamhaus: 127.255.255.254 = public/open resolver, 127.255.255.252 = ANY query not supported
    // URIBL/SURBL: 127.0.0.1 = query refused (public resolver)
    private static readonly HashSet<string> FalsePositiveResponses = new(StringComparer.Ordinal)
    {
        "127.255.255.254", "127.255.255.253", "127.255.255.252",
        "127.0.0.1"
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
            var tasks = new List<Task<(string ip, string bl, List<DnsClient.Protocol.ARecord> aRecs)>>();

            foreach (var ip in allMxIps)
            {
                var octets = ip.Split('.').Reverse();
                var reversed = string.Join('.', octets);

                var blocklists = ctx.Options.EnablePrivateDnsbl
                    ? PublicBlocklists.Concat(PrivateBlocklists)
                    : PublicBlocklists;
                foreach (var bl in blocklists)
                {
                    var capturedIp = ip;
                    var capturedBl = bl;
                    var query = $"{reversed}.{bl}";
                    tasks.Add(Task.Run(async () =>
                    {
                        var resp = await ctx.Dns.QueryDnsblAsync(query, QueryType.A);
                        return (capturedIp, capturedBl, resp.Answers.ARecords().ToList());
                    }));
                }
            }

            var results = await Task.WhenAll(tasks);
            foreach (var (ip, bl, aRecs) in results)
            {
                if (aRecs.Any())
                {
                    var responses = aRecs.Select(a => a.Address.ToString()).ToList();
                    var realListings = responses.Where(r => !FalsePositiveResponses.Contains(r)).ToList();
                    var falsePositives = responses.Where(r => FalsePositiveResponses.Contains(r)).ToList();

                    if (realListings.Any())
                    {
                        listed++;
                        result.Errors.Add($"{ip} is LISTED on {bl} ({string.Join(", ", realListings)})");
                    }

                    if (falsePositives.Any())
                    {
                        result.Details.Add($"{ip}: {bl} returned resolver/error code ({string.Join(", ", falsePositives)}) - not a real listing (using public DNS resolver)");
                    }
                }
                else
                {
                    result.Details.Add($"{ip}: Not listed on {bl}");
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

/// <summary>
/// Checks MX hostnames (not just the domain) against domain-based blocklists (RHSBL).
/// MXToolbox checks MX hostnames individually for listing.
/// </summary>
public class MxHostnameBlocklistCheck : ICheck
{
    public string Name => "MX Hostname Blocklist (RHSBL)";
    public CheckCategory Category => CheckCategory.DomainBL;

    // All RHSBL lists require private/registered resolvers
    private static readonly string[] PrivateDomainBlocklists =
    {
        "dbl.spamhaus.org",
        "multi.surbl.org",
        "black.uribl.com"
    };

    private static readonly HashSet<string> FalsePositiveResponses = new(StringComparer.Ordinal)
    {
        "127.255.255.254", "127.255.255.253", "127.255.255.252", "127.0.0.1"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.Options.EnablePrivateDnsbl)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Skipped — MX hostname blocklists (Spamhaus DBL, SURBL, URIBL) require a private DNS resolver (use --private-dnsbl to enable)";
            return new List<CheckResult> { result };
        }

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX hosts to check against domain blocklists";
                return new List<CheckResult> { result };
            }

            // Extract unique base domains from MX hostnames to avoid redundant lookups
            var mxDomains = ctx.MxHosts
                .Select(h => h.TrimEnd('.'))
                .Where(h => h != domain && !h.Equals(domain, StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (!mxDomains.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "MX hostnames same as domain (already checked by domain blocklist check)";
                return new List<CheckResult> { result };
            }

            int listed = 0;
            foreach (var mxDomain in mxDomains)
            {
                foreach (var bl in PrivateDomainBlocklists)
                {
                    var query = $"{mxDomain}.{bl}";
                    var resp = await ctx.Dns.QueryDnsblAsync(query, QueryType.A);
                    var aRecs = resp.Answers.ARecords().ToList();
                    if (aRecs.Any())
                    {
                        var responses = aRecs.Select(a => a.Address.ToString()).ToList();
                        var realListings = responses.Where(r => !FalsePositiveResponses.Contains(r)).ToList();
                        var falsePositives = responses.Where(r => FalsePositiveResponses.Contains(r)).ToList();

                        if (realListings.Any())
                        {
                            listed++;
                            result.Errors.Add($"MX host {mxDomain} is LISTED on {bl} ({string.Join(", ", realListings)})");
                        }
                        if (falsePositives.Any())
                            result.Details.Add($"{mxDomain}: {bl} returned resolver/error code ({string.Join(", ", falsePositives)})");
                    }
                    else
                    {
                        result.Details.Add($"{mxDomain}: Not listed on {bl}");
                    }
                }
            }

            result.Severity = listed > 0 ? CheckSeverity.Critical : CheckSeverity.Pass;
            result.Summary = listed > 0
                ? $"{listed} MX hostname blocklist listing(s) found!"
                : $"MX hostnames clean on all domain blocklists ({mxDomains.Count} checked)";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "MX hostname blocklist check failed";
        }

        return new List<CheckResult> { result };
    }
}

public class DomainBlocklistCheck : ICheck
{
    public string Name => "Domain Blocklist Check";
    public CheckCategory Category => CheckCategory.DomainBL;

    // All domain blocklists require private/registered resolvers
    private static readonly string[] PrivateDomainBlocklists =
    {
        "dbl.spamhaus.org",
        "multi.surbl.org",
        "black.uribl.com"
    };

    // Well-known responses that indicate resolver/query errors, not actual listings
    // Spamhaus DBL: 127.255.255.254 = public/open resolver
    // URIBL: 127.0.0.1 = query refused (public resolver)
    // SURBL: 127.0.0.1 = query refused (public resolver)
    private static readonly HashSet<string> FalsePositiveResponses = new(StringComparer.Ordinal)
    {
        "127.255.255.254", "127.255.255.253", "127.255.255.252",
        "127.0.0.1"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.Options.EnablePrivateDnsbl)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Skipped — domain blocklists (Spamhaus DBL, SURBL, URIBL) require a private DNS resolver (use --private-dnsbl to enable)";
            return new List<CheckResult> { result };
        }

        try
        {
            int listed = 0;
            foreach (var bl in PrivateDomainBlocklists)
            {
                var query = $"{domain}.{bl}";
                var resp = await ctx.Dns.QueryDnsblAsync(query, QueryType.A);
                var aRecs = resp.Answers.ARecords().ToList();
                if (aRecs.Any())
                {
                    var responses = aRecs.Select(a => a.Address.ToString()).ToList();
                    var realListings = responses.Where(r => !FalsePositiveResponses.Contains(r)).ToList();
                    var falsePositives = responses.Where(r => FalsePositiveResponses.Contains(r)).ToList();

                    if (realListings.Any())
                    {
                        listed++;
                        result.Errors.Add($"{domain} is LISTED on {bl} (response: {string.Join(", ", realListings)})");
                    }

                    if (falsePositives.Any())
                    {
                        result.Details.Add($"{domain}: {bl} returned resolver/error code ({string.Join(", ", falsePositives)}) - not a real listing (using public DNS resolver)");
                    }
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
