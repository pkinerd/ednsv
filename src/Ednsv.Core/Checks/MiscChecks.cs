using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class SrvRecordsCheck : ICheck
{
    public string Name => "Mail Service SRV Records";
    public CheckCategory Category => CheckCategory.SRV;

    private static readonly string[] SrvNames =
    {
        "_submission._tcp",
        "_imap._tcp",
        "_imaps._tcp",
        "_pop3s._tcp",
        "_jmap._tcp"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        int found = 0;

        try
        {
            foreach (var srv in SrvNames)
            {
                var srvDomain = $"{srv}.{domain}";
                var resp = await ctx.Dns.QueryRawAsync(srvDomain, QueryType.SRV);
                var srvRecords = resp.Answers.SrvRecords().ToList();

                if (srvRecords.Any())
                {
                    found += srvRecords.Count;
                    foreach (var s in srvRecords)
                        result.Details.Add($"{srv}: {s.Target.Value.TrimEnd('.')}:{s.Port} (priority={s.Priority}, weight={s.Weight})");
                }
                else
                {
                    result.Details.Add($"{srv}: Not found");
                }
            }

            result.Severity = found > 0 ? CheckSeverity.Pass : CheckSeverity.Info;
            result.Summary = found > 0 ? $"{found} mail SRV record(s) found" : "No mail SRV records";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class AutodiscoverCheck : ICheck
{
    public string Name => "Autodiscover";
    public CheckCategory Category => CheckCategory.Autodiscover;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            // Check SRV
            var srvDomain = $"_autodiscover._tcp.{domain}";
            var srvResp = await ctx.Dns.QueryRawAsync(srvDomain, QueryType.SRV);
            var srvRecords = srvResp.Answers.SrvRecords().ToList();

            if (srvRecords.Any())
            {
                foreach (var s in srvRecords)
                    result.Details.Add($"SRV: {s.Target.Value.TrimEnd('.')}:{s.Port}");
            }
            else
            {
                result.Details.Add("_autodiscover._tcp SRV: Not found");
            }

            // Check autodiscover CNAME/A
            var autoHost = $"autodiscover.{domain}";
            var chain = await ctx.Dns.ResolveCnameChainAsync(autoHost);
            if (chain.Any())
            {
                result.Details.Add($"autodiscover.{domain}: {string.Join(" -> ", chain)}");
            }
            else
            {
                var aRecs = await ctx.Dns.ResolveAAsync(autoHost);
                if (aRecs.Any())
                    result.Details.Add($"autodiscover.{domain}: {string.Join(", ", aRecs)}");
                else
                    result.Details.Add($"autodiscover.{domain}: Not found");
            }

            result.Severity = (srvRecords.Any() || chain.Any()) ? CheckSeverity.Pass : CheckSeverity.Info;
            result.Summary = srvRecords.Any() || chain.Any() ? "Autodiscover configured" : "No autodiscover found";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class Ipv6ReadinessCheck : ICheck
{
    public string Name => "IPv6 Readiness";
    public CheckCategory Category => CheckCategory.IPv6;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            int withIpv6 = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var aaaaRecs = await ctx.Dns.ResolveAAAAAsync(mxHost);
                if (aaaaRecs.Any())
                {
                    withIpv6++;
                    result.Details.Add($"{mxHost}: {string.Join(", ", aaaaRecs)}");
                }
                else
                {
                    result.Details.Add($"{mxHost}: No AAAA records");
                }
            }

            if (ctx.MxHosts.Any())
            {
                result.Severity = withIpv6 == ctx.MxHosts.Count ? CheckSeverity.Pass :
                                 withIpv6 > 0 ? CheckSeverity.Warning : CheckSeverity.Info;
                result.Summary = $"{withIpv6}/{ctx.MxHosts.Count} MX hosts have IPv6";
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX hosts to check IPv6";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class WildcardDnsCheck : ICheck
{
    public string Name => "Wildcard DNS";
    public CheckCategory Category => CheckCategory.Wildcard;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var randomSub = $"ednsv-wildcard-test-{Guid.NewGuid():N}.{domain}";

            var aResp = await ctx.Dns.ResolveAAsync(randomSub);
            var mxResp = await ctx.Dns.GetMxRecordsAsync(randomSub);
            var spfTxts = await ctx.Dns.GetTxtRecordsAsync(randomSub);
            var hasSpf = spfTxts.Any(t => t.Text.Any(s => s.Contains("v=spf1", StringComparison.OrdinalIgnoreCase)));

            if (aResp.Any())
            {
                result.Warnings.Add($"Wildcard A record detected: {string.Join(", ", aResp)}");
            }
            if (mxResp.Any())
            {
                result.Warnings.Add("Wildcard MX record detected");
            }
            if (hasSpf)
            {
                result.Warnings.Add("Wildcard SPF record detected");
            }

            if (result.Warnings.Any())
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "Wildcard DNS records detected";
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No wildcard DNS records";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class TtlSanityCheck : ICheck
{
    public string Name => "TTL Sanity";
    public CheckCategory Category => CheckCategory.TTL;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var checks = new List<(string name, QueryType type, string queryDomain)>
            {
                ("MX", QueryType.MX, domain),
                ("SPF/TXT", QueryType.TXT, domain),
                ("DMARC", QueryType.TXT, $"_dmarc.{domain}"),
            };

            foreach (var (name, type, queryDomain) in checks)
            {
                var resp = await ctx.Dns.QueryRawAsync(queryDomain, type);
                var ttls = resp.Answers.Select(a => a.TimeToLive).Distinct().ToList();
                var label = $"{name} ({queryDomain})";

                if (!ttls.Any()) continue;

                foreach (var ttl in ttls)
                {
                    if (ttl < 60)
                    {
                        result.Warnings.Add($"{label}: TTL {ttl}s is very low (< 60s)");
                    }
                    else if (ttl > 86400)
                    {
                        result.Warnings.Add($"{label}: TTL {ttl}s is very high (> 86400s)");
                    }
                    else
                    {
                        result.Details.Add($"{label}: TTL {ttl}s");
                    }
                }

                if (ttls.Count > 1)
                {
                    result.Warnings.Add($"{label}: inconsistent TTLs across records ({string.Join(", ", ttls.Select(t => $"{t}s"))})");
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = result.Warnings.Any() ? "TTL issues detected" : "TTLs within reasonable range";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class AllTxtRecordsCheck : ICheck
{
    public string Name => "All TXT Records";
    public CheckCategory Category => CheckCategory.TXT;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var txts = await ctx.Dns.GetTxtRecordsAsync(domain);
            if (txts.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = $"{txts.Count} TXT record(s) found";
                foreach (var txt in txts)
                {
                    var text = string.Join("", txt.Text);
                    result.Details.Add($"TXT: {text}");
                }
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No TXT records found";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}
