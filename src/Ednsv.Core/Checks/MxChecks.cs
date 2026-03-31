using System.Net;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class MxRecordsCheck : ICheck
{
    public string Name => "MX Records";
    public CheckCategory Category => CheckCategory.MX;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var mxRecords = await ctx.Dns.GetMxRecordsAsync(domain);
            if (mxRecords.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"{mxRecords.Count} MX record(s) found";

                foreach (var mx in mxRecords)
                {
                    var host = mx.Exchange.Value.TrimEnd('.');
                    ctx.MxHosts.Add(host);

                    var aRecs = await ctx.Dns.ResolveAAsync(host);
                    var aaaaRecs = await ctx.Dns.ResolveAAAAAsync(host);
                    ctx.MxHostIps[host] = aRecs.Concat(aaaaRecs).ToList();

                    var ips = string.Join(", ", aRecs);
                    var ipv6 = aaaaRecs.Any() ? $" IPv6: {string.Join(", ", aaaaRecs)}" : "";

                    // PTR lookups
                    var ptrInfo = new List<string>();
                    foreach (var ip in aRecs)
                    {
                        var ptrs = await ctx.Dns.ResolvePtrAsync(ip);
                        ptrInfo.Add($"{ip} PTR: {(ptrs.Any() ? string.Join(", ", ptrs) : "none")}");
                    }

                    result.Details.Add($"Priority {mx.Preference}: {host} -> {ips}{ipv6}");
                    foreach (var ptr in ptrInfo)
                        result.Details.Add($"  {ptr}");

                    // Probe STARTTLS
                    if (aRecs.Any())
                    {
                        var probe = await ctx.Smtp.ProbeSmtpAsync(host, 25);
                        if (probe.Connected)
                        {
                            result.Details.Add($"  SMTP: Connected, STARTTLS: {(probe.SupportsStartTls ? "Yes" : "No")}");
                            if (!probe.SupportsStartTls)
                                result.Warnings.Add($"MX {host} does not support STARTTLS");
                        }
                        else
                        {
                            result.Details.Add($"  SMTP: Could not connect ({probe.Error ?? "timeout"})");
                        }
                    }
                }
            }
            else
            {
                // RFC 5321 §5: If no MX records, fall back to A/AAAA for the domain itself
                var fallbackA = await ctx.Dns.ResolveAAsync(domain);
                var fallbackAAAA = await ctx.Dns.ResolveAAAAAsync(domain);
                if (fallbackA.Any() || fallbackAAAA.Any())
                {
                    result.Severity = CheckSeverity.Warning;
                    result.Summary = "No MX records — using implicit A/AAAA fallback (RFC 5321 §5)";
                    result.Warnings.Add("No MX records found — SMTP will attempt delivery to the domain's A/AAAA addresses directly");
                    foreach (var ip in fallbackA)
                        result.Details.Add($"  Fallback A: {ip}");
                    foreach (var ip in fallbackAAAA)
                        result.Details.Add($"  Fallback AAAA: {ip}");
                }
                else
                {
                    result.Severity = CheckSeverity.Error;
                    result.Summary = "No MX records and no A/AAAA fallback — domain cannot receive email";
                    result.Errors.Add("No MX records and no A/AAAA records for the domain — mail delivery is impossible (RFC 5321 §5)");
                }
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

public class MxIpDetectionCheck : ICheck
{
    public string Name => "MX-to-IP Detection";
    public CheckCategory Category => CheckCategory.MX;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        await Task.CompletedTask;

        bool hasIpMx = false;
        foreach (var host in ctx.MxHosts)
        {
            if (IPAddress.TryParse(host, out _))
            {
                hasIpMx = true;
                result.Errors.Add($"MX points to IP address '{host}' - violates RFC 5321 §5.1");
            }
        }

        result.Severity = hasIpMx ? CheckSeverity.Error : CheckSeverity.Pass;
        result.Summary = hasIpMx ? "MX records point to bare IPs (RFC violation)" : "No MX-to-IP issues";
        return new List<CheckResult> { result };
    }
}

public class MxCnameCheck : ICheck
{
    public string Name => "MX CNAME Check";
    public CheckCategory Category => CheckCategory.MX;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        bool hasCname = false;
        foreach (var host in ctx.MxHosts)
        {
            var chain = await ctx.Dns.ResolveCnameChainAsync(host);
            if (chain.Any())
            {
                hasCname = true;
                result.Warnings.Add($"MX host {host} is a CNAME: {string.Join(" -> ", chain)} (RFC 5321 violation)");
            }
        }

        result.Severity = hasCname ? CheckSeverity.Warning : CheckSeverity.Pass;
        result.Summary = hasCname ? "MX hosts resolve via CNAME (not recommended)" : "No MX CNAME issues";
        return new List<CheckResult> { result };
    }
}

public class NullMxCheck : ICheck
{
    public string Name => "Null MX / Duplicates";
    public CheckCategory Category => CheckCategory.MX;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var mxRecords = await ctx.Dns.GetMxRecordsAsync(domain);

            // Check null MX (RFC 7505): single MX with preference 0 and empty exchange "."
            var nullMxRecords = mxRecords.Where(m => m.Exchange.Value.TrimEnd('.') == "" || m.Exchange.Value == ".").ToList();
            if (nullMxRecords.Any())
            {
                var nullMxRec = nullMxRecords.First();
                if (nullMxRec.Preference != 0)
                    result.Warnings.Add($"Null MX record has preference {nullMxRec.Preference} — RFC 7505 §3 requires preference 0");
                if (mxRecords.Count > 1)
                    result.Warnings.Add($"Null MX present alongside {mxRecords.Count - 1} other MX record(s) — RFC 7505 §3 requires it to be the only MX");
                result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Info;
                result.Summary = "Null MX (RFC 7505) - domain explicitly does not accept email";
                result.Details.Add("Domain has declared it does not accept email via null MX");
                return new List<CheckResult> { result };
            }

            // Check duplicates
            var hosts = mxRecords.Select(m => m.Exchange.Value.TrimEnd('.').ToLowerInvariant()).ToList();
            var dupes = hosts.GroupBy(h => h).Where(g => g.Count() > 1).ToList();
            if (dupes.Any())
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "Duplicate MX hosts found";
                foreach (var d in dupes)
                    result.Warnings.Add($"Duplicate MX: {d.Key} appears {d.Count()} times");
            }

            // Check localhost MX
            if (hosts.Any(h => h == "localhost" || h == "127.0.0.1"))
            {
                result.Severity = CheckSeverity.Error;
                result.Errors.Add("MX points to localhost");
            }

            if (result.Severity == default)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No null MX or duplicate issues";
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

public class MxPriorityDistributionCheck : ICheck
{
    public string Name => "MX Priority Distribution";
    public CheckCategory Category => CheckCategory.MX;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var mxRecords = await ctx.Dns.GetMxRecordsAsync(domain);
            if (!mxRecords.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX records to analyze";
                return new List<CheckResult> { result };
            }

            var priorities = mxRecords.Select(m => (int)m.Preference).ToList();
            result.Details.Add($"Priorities: {string.Join(", ", priorities)}");

            if (mxRecords.Count == 1)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "Single MX record - no failover";
                result.Warnings.Add("Only one MX record - if it goes down, email delivery will be delayed");
            }
            else
            {
                var distinctPriorities = priorities.Distinct().Count();
                if (distinctPriorities == 1)
                {
                    result.Details.Add("All MX records have same priority (round-robin)");
                }

                var sorted = priorities.OrderBy(p => p).ToList();
                for (int i = 1; i < sorted.Count; i++)
                {
                    var gap = sorted[i] - sorted[i - 1];
                    if (gap > 50)
                        result.Details.Add($"Large priority gap: {sorted[i - 1]} -> {sorted[i]} (gap: {gap})");
                }

                result.Severity = CheckSeverity.Pass;
                result.Summary = $"{mxRecords.Count} MX records with {distinctPriorities} priority level(s)";
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

public class MxBackupSecurityCheck : ICheck
{
    public string Name => "MX Backup Security Parity";
    public CheckCategory Category => CheckCategory.MX;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var mxRecords = await ctx.Dns.GetMxRecordsAsync(domain);
            if (mxRecords.Count <= 1)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "Single or no MX - backup parity check not applicable";
                return new List<CheckResult> { result };
            }

            var noTls = new List<string>();
            foreach (var mx in mxRecords)
            {
                var host = mx.Exchange.Value.TrimEnd('.');
                var probe = await ctx.Smtp.ProbeSmtpAsync(host, 25);
                if (probe.Connected && !probe.SupportsStartTls)
                    noTls.Add(host);
                else if (probe.Connected)
                    result.Details.Add($"{host}: STARTTLS supported");
                else
                    result.Details.Add($"{host}: Could not connect");
            }

            if (noTls.Any())
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"{noTls.Count} backup MX host(s) lack STARTTLS";
                foreach (var h in noTls)
                    result.Warnings.Add($"{h} does not support STARTTLS");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "All MX hosts support STARTTLS";
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
