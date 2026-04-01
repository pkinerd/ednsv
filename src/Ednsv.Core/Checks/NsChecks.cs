using System.Net;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class SoaRecordCheck : ICheck
{
    public string Name => "SOA Record";
    public CheckCategory Category => CheckCategory.SOA;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var soa = await ctx.Dns.GetSoaRecordAsync(domain);
            if (soa != null)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"SOA: {soa.MName.Value.TrimEnd('.')}";
                result.Details.Add($"Primary NS: {soa.MName.Value.TrimEnd('.')}");
                result.Details.Add($"Admin: {soa.RName.Value.TrimEnd('.')}");
                result.Details.Add($"Serial: {soa.Serial}");
                result.Details.Add($"Refresh: {soa.Refresh}s");
                result.Details.Add($"Retry: {soa.Retry}s");
                result.Details.Add($"Expire: {soa.Expire}s");
                result.Details.Add($"Minimum TTL: {soa.Minimum}s");

                // Check serial convention
                var serialStr = soa.Serial.ToString();
                if (serialStr.Length == 10 && serialStr.StartsWith("20"))
                    result.Details.Add("Serial follows YYYYMMDDnn convention");
                else
                    result.Warnings.Add($"Serial {soa.Serial} doesn't follow YYYYMMDDnn convention");

                // RFC 1035 §3.3.13 / RFC 2308 SOA timer validation
                if (soa.Refresh < 3600)
                    result.Warnings.Add($"Refresh interval {soa.Refresh}s is low (recommended >= 3600)");
                if (soa.Retry < 600)
                    result.Warnings.Add($"Retry interval {soa.Retry}s is low (recommended >= 600)");
                if (soa.Retry >= soa.Refresh)
                    result.Warnings.Add($"Retry ({soa.Retry}s) should be less than Refresh ({soa.Refresh}s)");
                if (soa.Expire < 604800)
                    result.Warnings.Add($"Expire interval {soa.Expire}s is low (recommended >= 604800)");
                if (soa.Expire <= soa.Refresh)
                    result.Warnings.Add($"Expire ({soa.Expire}s) must be greater than Refresh ({soa.Refresh}s)");
                // RFC 2308 §5: Minimum TTL field is used as the negative caching TTL
                if (soa.Minimum < 60)
                    result.Warnings.Add($"Minimum TTL {soa.Minimum}s is very low — affects NXDOMAIN cache duration (RFC 2308)");
                else if (soa.Minimum > 86400)
                    result.Warnings.Add($"Minimum TTL {soa.Minimum}s is high — NXDOMAIN responses cached for > 1 day (RFC 2308 recommends 1-3 hours)");
            }
            else
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "No SOA record found";
                result.Warnings.Add("No SOA record found - domain may be a subdomain without its own zone");
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "SOA check failed";
        }

        return new List<CheckResult> { result };
    }
}

public class NsRecordsCheck : ICheck
{
    public string Name => "NS Records";
    public CheckCategory Category => CheckCategory.NS;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var nsRecords = await ctx.Dns.GetNsRecordsAsync(domain);
            if (nsRecords.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"{nsRecords.Count} NS records found";
                foreach (var ns in nsRecords)
                    result.Details.Add($"NS: {ns.NSDName.Value.TrimEnd('.')} (TTL: {ns.TimeToLive}s)");
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No NS records at this name (may be a subdomain)";
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

public class NsLameDelegationCheck : ICheck
{
    public string Name => "NS Lame Delegation";
    public CheckCategory Category => CheckCategory.NS;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        int lameCount = 0;
        int unreachableCount = 0;
        int totalChecked = 0;

        try
        {
            foreach (var nsHost in ctx.NsHosts)
            {
                if (!ctx.NsHostIps.TryGetValue(nsHost, out var ips) || !ips.Any())
                {
                    result.Warnings.Add($"{nsHost}: No IP addresses to test");
                    continue;
                }

                foreach (var ip in ips)
                {
                    totalChecked++;
                    var errorsBefore = ctx.Dns.QueryErrors.Count;
                    var soaResp = await ctx.Dns.QueryServerAsync(IPAddress.Parse(ip), domain, QueryType.SOA);
                    var errorsAfter = ctx.Dns.QueryErrors.Count;

                    if (errorsAfter > errorsBefore)
                    {
                        // Query failed (timeout, network error, etc.) — not the same as lame
                        unreachableCount++;
                        result.Details.Add($"{nsHost} ({ip}): Unreachable (query failed)");
                    }
                    else
                    {
                        var hasSoa = soaResp.Answers.SoaRecords().Any() || soaResp.Authorities.SoaRecords().Any();
                        if (hasSoa)
                        {
                            result.Details.Add($"{nsHost} ({ip}): Authoritative (SOA present)");
                        }
                        else
                        {
                            lameCount++;
                            result.Warnings.Add($"{nsHost} ({ip}): LAME — responded but does not return SOA for {domain}");
                        }
                    }
                }
            }

            if (lameCount > 0)
            {
                result.Severity = CheckSeverity.Error;
                var extra = unreachableCount > 0 ? $", {unreachableCount} unreachable" : "";
                result.Summary = $"{lameCount}/{totalChecked} nameservers are lame{extra}";
            }
            else if (unreachableCount > 0 && unreachableCount < totalChecked)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"{unreachableCount}/{totalChecked} nameservers unreachable (none confirmed lame)";
            }
            else if (unreachableCount > 0)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"All {totalChecked} nameservers unreachable — cannot verify";
            }
            else if (totalChecked > 0)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"All {totalChecked} nameservers are authoritative";
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No nameservers to check";
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

public class NsNetworkDiversityCheck : ICheck
{
    public string Name => "NS Network Diversity";
    public CheckCategory Category => CheckCategory.NS;

    public Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var subnets = new HashSet<string>();
            var allIps = new List<string>();

            foreach (var kvp in ctx.NsHostIps)
            {
                foreach (var ip in kvp.Value)
                {
                    allIps.Add(ip);
                    if (IPAddress.TryParse(ip, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var bytes = addr.GetAddressBytes();
                        subnets.Add($"{bytes[0]}.{bytes[1]}.{bytes[2]}.0/24");
                    }
                    result.Details.Add($"{kvp.Key}: {ip}");
                }
            }

            if (subnets.Count >= 2)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"NS IPs span {subnets.Count} different /24 subnets";
            }
            else if (subnets.Count == 1)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "All NS IPs are in the same /24 subnet";
                result.Warnings.Add("Nameservers lack network diversity - all in same /24");
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No IPv4 NS IPs to check diversity";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return Task.FromResult(new List<CheckResult> { result });
    }
}

/// <summary>
/// Queries SOA from each NS server and compares serial numbers — mismatches indicate
/// replication lag or misconfiguration (MXToolbox "SOA Serial Number" check).
/// </summary>
public class SoaSerialConsistencyCheck : ICheck
{
    public string Name => "SOA Serial Consistency";
    public CheckCategory Category => CheckCategory.SOA;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.NsHosts.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No NS hosts to check SOA serial consistency";
                return new List<CheckResult> { result };
            }

            var serials = new Dictionary<string, uint>();
            var failures = new List<string>();

            foreach (var nsHost in ctx.NsHosts)
            {
                if (!ctx.NsHostIps.TryGetValue(nsHost, out var ips) || !ips.Any())
                {
                    failures.Add($"{nsHost}: No IP addresses");
                    continue;
                }

                foreach (var ip in ips)
                {
                    try
                    {
                        var resp = await ctx.Dns.QueryServerAsync(IPAddress.Parse(ip), domain, QueryType.SOA);
                        var soaRec = resp.Answers.SoaRecords().FirstOrDefault()
                                  ?? resp.Authorities.SoaRecords().FirstOrDefault();
                        if (soaRec != null)
                        {
                            serials[$"{nsHost} ({ip})"] = soaRec.Serial;
                            result.Details.Add($"{nsHost} ({ip}): Serial {soaRec.Serial}");
                        }
                        else
                        {
                            failures.Add($"{nsHost} ({ip}): No SOA in response");
                        }
                    }
                    catch
                    {
                        failures.Add($"{nsHost} ({ip}): Query failed");
                    }
                }
            }

            foreach (var f in failures)
                result.Details.Add(f);

            if (serials.Count < 2)
            {
                result.Severity = serials.Count == 1 ? CheckSeverity.Info : CheckSeverity.Warning;
                result.Summary = serials.Count == 1
                    ? $"Only 1 NS responded with SOA (serial {serials.Values.First()}) — cannot compare"
                    : "No NS servers returned SOA records";
                return new List<CheckResult> { result };
            }

            var uniqueSerials = serials.Values.Distinct().ToList();
            if (uniqueSerials.Count == 1)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"All {serials.Count} nameservers agree on SOA serial {uniqueSerials[0]}";
            }
            else
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"SOA serial mismatch across nameservers ({uniqueSerials.Count} different serials)";
                foreach (var g in serials.GroupBy(kv => kv.Value))
                {
                    result.Warnings.Add($"Serial {g.Key}: {string.Join(", ", g.Select(kv => kv.Key))}");
                }
                result.Warnings.Add("Serial mismatch indicates zone transfer lag or misconfigured secondary nameservers");
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "SOA serial consistency check failed";
        }

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Tests whether NS servers respond to queries for external domains (open recursive resolver),
/// which is a security risk (DNS amplification attacks).
/// </summary>
public class OpenRecursiveResolverCheck : ICheck
{
    public string Name => "Open Recursive Resolver Detection";
    public CheckCategory Category => CheckCategory.NS;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.Options.EnableOpenResolver)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Open resolver check skipped (use --open-resolver to enable)";
            return new List<CheckResult> { result };
        }

        try
        {
            var testDomain = ctx.Options.OpenResolverTestDomain;

            if (!ctx.NsHosts.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No NS hosts to check for open recursion";
                return new List<CheckResult> { result };
            }

            int openCount = 0;
            int checkedCount = 0;

            foreach (var nsHost in ctx.NsHosts)
            {
                if (!ctx.NsHostIps.TryGetValue(nsHost, out var ips) || !ips.Any())
                    continue;

                foreach (var ip in ips)
                {
                    checkedCount++;
                    try
                    {
                        var resp = await ctx.Dns.QueryServerAsync(IPAddress.Parse(ip), testDomain, QueryType.A);
                        var aRecords = resp.Answers.ARecords().ToList();
                        if (aRecords.Any())
                        {
                            openCount++;
                            result.Errors.Add($"{nsHost} ({ip}): Resolved external domain '{testDomain}' — open recursive resolver");
                        }
                        else
                        {
                            result.Details.Add($"{nsHost} ({ip}): Did not resolve external domain (good)");
                        }
                    }
                    catch
                    {
                        // Query failure = not resolving external domains = good
                        result.Details.Add($"{nsHost} ({ip}): Refused/failed external query (good)");
                    }
                }
            }

            if (openCount > 0)
            {
                result.Severity = CheckSeverity.Error;
                result.Summary = $"{openCount}/{checkedCount} nameservers are open recursive resolvers";
                result.Errors.Add("Open resolvers can be abused for DNS amplification attacks — disable recursion for external queries");
            }
            else if (checkedCount > 0)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"All {checkedCount} nameservers correctly refuse external recursive queries";
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No NS IPs available to test";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "Open recursive resolver check failed";
        }

        return new List<CheckResult> { result };
    }
}

public class DuplicateNsIpCheck : ICheck
{
    public string Name => "Duplicate NS IPs";
    public CheckCategory Category => CheckCategory.NS;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        await Task.CompletedTask;

        try
        {
            var ipToHosts = new Dictionary<string, List<string>>();
            foreach (var kvp in ctx.NsHostIps)
            {
                foreach (var ip in kvp.Value)
                {
                    if (!ipToHosts.ContainsKey(ip))
                        ipToHosts[ip] = new List<string>();
                    ipToHosts[ip].Add(kvp.Key);
                }
            }

            var dupes = ipToHosts.Where(kvp => kvp.Value.Count > 1).ToList();
            if (dupes.Any())
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"{dupes.Count} IPs shared by multiple NS hostnames";
                foreach (var dupe in dupes)
                    result.Warnings.Add($"IP {dupe.Key} shared by: {string.Join(", ", dupe.Value)}");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No duplicate NS IPs found";
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
