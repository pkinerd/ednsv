using System.Net;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class DelegationChainCheck : ICheck
{
    public string Name => "Delegation Chain";
    public CheckCategory Category => CheckCategory.Delegation;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category, Severity = CheckSeverity.Info };
        var parts = domain.Split('.');

        try
        {
            // Walk from TLD down
            for (int i = parts.Length - 1; i >= 0; i--)
            {
                var zone = string.Join('.', parts.Skip(i));
                if (string.IsNullOrEmpty(zone)) continue;

                var nsResponse = await ctx.Dns.QueryAsync(zone, QueryType.NS);
                var nsRecords = nsResponse.Answers.NsRecords().ToList();
                if (nsRecords.Any())
                {
                    var nsNames = string.Join(", ", nsRecords.Select(n => n.NSDName.Value.TrimEnd('.')));
                    result.Details.Add($"Zone [{zone}] NS: {nsNames}");
                }
            }

            // Check for CNAME at zone cut
            var cnameResp = await ctx.Dns.QueryAsync(domain, QueryType.CNAME);
            var cnames = cnameResp.Answers.CnameRecords().ToList();
            if (cnames.Any())
            {
                var nsResp = await ctx.Dns.QueryAsync(domain, QueryType.NS);
                if (nsResp.Answers.NsRecords().Any())
                {
                    result.Warnings.Add("CNAME found at zone cut - this is a protocol violation");
                    result.Severity = CheckSeverity.Warning;
                }
            }

            if (!result.Warnings.Any())
                result.Severity = CheckSeverity.Pass;

            result.Summary = $"Delegation chain walked through {parts.Length} levels";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add($"Failed to walk delegation chain: {ex.Message}");
            result.Summary = "Delegation chain check failed";
        }

        return new List<CheckResult> { result };
    }
}

public class AuthoritativeNsCheck : ICheck
{
    public string Name => "Authoritative NS";
    public CheckCategory Category => CheckCategory.Delegation;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category, Severity = CheckSeverity.Info };

        try
        {
            var nsRecords = await ctx.Dns.GetNsRecordsAsync(domain);
            if (!nsRecords.Any())
            {
                // Try parent domain
                var parentParts = domain.Split('.');
                if (parentParts.Length > 2)
                {
                    var parent = string.Join('.', parentParts.Skip(1));
                    nsRecords = await ctx.Dns.GetNsRecordsAsync(parent);
                    if (nsRecords.Any())
                        result.Details.Add($"NS records found at parent zone: {parent}");
                }
            }

            foreach (var ns in nsRecords)
            {
                var nsHost = ns.NSDName.Value.TrimEnd('.');
                ctx.NsHosts.Add(nsHost);

                var aRecords = await ctx.Dns.ResolveAAsync(nsHost);
                ctx.NsHostIps[nsHost] = aRecords;

                foreach (var ip in aRecords)
                {
                    var ptrs = await ctx.Dns.ResolvePtrAsync(ip);
                    var ptrStr = ptrs.Any() ? string.Join(", ", ptrs) : "No PTR";
                    result.Details.Add($"NS: {nsHost} -> {ip} (PTR: {ptrStr})");
                }
                if (!aRecords.Any())
                    result.Details.Add($"NS: {nsHost} -> No A records found");
            }

            result.Summary = $"Found {nsRecords.Count} authoritative nameservers";
            result.Severity = nsRecords.Any() ? CheckSeverity.Pass : CheckSeverity.Warning;
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "Failed to resolve authoritative NS";
        }

        return new List<CheckResult> { result };
    }
}

public class DelegationConsistencyCheck : ICheck
{
    public string Name => "Delegation Consistency";
    public CheckCategory Category => CheckCategory.Delegation;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category, Severity = CheckSeverity.Info };

        try
        {
            // Get NS from direct query (child perspective)
            var childNs = await ctx.Dns.GetNsRecordsAsync(domain);
            var childSet = childNs.Select(n => n.NSDName.Value.TrimEnd('.').ToLowerInvariant()).ToHashSet();

            // Query parent for delegation
            var parts = domain.Split('.');
            if (parts.Length >= 2)
            {
                var tld = string.Join('.', parts.Skip(1));
                var parentResp = await ctx.Dns.QueryAsync(tld, QueryType.NS);
                var parentNsIps = parentResp.Answers.NsRecords()
                    .Select(n => n.NSDName.Value.TrimEnd('.'))
                    .ToList();

                // Query one of the parent's NS for delegation
                if (parentNsIps.Any())
                {
                    var parentNsHost = parentNsIps.First();
                    var parentIps = await ctx.Dns.ResolveAAsync(parentNsHost);
                    if (parentIps.Any())
                    {
                        var parentResp2 = await ctx.Dns.QueryServerAsync(
                            IPAddress.Parse(parentIps.First()), domain, QueryType.NS);
                        var parentDelegation = parentResp2.Answers.NsRecords()
                            .Concat(parentResp2.Authorities.NsRecords())
                            .Select(n => n.NSDName.Value.TrimEnd('.').ToLowerInvariant())
                            .ToHashSet();

                        if (parentDelegation.Any())
                        {
                            var onlyInParent = parentDelegation.Except(childSet).ToList();
                            var onlyInChild = childSet.Except(parentDelegation).ToList();

                            if (onlyInParent.Any())
                                result.Warnings.Add($"NS only in parent: {string.Join(", ", onlyInParent)}");
                            if (onlyInChild.Any())
                                result.Warnings.Add($"NS only in child: {string.Join(", ", onlyInChild)}");

                            if (!onlyInParent.Any() && !onlyInChild.Any())
                            {
                                result.Severity = CheckSeverity.Pass;
                                result.Details.Add("Parent and child NS sets are consistent");
                            }
                            else
                            {
                                result.Severity = CheckSeverity.Warning;
                            }

                            result.Details.Add($"Parent NS set: {string.Join(", ", parentDelegation)}");
                            result.Details.Add($"Child NS set: {string.Join(", ", childSet)}");
                        }
                        else
                        {
                            result.Details.Add("Could not retrieve parent delegation records");
                            result.Severity = childSet.Any() ? CheckSeverity.Pass : CheckSeverity.Warning;
                        }
                    }
                }
            }

            result.Summary = "Delegation consistency check completed";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "Failed delegation consistency check";
        }

        return new List<CheckResult> { result };
    }
}
