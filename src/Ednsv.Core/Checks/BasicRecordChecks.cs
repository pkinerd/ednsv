using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class CnameChainCheck : ICheck
{
    public string Name => "CNAME Chain";
    public CheckCategory Category => CheckCategory.CNAME;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var chain = await ctx.Dns.ResolveCnameChainAsync(domain);
            if (chain.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = $"CNAME chain with {chain.Count} hop(s)";
                foreach (var hop in chain)
                    result.Details.Add(hop);

                // Check if apex has CNAME
                var parts = domain.Split('.');
                if (parts.Length == 2) // apex domain
                {
                    result.Severity = CheckSeverity.Warning;
                    result.Warnings.Add("CNAME at apex/root domain - this violates RFC 1034 and can break MX/NS records");
                }
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No CNAME chain (direct resolution)";
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

public class ARecordCheck : ICheck
{
    public string Name => "A Records";
    public CheckCategory Category => CheckCategory.A;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var response = await ctx.Dns.QueryRawAsync(domain, QueryType.A);
            var records = response.Answers.ARecords().ToList();
            if (records.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"{records.Count} A record(s) found";
                foreach (var a in records)
                {
                    result.Details.Add($"{a.Address} (TTL: {a.TimeToLive}s)");
                    ctx.DomainARecords.Add(a.Address.ToString());
                }
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No A records found";
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

public class AAAARecordCheck : ICheck
{
    public string Name => "AAAA Records";
    public CheckCategory Category => CheckCategory.AAAA;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var response = await ctx.Dns.QueryRawAsync(domain, QueryType.AAAA);
            var records = response.Answers.AaaaRecords().ToList();
            if (records.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"{records.Count} AAAA record(s) found";
                foreach (var a in records)
                {
                    result.Details.Add($"{a.Address} (TTL: {a.TimeToLive}s)");
                    ctx.DomainAAAARecords.Add(a.Address.ToString());
                }
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No AAAA records found";
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
