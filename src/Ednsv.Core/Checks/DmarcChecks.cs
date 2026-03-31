using System.Text.RegularExpressions;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class DmarcRecordCheck : ICheck
{
    public string Name => "DMARC Record";
    public CheckCategory Category => CheckCategory.DMARC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var dmarcDomain = $"_dmarc.{domain}";
            var txts = await ctx.Dns.GetTxtRecordsAsync(dmarcDomain);
            var dmarcRecords = txts
                .Where(t => t.Text.Any(s => s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (!dmarcRecords.Any())
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "No DMARC record found";
                result.Warnings.Add("No DMARC record at _dmarc." + domain);
                return new List<CheckResult> { result };
            }

            if (dmarcRecords.Count > 1)
            {
                result.Severity = CheckSeverity.Error;
                result.Errors.Add("Multiple DMARC records found - only one is allowed");
            }

            var dmarcText = string.Join("", dmarcRecords[0].Text);
            ctx.DmarcRecord = dmarcText;
            result.Details.Add($"DMARC: {dmarcText}");

            // Parse tags
            var tags = ParseDmarcTags(dmarcText);

            if (tags.TryGetValue("p", out var policy))
            {
                result.Details.Add($"Policy (p): {policy}");
                if (policy == "none")
                    result.Warnings.Add("DMARC policy is 'none' - no enforcement");
            }
            if (tags.TryGetValue("sp", out var sp))
                result.Details.Add($"Subdomain policy (sp): {sp}");
            if (tags.TryGetValue("pct", out var pct))
                result.Details.Add($"Percentage (pct): {pct}%");
            if (tags.TryGetValue("adkim", out var adkim))
                result.Details.Add($"DKIM alignment (adkim): {adkim}");
            if (tags.TryGetValue("aspf", out var aspf))
                result.Details.Add($"SPF alignment (aspf): {aspf}");
            if (tags.TryGetValue("rua", out var rua))
                result.Details.Add($"Aggregate reports (rua): {rua}");
            if (tags.TryGetValue("ruf", out var ruf))
                result.Details.Add($"Forensic reports (ruf): {ruf}");
            if (tags.TryGetValue("fo", out var fo))
                result.Details.Add($"Failure options (fo): {fo}");
            if (tags.TryGetValue("rf", out var rf))
                result.Details.Add($"Report format (rf): {rf}");
            if (tags.TryGetValue("ri", out var ri))
                result.Details.Add($"Report interval (ri): {ri}s");

            if (result.Severity == default)
            {
                result.Severity = policy == "reject" || policy == "quarantine" ? CheckSeverity.Pass : CheckSeverity.Warning;
            }
            result.Summary = $"DMARC p={policy ?? "unknown"}";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }

    public static Dictionary<string, string> ParseDmarcTags(string dmarc)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // Remove v=DMARC1 prefix
        var content = dmarc;
        if (content.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
            content = content.Substring(8);

        foreach (var part in content.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            var eqIdx = trimmed.IndexOf('=');
            if (eqIdx > 0)
            {
                var key = trimmed.Substring(0, eqIdx).Trim();
                var value = trimmed.Substring(eqIdx + 1).Trim();
                tags[key] = value;
            }
        }
        return tags;
    }
}

public class DmarcInheritanceCheck : ICheck
{
    public string Name => "DMARC Inheritance";
    public CheckCategory Category => CheckCategory.DMARC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            // Check if there's a DMARC at this domain
            var dmarcDomain = $"_dmarc.{domain}";
            var txts = await ctx.Dns.GetTxtRecordsAsync(dmarcDomain);
            var hasDmarc = txts.Any(t => t.Text.Any(s => s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)));

            if (hasDmarc)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "DMARC record exists at this domain level";
                result.Details.Add("No inheritance needed - DMARC found directly");
                return new List<CheckResult> { result };
            }

            // Walk up parent domains
            var parts = domain.Split('.');
            for (int i = 1; i < parts.Length - 1; i++)
            {
                var parent = string.Join('.', parts.Skip(i));
                var parentDmarc = $"_dmarc.{parent}";
                var parentTxts = await ctx.Dns.GetTxtRecordsAsync(parentDmarc);
                var parentRecord = parentTxts.FirstOrDefault(t =>
                    t.Text.Any(s => s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)));

                if (parentRecord != null)
                {
                    var dmarcText = string.Join("", parentRecord.Text);
                    result.Severity = CheckSeverity.Info;
                    result.Summary = $"DMARC inherited from {parent}";
                    result.Details.Add($"Inherited DMARC from {parent}: {dmarcText}");

                    var tags = DmarcRecordCheck.ParseDmarcTags(dmarcText);
                    if (tags.TryGetValue("sp", out var sp))
                        result.Details.Add($"Subdomain policy (sp) applied: {sp}");
                    else if (tags.TryGetValue("p", out var p))
                        result.Details.Add($"Policy (p) inherited as subdomain policy: {p}");

                    return new List<CheckResult> { result };
                }
            }

            result.Severity = CheckSeverity.Warning;
            result.Summary = "No DMARC record found in hierarchy";
            result.Warnings.Add("No DMARC policy applies to this domain");
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class DmarcExternalReportAuthCheck : ICheck
{
    public string Name => "DMARC External Report Auth";
    public CheckCategory Category => CheckCategory.DMARC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (ctx.DmarcRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No DMARC record to check";
                return new List<CheckResult> { result };
            }

            var tags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
            var reportUris = new List<string>();

            if (tags.TryGetValue("rua", out var rua))
                reportUris.AddRange(rua.Split(',').Select(u => u.Trim()));
            if (tags.TryGetValue("ruf", out var ruf))
                reportUris.AddRange(ruf.Split(',').Select(u => u.Trim()));

            if (!reportUris.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No DMARC report URIs configured";
                return new List<CheckResult> { result };
            }

            foreach (var uri in reportUris)
            {
                if (!uri.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) continue;
                var email = uri.Substring(7).Split('!')[0]; // remove size limit
                var atIdx = email.IndexOf('@');
                if (atIdx < 0) continue;

                var reportDomain = email.Substring(atIdx + 1).ToLowerInvariant();
                if (reportDomain == domain.ToLowerInvariant())
                {
                    result.Details.Add($"{uri}: Same domain (no external auth needed)");
                    continue;
                }

                // Check external authorization
                var authDomain = $"{domain}._report._dmarc.{reportDomain}";
                var authTxts = await ctx.Dns.GetTxtRecordsAsync(authDomain);
                var hasAuth = authTxts.Any(t => t.Text.Any(s =>
                    s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)));

                if (hasAuth)
                {
                    result.Details.Add($"{uri}: External report authorization found at {authDomain}");
                }
                else
                {
                    result.Warnings.Add($"{uri}: No external authorization at {authDomain} - reports may not be delivered");
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"Checked {reportUris.Count} report URI(s)";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class DmarcReportTargetMxCheck : ICheck
{
    public string Name => "DMARC Report Target MX";
    public CheckCategory Category => CheckCategory.DMARC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (ctx.DmarcRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No DMARC record";
                return new List<CheckResult> { result };
            }

            var tags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
            var checked_ = 0;

            foreach (var tag in new[] { "rua", "ruf" })
            {
                if (!tags.TryGetValue(tag, out var uris)) continue;
                foreach (var uri in uris.Split(','))
                {
                    if (!uri.Trim().StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) continue;
                    var email = uri.Trim().Substring(7).Split('!')[0];
                    var atIdx = email.IndexOf('@');
                    if (atIdx < 0) continue;

                    var reportDomain = email.Substring(atIdx + 1);
                    checked_++;
                    var mx = await ctx.Dns.GetMxRecordsAsync(reportDomain);
                    if (mx.Any())
                    {
                        result.Details.Add($"{reportDomain}: Has {mx.Count} MX record(s)");
                    }
                    else
                    {
                        result.Warnings.Add($"{reportDomain}: No MX records - reports may not be deliverable");
                    }
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = checked_ > 0 ? $"Checked MX for {checked_} report target(s)" : "No report targets to check";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class SpfDmarcCombinedCheck : ICheck
{
    public string Name => "SPF+DMARC Combined";
    public CheckCategory Category => CheckCategory.DMARC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        await Task.CompletedTask;

        if (ctx.SpfRecord == null || ctx.DmarcRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Cannot check combo - missing SPF or DMARC";
            return new List<CheckResult> { result };
        }

        var spfAll = "";
        var spfParts = ctx.SpfRecord.Split(' ');
        var allMech = spfParts.LastOrDefault(p => p.TrimStart('+', '-', '~', '?').StartsWith("all"));
        if (allMech != null) spfAll = allMech;

        var dmarcTags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
        dmarcTags.TryGetValue("p", out var dmarcPolicy);

        result.Details.Add($"SPF: {spfAll}");
        result.Details.Add($"DMARC: p={dmarcPolicy ?? "not set"}");

        if (spfAll == "+all")
        {
            result.Severity = CheckSeverity.Error;
            result.Summary = "+all nullifies any DMARC protection";
            result.Errors.Add("SPF +all allows all senders regardless of DMARC policy");
        }
        else if (spfAll == "~all" && (dmarcPolicy == "reject" || dmarcPolicy == "quarantine"))
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = $"Ideal combination: ~all + p={dmarcPolicy}";
            result.Details.Add("~all (softfail) with DMARC enforcement is the recommended configuration");
            result.Details.Add("Forwarded mail can pass via DKIM while DMARC catches unauthenticated mail");
        }
        else if (spfAll == "-all" && (dmarcPolicy == "reject" || dmarcPolicy == "quarantine"))
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = $"Strong combination: -all + p={dmarcPolicy}";
            result.Details.Add("Note: ~all is generally preferred over -all when DMARC is enforced, as -all can reject legitimate forwarded mail that would otherwise pass DKIM alignment");
        }
        else if (spfAll == "~all" && dmarcPolicy == "none")
        {
            result.Severity = CheckSeverity.Warning;
            result.Summary = "~all with p=none provides minimal protection";
            result.Warnings.Add("SPF softfail (~all) combined with DMARC p=none provides no enforcement - consider moving to p=quarantine or p=reject");
        }
        else if (spfAll == "-all" && dmarcPolicy == "none")
        {
            result.Severity = CheckSeverity.Warning;
            result.Summary = "-all with p=none - SPF enforces but DMARC does not";
            result.Warnings.Add("Consider enabling DMARC enforcement (p=quarantine or p=reject) and switching to ~all to avoid breaking forwarded mail");
        }
        else if (spfAll == "?all")
        {
            result.Severity = CheckSeverity.Warning;
            result.Summary = "?all (neutral) provides no SPF protection";
            result.Warnings.Add("SPF neutral (?all) does not reject any mail - consider ~all with DMARC enforcement");
        }
        else
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = $"SPF: {spfAll}, DMARC: p={dmarcPolicy ?? "none"}";
        }

        return new List<CheckResult> { result };
    }
}

public class SubdomainDmarcOverrideCheck : ICheck
{
    public string Name => "Subdomain DMARC Override";
    public CheckCategory Category => CheckCategory.DMARC;

    private static readonly string[] CommonSubdomains = { "mail", "smtp", "email", "www", "newsletter", "marketing", "bounce", "send", "outbound" };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (ctx.DmarcRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No DMARC to check for subdomain overrides";
                return new List<CheckResult> { result };
            }

            var parentTags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
            parentTags.TryGetValue("p", out var parentPolicy);

            var weaker = new List<string>();

            foreach (var sub in CommonSubdomains)
            {
                var subDmarc = $"_dmarc.{sub}.{domain}";
                var txts = await ctx.Dns.GetTxtRecordsAsync(subDmarc);
                var rec = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)));
                if (rec != null)
                {
                    var subText = string.Join("", rec.Text);
                    var subTags = DmarcRecordCheck.ParseDmarcTags(subText);
                    subTags.TryGetValue("p", out var subPolicy);

                    result.Details.Add($"{sub}.{domain}: p={subPolicy ?? "not set"}");

                    if (IsWeaker(subPolicy, parentPolicy))
                    {
                        weaker.Add($"{sub}.{domain}");
                        result.Warnings.Add($"{sub}.{domain} has weaker policy (p={subPolicy}) than parent (p={parentPolicy})");
                    }
                }
            }

            if (weaker.Any())
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"{weaker.Count} subdomain(s) with weaker DMARC policies";
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No weaker subdomain DMARC overrides found";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }

    private static bool IsWeaker(string? sub, string? parent)
    {
        var strength = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["reject"] = 3, ["quarantine"] = 2, ["none"] = 1
        };

        var subStr = strength.GetValueOrDefault(sub ?? "none", 0);
        var parentStr = strength.GetValueOrDefault(parent ?? "none", 0);
        return subStr < parentStr;
    }
}
