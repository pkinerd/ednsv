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

            // #30 - v=DMARC1 case sensitivity check
            var vTagMatch = dmarcRecords[0].Text.FirstOrDefault(s => s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));
            if (vTagMatch != null)
            {
                var trimmedV = vTagMatch.TrimStart();
                // Extract the v=DMARC1 portion (up to first ; or end)
                var vPart = trimmedV.Split(';')[0].Trim();
                if (!vPart.StartsWith("v=DMARC1") && vPart.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase))
                    result.Warnings.Add("v=DMARC1 uses incorrect case — RFC 7489 ABNF requires exact uppercase 'DMARC1'");
            }

            // Parse tags (with duplicate detection - #29)
            var tags = ParseDmarcTags(dmarcText, out var duplicateTags);

            // #29 - Duplicate tags detection
            foreach (var dup in duplicateTags)
                result.Warnings.Add($"Duplicate tag '{dup}' in DMARC record — behavior is unpredictable");

            if (tags.TryGetValue("p", out var policy))
            {
                result.Details.Add($"Policy (p): {policy}");
                if (policy == "none")
                    result.Warnings.Add("DMARC policy is 'none' - no enforcement");
            }
            else
            {
                // #13 - Missing p= tag
                result.Severity = CheckSeverity.Error;
                result.Errors.Add("Missing required p= tag — DMARC record is invalid without it (RFC 7489 §6.3)");
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
            {
                result.Details.Add($"Aggregate reports (rua): {rua}");
                // #14 - Empty rua= value
                var ruaUris = rua.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim()).Where(u => u.Length > 0).ToList();
                if (!ruaUris.Any())
                {
                    result.Severity = CheckSeverity.Error;
                    result.Errors.Add("rua= tag is present but contains no valid URI");
                }
                else
                {
                    // #27 - Report size suffix validation for rua URIs
                    foreach (var ruaUri in ruaUris)
                    {
                        var bangIdx = ruaUri.IndexOf('!');
                        if (bangIdx >= 0 && bangIdx < ruaUri.Length - 1)
                        {
                            var suffix = ruaUri.Substring(bangIdx + 1);
                            if (!Regex.IsMatch(suffix, @"^\d+[kmgt]?$", RegexOptions.IgnoreCase))
                                result.Warnings.Add($"Report size limit '{suffix}' is malformed in URI — expected format: !<digits>[k|m|g|t]");
                        }
                    }
                }
            }
            if (tags.TryGetValue("ruf", out var ruf))
            {
                result.Details.Add($"Forensic reports (ruf): {ruf}");
                // #14 - Empty ruf= value
                var rufUris = ruf.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(u => u.Trim()).Where(u => u.Length > 0).ToList();
                if (!rufUris.Any())
                {
                    result.Severity = CheckSeverity.Error;
                    result.Errors.Add("ruf= tag is present but contains no valid URI");
                }
                else
                {
                    // #27 - Report size suffix validation for ruf URIs
                    foreach (var rufUri in rufUris)
                    {
                        var bangIdx = rufUri.IndexOf('!');
                        if (bangIdx >= 0 && bangIdx < rufUri.Length - 1)
                        {
                            var suffix = rufUri.Substring(bangIdx + 1);
                            if (!Regex.IsMatch(suffix, @"^\d+[kmgt]?$", RegexOptions.IgnoreCase))
                                result.Warnings.Add($"Report size limit '{suffix}' is malformed in URI — expected format: !<digits>[k|m|g|t]");
                        }
                    }
                }
            }
            if (tags.TryGetValue("fo", out var fo))
                result.Details.Add($"Failure options (fo): {fo}");
            if (tags.TryGetValue("rf", out var rf))
                result.Details.Add($"Report format (rf): {rf}");
            if (tags.TryGetValue("ri", out var ri))
                result.Details.Add($"Report interval (ri): {ri}s");

            // RFC 7489 tag value validation
            var validPolicies = new[] { "none", "quarantine", "reject" };
            if (policy != null && !validPolicies.Contains(policy, StringComparer.OrdinalIgnoreCase))
                result.Errors.Add($"Invalid DMARC policy (p): '{policy}' — must be none, quarantine, or reject (RFC 7489 §6.3)");
            if (sp != null && !validPolicies.Contains(sp, StringComparer.OrdinalIgnoreCase))
                result.Errors.Add($"Invalid subdomain policy (sp): '{sp}' — must be none, quarantine, or reject");
            if (pct != null && (!int.TryParse(pct, out var pctVal) || pctVal < 0 || pctVal > 100))
                result.Errors.Add($"Invalid pct value: '{pct}' — must be 0-100 (RFC 7489 §6.3)");
            if (adkim != null && adkim != "r" && adkim != "s")
                result.Errors.Add($"Invalid DKIM alignment (adkim): '{adkim}' — must be 'r' (relaxed) or 's' (strict)");
            if (aspf != null && aspf != "r" && aspf != "s")
                result.Errors.Add($"Invalid SPF alignment (aspf): '{aspf}' — must be 'r' (relaxed) or 's' (strict)");
            if (fo != null)
            {
                var foValues = fo.Split(':', StringSplitOptions.RemoveEmptyEntries).Select(v => v.Trim());
                var validFo = new[] { "0", "1", "d", "s" };
                foreach (var fv in foValues)
                    if (!validFo.Contains(fv))
                        result.Errors.Add($"Invalid failure option (fo): '{fv}' — must be 0, 1, d, or s (RFC 7489 §6.3)");

                // #25 - fo= without ruf=
                if (ruf == null)
                    result.Warnings.Add("fo= tag has no effect without ruf= (RFC 7489 §6.3)");
            }
            // #26 - rf= validation: only afrf is valid
            if (rf != null && !rf.Equals("afrf", StringComparison.OrdinalIgnoreCase))
                result.Warnings.Add($"rf= value '{rf}' is not valid — only 'afrf' is defined (RFC 7489 §6.3)");
            if (ri != null)
            {
                if (!long.TryParse(ri, out var riVal))
                    result.Errors.Add($"Invalid report interval (ri): '{ri}' — must be a number of seconds");
                else if (riVal < 3600)
                    result.Warnings.Add($"Report interval (ri) is very short: {riVal}s (< 1 hour)");
            }

            // #56 - pct= with p=none
            if (pct != null && policy != null && string.Equals(policy, "none", StringComparison.OrdinalIgnoreCase))
                result.Details.Add($"pct={pct} has no practical effect with p=none (no action is taken regardless of pct)");

            // #57 - Unknown tags detection
            var knownTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "v", "p", "sp", "rua", "ruf", "adkim", "aspf", "pct", "fo", "rf", "ri", "np", "psd" };
            foreach (var tagName in tags.Keys)
            {
                if (!knownTags.Contains(tagName))
                    result.Details.Add($"Unknown tag '{tagName}' in DMARC record (will be ignored, possible typo?)");
            }

            // #58 - np= tag (RFC 9091)
            if (tags.TryGetValue("np", out var np))
            {
                result.Details.Add($"Non-existent subdomain policy (np=): {np} (RFC 9091)");
                if (!validPolicies.Contains(np, StringComparer.OrdinalIgnoreCase))
                    result.Warnings.Add($"Invalid np= value '{np}' — must be none, quarantine, or reject (RFC 9091)");
            }

            // #59 - psd=y tag (RFC 9091)
            if (tags.TryGetValue("psd", out var psd))
            {
                if (string.Equals(psd, "y", StringComparison.OrdinalIgnoreCase))
                {
                    result.Details.Add("Public Suffix Domain DMARC record (psd=y, RFC 9091)");
                    if (ruf != null)
                        result.Warnings.Add("ruf= MUST NOT be used with psd=y (RFC 9091) — failure reports must not be sent for PSD DMARC records");
                }
            }

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
        return ParseDmarcTags(dmarc, out _);
    }

    public static Dictionary<string, string> ParseDmarcTags(string dmarc, out List<string> duplicates)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        duplicates = new List<string>();
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
                if (tags.ContainsKey(key))
                    duplicates.Add(key);
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

                // #28 - sp= on subdomain records: if this domain has 3+ parts, it's likely a subdomain
                var domainParts = domain.Split('.');
                if (domainParts.Length > 2)
                {
                    var rec = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)));
                    if (rec != null)
                    {
                        var dmarcText = string.Join("", rec.Text);
                        var subTags = DmarcRecordCheck.ParseDmarcTags(dmarcText);
                        if (subTags.ContainsKey("sp"))
                            result.Warnings.Add("sp= tag on subdomain DMARC record is ignored — sp= only applies at the Organizational Domain level (RFC 7489 §6.3)");

                        // Check parent domain for conflicting DMARC policy
                        subTags.TryGetValue("p", out var subPolicy);
                        for (int i = 1; i < domainParts.Length - 1; i++)
                        {
                            var parent = string.Join('.', domainParts.Skip(i));
                            var parentDmarc = $"_dmarc.{parent}";
                            var parentTxts = await ctx.Dns.GetTxtRecordsAsync(parentDmarc);
                            var parentRec = parentTxts.FirstOrDefault(t =>
                                t.Text.Any(s => s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)));

                            if (parentRec != null)
                            {
                                var parentText = string.Join("", parentRec.Text);
                                var parentTags = DmarcRecordCheck.ParseDmarcTags(parentText);

                                // Determine what policy the parent intended for subdomains
                                parentTags.TryGetValue("sp", out var parentSp);
                                parentTags.TryGetValue("p", out var parentP);
                                var parentSubdomainPolicy = parentSp ?? parentP;

                                result.Details.Add($"Parent domain ({parent}) DMARC: p={parentP ?? "not set"}, sp={parentSp ?? "not set (inherits p)"}");;
                                result.Details.Add($"This subdomain DMARC: p={subPolicy ?? "not set"}");

                                if (parentSubdomainPolicy != null && subPolicy != null)
                                {
                                    var strength = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                                        { { "none", 0 }, { "quarantine", 1 }, { "reject", 2 } };
                                    var parentStr = strength.GetValueOrDefault(parentSubdomainPolicy, 0);
                                    var subStr = strength.GetValueOrDefault(subPolicy, 0);

                                    if (subStr < parentStr)
                                        result.Warnings.Add($"Subdomain DMARC policy (p={subPolicy}) is weaker than parent's subdomain policy ({(parentSp != null ? $"sp={parentSp}" : $"p={parentP}")}) — this subdomain overrides the parent with a less restrictive policy");
                                    else if (subStr > parentStr)
                                        result.Details.Add($"Subdomain enforces stricter policy (p={subPolicy}) than parent's subdomain policy ({(parentSp != null ? $"sp={parentSp}" : $"p={parentP}")})");
                                }
                                break;
                            }
                        }
                    }
                }

                return new List<CheckResult> { result };
            }

            // Walk up parent domains
            // NOTE: PSL limitation — this tree walk uses simple domain splitting and does not
            // consult the Public Suffix List (PSL). For multi-level TLDs (e.g., co.uk, com.au),
            // the Organizational Domain detection may be incorrect. A proper implementation
            // should use the PSL to determine the Organizational Domain boundary.
            var knownMultiLevelSuffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "co.uk", "com.au", "co.za", "co.jp", "com.br", "co.in",
                "org.uk", "net.au", "ac.uk", "co.nz"
            };

            var parts = domain.Split('.');
            for (int i = 1; i < parts.Length - 1; i++)
            {
                var parent = string.Join('.', parts.Skip(i));

                // #31 - PSL-aware tree walk: warn if we reach a known multi-level TLD suffix
                if (knownMultiLevelSuffixes.Contains(parent))
                {
                    result.Warnings.Add($"DMARC tree walk reached public suffix '{parent}' — Organizational Domain detection may be incorrect for multi-level TLDs. Consider using the Public Suffix List.");
                    continue;
                }

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

                    // #28 - sp= on subdomain records is ignored
                    if (subTags.ContainsKey("sp"))
                        result.Warnings.Add($"sp= tag on subdomain DMARC record is ignored — sp= only applies at the Organizational Domain level (RFC 7489 §6.3)");

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

public class DmarcSubdomainPolicyCheck : ICheck
{
    public string Name => "DMARC Subdomain Policy Analysis";
    public CheckCategory Category => CheckCategory.DMARC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        await Task.CompletedTask;

        try
        {
            if (ctx.DmarcRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No DMARC record to analyze subdomain policy";
                return new List<CheckResult> { result };
            }

            var tags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
            tags.TryGetValue("p", out var policy);
            tags.TryGetValue("sp", out var subdomainPolicy);
            tags.TryGetValue("adkim", out var adkim);
            tags.TryGetValue("aspf", out var aspf);
            tags.TryGetValue("pct", out var pct);

            // Effective subdomain policy: sp if set, otherwise p
            var effectiveSp = subdomainPolicy ?? policy;

            result.Details.Add($"Parent policy (p): {policy ?? "not set"}");
            var spDisplay = subdomainPolicy ?? $"not set (inherits p={policy})";
            result.Details.Add($"Subdomain policy (sp): {spDisplay}");
            result.Details.Add($"Effective subdomain policy: {effectiveSp}");

            // 1. sp weaker than p
            if (subdomainPolicy != null && policy != null)
            {
                var strength = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                {
                    ["reject"] = 3, ["quarantine"] = 2, ["none"] = 1
                };
                var spStrength = strength.GetValueOrDefault(subdomainPolicy, 0);
                var pStrength = strength.GetValueOrDefault(policy, 0);

                if (spStrength < pStrength)
                {
                    result.Warnings.Add($"sp={subdomainPolicy} is weaker than p={policy} — subdomains are less protected than the parent domain");
                }
            }

            // 2. sp=none or effective sp=none: non-existent subdomain spoofing risk
            if (string.Equals(effectiveSp, "none", StringComparison.OrdinalIgnoreCase))
            {
                result.Warnings.Add("Effective subdomain policy is 'none' — attackers can spoof any subdomain (including non-existent ones like fake.{domain})");
                result.Warnings.Add("Consider setting sp=reject to protect all subdomains from spoofing");
            }

            // 3. Alignment mode inheritance
            if (adkim != null)
            {
                result.Details.Add($"DKIM alignment (adkim): {adkim}");
                if (string.Equals(adkim, "s", StringComparison.OrdinalIgnoreCase))
                {
                    result.Details.Add("  Strict DKIM alignment: subdomain mail must be signed with exact domain match");
                    result.Warnings.Add("adkim=s (strict) inherited by subdomains — subdomain mail must use exact-match DKIM signing (d=sub.domain, not d=domain)");
                }
            }
            else
            {
                result.Details.Add("DKIM alignment (adkim): relaxed (default)");
            }

            if (aspf != null)
            {
                result.Details.Add($"SPF alignment (aspf): {aspf}");
                if (string.Equals(aspf, "s", StringComparison.OrdinalIgnoreCase))
                {
                    result.Details.Add("  Strict SPF alignment: RFC5321.MailFrom must exactly match RFC5322.From domain");
                    result.Warnings.Add("aspf=s (strict) inherited by subdomains — subdomain mail must have exact SPF domain match in envelope");
                }
            }
            else
            {
                result.Details.Add("SPF alignment (aspf): relaxed (default)");
            }

            // 4. pct < 100 on subdomain policy
            if (pct != null && int.TryParse(pct, out var pctVal) && pctVal < 100)
            {
                result.Warnings.Add($"pct={pctVal} — only {pctVal}% of failing messages get the DMARC policy applied (applies to subdomains too)");
            }

            // 5. Strong parent but weak subdomain pattern
            if (string.Equals(policy, "reject", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(effectiveSp, "none", StringComparison.OrdinalIgnoreCase))
            {
                result.Errors.Add("p=reject but sp=none — parent domain is protected but ALL subdomains are wide open to spoofing");
            }

            if (result.Errors.Any())
                result.Severity = CheckSeverity.Error;
            else if (result.Warnings.Any())
                result.Severity = CheckSeverity.Warning;
            else
                result.Severity = CheckSeverity.Pass;

            result.Summary = $"Subdomain policy: {effectiveSp}" +
                (result.Warnings.Any() ? $" ({result.Warnings.Count} issue(s))" : " — well configured");
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class DmarcReportUriValidationCheck : ICheck
{
    public string Name => "DMARC Report URI Validation";
    public CheckCategory Category => CheckCategory.DMARC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (ctx.DmarcRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No DMARC record to validate report URIs";
                return new List<CheckResult> { result };
            }

            var tags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
            var allUris = new List<(string tag, string uri)>();

            if (tags.TryGetValue("rua", out var rua))
                foreach (var u in rua.Split(','))
                    allUris.Add(("rua", u.Trim()));
            if (tags.TryGetValue("ruf", out var ruf))
                foreach (var u in ruf.Split(','))
                    allUris.Add(("ruf", u.Trim()));

            if (!allUris.Any())
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "No DMARC report URIs configured — no visibility into authentication failures";
                result.Warnings.Add("Without rua/ruf, you won't receive DMARC aggregate or forensic reports");
                return new List<CheckResult> { result };
            }

            bool hasRua = tags.ContainsKey("rua");
            bool hasRuf = tags.ContainsKey("ruf");
            if (!hasRua)
                result.Warnings.Add("No rua= (aggregate reports) configured — you won't see authentication statistics");
            if (!hasRuf)
                result.Details.Add("No ruf= (forensic reports) — optional, many providers don't send them");

            foreach (var (tag, uri) in allUris)
            {
                if (uri.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                {
                    var email = uri.Substring(7).Split('!')[0]; // remove optional size limit
                    var atIdx = email.IndexOf('@');
                    if (atIdx < 0)
                    {
                        result.Errors.Add($"{tag}: Invalid mailto URI: {uri}");
                        continue;
                    }

                    var reportDomain = email.Substring(atIdx + 1).ToLowerInvariant();
                    result.Details.Add($"{tag}: {uri}");

                    // Check MX for report domain
                    var mx = await ctx.Dns.GetMxRecordsAsync(reportDomain);
                    if (!mx.Any())
                    {
                        // Check for A record fallback (implicit MX)
                        var aRecs = await ctx.Dns.ResolveAAsync(reportDomain);
                        if (aRecs.Any())
                        {
                            result.Details.Add($"  {reportDomain}: No MX but has A record (implicit MX)");
                        }
                        else
                        {
                            result.Errors.Add($"  {reportDomain}: No MX and no A record — reports undeliverable");
                        }
                    }
                    else
                    {
                        result.Details.Add($"  {reportDomain}: {mx.Count} MX record(s)");
                    }

                    // External report authorization check
                    if (!string.Equals(reportDomain, domain, StringComparison.OrdinalIgnoreCase))
                    {
                        var authDomain = $"{domain}._report._dmarc.{reportDomain}";
                        var authTxts = await ctx.Dns.GetTxtRecordsAsync(authDomain);
                        var hasAuth = authTxts.Any(t => t.Text.Any(s =>
                            s.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)));

                        if (hasAuth)
                            result.Details.Add($"  External authorization: verified at {authDomain}");
                        else
                            result.Warnings.Add($"  {reportDomain}: External domain — no authorization record at {authDomain}");
                    }
                }
                else if (uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    result.Details.Add($"{tag}: {uri} (HTTPS endpoint)");
                }
                else
                {
                    result.Warnings.Add($"{tag}: Unrecognized URI scheme: {uri}");
                }
            }

            if (result.Errors.Any())
                result.Severity = CheckSeverity.Error;
            else if (result.Warnings.Any())
                result.Severity = CheckSeverity.Warning;
            else
                result.Severity = CheckSeverity.Pass;

            result.Summary = $"Validated {allUris.Count} DMARC report URI(s)";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}
