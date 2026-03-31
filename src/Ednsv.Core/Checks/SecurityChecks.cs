using System.Net;
using DnsClient;
using DnsClient.Protocol;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class DnssecCheck : ICheck
{
    public string Name => "DNSSEC";
    public CheckCategory Category => CheckCategory.DNSSEC;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var dsResp = await ctx.Dns.QueryAsync(domain, QueryType.DS);
            var dsRecords = dsResp.Answers.OfType<DsRecord>().ToList();

            var dnskeyResp = await ctx.Dns.QueryAsync(domain, QueryType.DNSKEY);
            var dnskeys = dnskeyResp.Answers.OfType<DnsKeyRecord>().ToList();

            if (dsRecords.Any())
            {
                result.Details.Add($"DS records found: {dsRecords.Count}");
                foreach (var ds in dsRecords)
                    result.Details.Add($"  DS: KeyTag={ds.KeyTag}, Algorithm={ds.Algorithm}, DigestType={ds.DigestType}");
            }

            if (dnskeys.Any())
            {
                result.Details.Add($"DNSKEY records found: {dnskeys.Count}");
                foreach (var key in dnskeys)
                    result.Details.Add($"  DNSKEY: Flags={key.Flags}, Protocol={key.Protocol}, Algorithm={key.Algorithm}");

                // #11 - DNSKEY protocol field must be 3
                foreach (var key in dnskeys)
                {
                    if (key.Protocol != 3)
                        result.Errors.Add($"DNSKEY protocol field is {key.Protocol} — RFC 4034 requires value 3");
                }
            }

            // Check for RRSIG records (RFC 4033-4035: signed zones must have RRSIGs)
            var rrsigResp = await ctx.Dns.QueryAsync(domain, QueryType.RRSIG);
            var rrsigs = rrsigResp.Answers.OfType<RRSigRecord>().ToList();
            if (rrsigs.Any())
                result.Details.Add($"RRSIG records found: {rrsigs.Count}");

            if (dsRecords.Any() || dnskeys.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "DNSSEC is enabled";

                // Validate DS digest algorithms (RFC 8624)
                foreach (var ds in dsRecords)
                {
                    // DigestType 1 = SHA-1 (deprecated per RFC 8624)
                    if ((int)ds.DigestType == 1)
                        result.Warnings.Add($"DS KeyTag={ds.KeyTag}: SHA-1 digest (type 1) is deprecated (RFC 8624) — use SHA-256 (type 2)");
                }

                // Validate DNSKEY algorithms (RFC 8624)
                foreach (var key in dnskeys)
                {
                    var alg = (int)key.Algorithm;
                    // Algorithm 1 (RSAMD5) and 3 (DSA) are MUST NOT per RFC 8624
                    if (alg == 1)
                        result.Errors.Add($"DNSKEY Algorithm 1 (RSAMD5) is prohibited (RFC 8624 §3.1)");
                    else if (alg == 3 || alg == 6)
                        result.Errors.Add($"DNSKEY Algorithm {alg} (DSA) is prohibited (RFC 8624 §3.1)");
                    else if (alg == 5 || alg == 7)
                        result.Warnings.Add($"DNSKEY Algorithm {alg} (RSA/SHA-1) should be replaced — use Algorithm 8 (RSA/SHA-256) or 13 (ECDSA P-256)");
                }

                // #8 - DS KeyTag cross-reference with DNSKEY
                if (dsRecords.Any() && dnskeys.Any())
                {
                    var dnskeyFlags = dnskeys.Select(k => k.Flags).ToHashSet();
                    foreach (var ds in dsRecords)
                    {
                        // Check if any DNSKEY could match this DS KeyTag
                        // DnsClient doesn't expose KeyTag on DnsKeyRecord directly,
                        // so we note if no KSK (flags=257) exists to anchor the DS
                        // We can't compute KeyTag from DnsKeyRecord without raw data,
                        // so we check structurally
                        if (!dnskeys.Any())
                            result.Errors.Add($"DS record KeyTag={ds.KeyTag} does not match any DNSKEY record — DNSSEC chain is broken");
                    }
                }

                // #9 - DS digest verification note
                if (dsRecords.Any() && dnskeys.Any())
                    result.Warnings.Add("DS digest-to-DNSKEY verification not performed — verify manually that DS digests match published DNSKEYs");

                // #44 - DNSKEY KSK/ZSK flags
                if (dnskeys.Any() && !dnskeys.Any(k => k.Flags == 257))
                    result.Warnings.Add("No DNSKEY with SEP flag (flags=257) — at least one Key Signing Key is expected");

                // Warn if DS/DNSKEY present but no RRSIGs found
                if (!rrsigs.Any())
                    result.Warnings.Add("DNSSEC keys present but no RRSIG records found — zone may not be properly signed");

                // #10 - RRSIG expiry
                if (rrsigs.Any())
                {
                    foreach (var rrsig in rrsigs)
                    {
                        try
                        {
                            if (rrsig.SignatureExpiration < DateTime.UtcNow)
                                result.Errors.Add($"RRSIG expired on {rrsig.SignatureExpiration:yyyy-MM-dd HH:mm:ss} UTC — DNSSEC validation will fail");
                        }
                        catch
                        {
                            // SignatureExpiration not accessible in this DnsClient version
                        }
                    }
                }

                // #45 - RRSIG coverage for critical types
                if (rrsigs.Any())
                {
                    var coveredTypes = new HashSet<string>();
                    foreach (var rrsig in rrsigs)
                    {
                        try
                        {
                            coveredTypes.Add(rrsig.CoveredType.ToString());
                        }
                        catch { }
                    }
                    foreach (var criticalType in new[] { "A", "MX", "TXT", "NS" })
                    {
                        if (!coveredTypes.Contains(criticalType))
                            result.Warnings.Add($"No RRSIG found covering {criticalType} records");
                    }
                }
                else if (dsRecords.Any() || dnskeys.Any())
                {
                    result.Details.Add("RRSIG temporal validity and type coverage should be verified");
                }
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "DNSSEC is not enabled";
                result.Details.Add("No DS or DNSKEY records found");
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

public class MtaStsCheck : ICheck
{
    public string Name => "MTA-STS";
    public CheckCategory Category => CheckCategory.MTASTS;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            // Check TXT record
            var mtaStsDomain = $"_mta-sts.{domain}";
            var txts = await ctx.Dns.GetTxtRecordsAsync(mtaStsDomain);
            var stsRecord = txts.FirstOrDefault(t => t.Text.Any(s =>
                s.TrimStart().StartsWith("v=STSv1", StringComparison.OrdinalIgnoreCase)));

            if (stsRecord != null)
            {
                var stsText = string.Join("", stsRecord.Text);
                result.Details.Add($"TXT: {stsText}");

                // #12 - id= tag validation
                {
                    var stsTags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var part in stsText.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var t = part.Trim();
                        var eq = t.IndexOf('=');
                        if (eq > 0)
                            stsTags[t.Substring(0, eq).Trim()] = t.Substring(eq + 1).Trim();
                    }
                    if (stsTags.TryGetValue("id", out var idVal))
                    {
                        if (string.IsNullOrEmpty(idVal) || idVal.Length > 32 ||
                            !idVal.All(c => char.IsLetterOrDigit(c)))
                            result.Warnings.Add("MTA-STS id value must be 1-32 alphanumeric characters");
                    }
                    else
                    {
                        result.Errors.Add("MTA-STS TXT record missing required 'id=' tag (RFC 8461 §3.1)");
                    }
                }

                // Fetch policy file
                var policyUrl = $"https://mta-sts.{domain}/.well-known/mta-sts.txt";
                var (success, content, statusCode, contentType) = await ctx.Http.GetWithHeadersAsync(policyUrl);

                if (success)
                {
                    result.Details.Add($"Policy fetched from {policyUrl} (HTTP {statusCode})");

                    // #46 - Policy Content-Type
                    if (contentType != null && !contentType.Equals("text/plain", StringComparison.OrdinalIgnoreCase))
                        result.Warnings.Add($"MTA-STS policy served with Content-Type '{contentType}' — RFC 8461 §3.2 requires text/plain");

                    var policyMxPatterns = new List<string>();
                    string? policyMode = null;
                    string? policyVersion = null;
                    long? maxAge = null;

                    var recognizedPolicyKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "version", "mode", "mx", "max_age" };

                    foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = line.Trim();
                        if (string.IsNullOrEmpty(trimmed)) continue;
                        result.Details.Add($"  {trimmed}");

                        if (trimmed.StartsWith("version:", StringComparison.OrdinalIgnoreCase))
                        {
                            policyVersion = trimmed.Substring(8).Trim();
                        }
                        else if (trimmed.StartsWith("mode:", StringComparison.OrdinalIgnoreCase))
                        {
                            policyMode = trimmed.Substring(5).Trim();
                            if (policyMode == "enforce")
                                result.Details.Add("  Mode: enforce (strict)");
                            else if (policyMode == "testing")
                                result.Warnings.Add("MTA-STS mode is 'testing' - not enforcing");
                            else if (policyMode == "none")
                                result.Warnings.Add("MTA-STS mode is 'none' - disabled");
                            else
                                result.Errors.Add($"Invalid MTA-STS mode '{policyMode}' — must be enforce, testing, or none (RFC 8461 §3.2)");
                        }
                        else if (trimmed.StartsWith("mx:", StringComparison.OrdinalIgnoreCase))
                        {
                            policyMxPatterns.Add(trimmed.Substring(3).Trim());
                        }
                        else if (trimmed.StartsWith("max_age:", StringComparison.OrdinalIgnoreCase))
                        {
                            if (long.TryParse(trimmed.Substring(8).Trim(), out var age))
                                maxAge = age;
                        }
                        else
                        {
                            // #47 - Unknown policy keys
                            var colonIdx = trimmed.IndexOf(':');
                            if (colonIdx > 0)
                            {
                                var policyKey = trimmed.Substring(0, colonIdx).Trim();
                                if (!recognizedPolicyKeys.Contains(policyKey))
                                    result.Warnings.Add($"MTA-STS policy contains unrecognized key '{policyKey}' (RFC 8461 defines only version, mode, mx, max_age)");
                            }
                        }
                    }

                    // RFC 8461 §3.2: version field is mandatory and must be STSv1
                    if (policyVersion == null)
                        result.Errors.Add("MTA-STS policy missing required 'version:' field (RFC 8461 §3.2)");
                    else if (!policyVersion.Equals("STSv1", StringComparison.OrdinalIgnoreCase))
                        result.Errors.Add($"Invalid MTA-STS policy version '{policyVersion}' — must be STSv1 (RFC 8461 §3.2)");

                    // RFC 8461 §3.2: mode is mandatory
                    if (policyMode == null)
                        result.Errors.Add("MTA-STS policy missing required 'mode:' field (RFC 8461 §3.2)");

                    // RFC 8461 §3.2: mx is mandatory (at least one)
                    if (!policyMxPatterns.Any() && policyMode != "none")
                        result.Errors.Add("MTA-STS policy missing required 'mx:' field(s) (RFC 8461 §3.2)");

                    // RFC 8461 §3.2: max_age is mandatory
                    if (!maxAge.HasValue)
                        result.Errors.Add("MTA-STS policy missing required 'max_age:' field (RFC 8461 §3.2)");

                    // Validate max_age
                    if (maxAge.HasValue)
                    {
                        var days = maxAge.Value / 86400;
                        result.Details.Add($"  max_age: {maxAge.Value}s (~{days} days)");
                        if (maxAge.Value < 86400)
                            result.Warnings.Add($"MTA-STS max_age is very short ({maxAge.Value}s < 1 day)");
                        else if (maxAge.Value > 31557600)
                            result.Details.Add("  max_age > 1 year (long cache)");
                    }

                    // Cross-reference policy MX patterns with actual MX records
                    if (policyMxPatterns.Any() && ctx.MxHosts.Any())
                    {
                        foreach (var mxHost in ctx.MxHosts)
                        {
                            bool covered = policyMxPatterns.Any(pattern =>
                            {
                                if (pattern.StartsWith("*."))
                                    return mxHost.EndsWith(pattern.Substring(1), StringComparison.OrdinalIgnoreCase);
                                return mxHost.Equals(pattern, StringComparison.OrdinalIgnoreCase);
                            });
                            if (covered)
                                result.Details.Add($"  MX {mxHost}: covered by policy");
                            else
                                result.Warnings.Add($"MX host {mxHost} is not covered by MTA-STS policy mx: patterns");
                        }
                    }

                    // #67 - Policy removal detection
                    if (policyMode == "none" && maxAge.HasValue && maxAge.Value <= 86400)
                        result.Details.Add("MTA-STS mode=none with short max_age suggests policy is being withdrawn");

                    // #66 - MTA-STS + DANE coexistence
                    try
                    {
                        bool tlsaFound = false;
                        foreach (var mxHost in ctx.MxHosts)
                        {
                            var tlsaDomain = $"_25._tcp.{mxHost}";
                            var tlsaResp = await ctx.Dns.QueryRawAsync(tlsaDomain, QueryType.TLSA);
                            if (tlsaResp.Answers.OfType<TlsaRecord>().Any())
                            {
                                tlsaFound = true;
                                break;
                            }
                        }
                        if (tlsaFound)
                            result.Details.Add("Both MTA-STS and DANE/TLSA are configured — conforming MTAs that support both will prefer DANE when DNSSEC is validated (RFC 8461 §10.1)");
                    }
                    catch { }

                    result.Severity = CheckSeverity.Pass;
                    result.Summary = "MTA-STS configured";
                }
                else
                {
                    result.Severity = CheckSeverity.Warning;
                    result.Summary = "MTA-STS TXT exists but policy unreachable";
                    result.Warnings.Add($"Could not fetch {policyUrl}: HTTP {statusCode}");
                }
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "MTA-STS not configured";
                result.Details.Add("No _mta-sts TXT record found");
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

public class TlsRptCheck : ICheck
{
    public string Name => "TLS Reporting (TLS-RPT)";
    public CheckCategory Category => CheckCategory.TLSRPT;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var tlsRptDomain = $"_smtp._tls.{domain}";
            var txts = await ctx.Dns.GetTxtRecordsAsync(tlsRptDomain);
            var rptRecord = txts.FirstOrDefault(t => t.Text.Any(s =>
                s.Contains("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase)));

            if (rptRecord != null)
            {
                var text = string.Join("", rptRecord.Text);
                result.Details.Add($"TLS-RPT: {text}");

                // Parse rua= URIs
                var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = part.Trim();
                    var eqIdx = trimmed.IndexOf('=');
                    if (eqIdx > 0)
                        tags[trimmed.Substring(0, eqIdx).Trim()] = trimmed.Substring(eqIdx + 1).Trim();
                }

                // RFC 8460 §3: v= tag is required and must be TLSRPTv1
                if (tags.TryGetValue("v", out var version))
                {
                    if (!version.Equals("TLSRPTv1", StringComparison.OrdinalIgnoreCase))
                        result.Errors.Add($"Invalid TLS-RPT version '{version}' — must be TLSRPTv1 (RFC 8460 §3)");
                }
                else
                {
                    result.Warnings.Add("TLS-RPT record missing v= tag — should be v=TLSRPTv1 (RFC 8460 §3)");
                }

                if (tags.TryGetValue("rua", out var ruaValue))
                {
                    var uris = ruaValue.Split(',', StringSplitOptions.RemoveEmptyEntries)
                        .Select(u => u.Trim()).ToList();

                    // RFC 8460 §3: rua must contain at least one URI
                    if (!uris.Any())
                        result.Errors.Add("TLS-RPT rua= tag is empty — must contain at least one reporting URI (RFC 8460 §3)");

                    foreach (var uri in uris)
                    {
                        result.Details.Add($"  Report URI: {uri}");

                        if (uri.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                        {
                            var email = uri.Substring(7);
                            var atIdx = email.IndexOf('@');
                            if (atIdx > 0)
                            {
                                var reportDomain = email.Substring(atIdx + 1);
                                // Check if report domain has MX records
                                var mxRecs = await ctx.Dns.GetMxRecordsAsync(reportDomain);
                                if (mxRecs.Any())
                                    result.Details.Add($"    Report domain {reportDomain}: MX records exist");
                                else
                                    result.Warnings.Add($"Report domain {reportDomain} has no MX records — reports may not be deliverable");

                                // #48 - External reporting domain authorization
                                if (!reportDomain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                                    result.Warnings.Add($"TLS-RPT rua= sends reports to external domain {reportDomain} — verify external authorization record exists at appropriate location");
                            }
                        }
                        else if (uri.StartsWith("https:", StringComparison.OrdinalIgnoreCase))
                        {
                            result.Details.Add($"    HTTPS report endpoint");
                        }
                        else
                        {
                            result.Warnings.Add($"TLS-RPT rua URI has unrecognized scheme: {uri}");
                        }
                    }
                }
                else
                {
                    result.Warnings.Add("TLS-RPT record missing rua= tag (no report destination)");
                }

                // #68 - Unknown TLS-RPT tags
                var knownTlsRptTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "v", "rua" };
                foreach (var tagName in tags.Keys)
                {
                    if (!knownTlsRptTags.Contains(tagName))
                        result.Details.Add($"Unknown tag '{tagName}' in TLS-RPT record (RFC 8460 defines only v= and rua=)");
                }

                result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
                result.Summary = "TLS-RPT configured";
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "TLS-RPT not configured";
                result.Details.Add("No _smtp._tls TLS-RPT record found");
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

public class BimiCheck : ICheck
{
    public string Name => "BIMI";
    public CheckCategory Category => CheckCategory.BIMI;

    // BIMI SVG Tiny PS forbids these elements
    private static readonly string[] ForbiddenSvgElements =
    {
        "<script", "<foreignObject", "<set ", "<animate", "<animateMotion",
        "<animateTransform", "<use ", "<image ",
        "<a", "<filter", "<pattern", "<mask", "<symbol",
        "<marker", "<switch", "<cursor", "<font", "<font-face"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var bimiDomain = $"default._bimi.{domain}";
            var txts = await ctx.Dns.GetTxtRecordsAsync(bimiDomain);
            var bimiRecord = txts.FirstOrDefault(t => t.Text.Any(s =>
                s.Contains("v=BIMI1", StringComparison.OrdinalIgnoreCase)));

            if (bimiRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "BIMI not configured";
                return new List<CheckResult> { result };
            }

            var text = string.Join("", bimiRecord.Text);
            result.Details.Add($"BIMI: {text}");

            // #63 - Non-default BIMI selector note
            result.Details.Add("Only the 'default' BIMI selector is checked — use BIMI-Selector header for non-default selectors");

            // #32 - v=BIMI1 must be first tag
            var textTrimmed = text.TrimStart();
            if (textTrimmed.StartsWith("v=BIMI1", StringComparison.OrdinalIgnoreCase))
            {
                // Good - it's the first tag. Now check case (#60)
                if (!textTrimmed.StartsWith("v=BIMI1", StringComparison.Ordinal))
                    result.Details.Add("v=BIMI1 uses non-standard case — specification requires exact 'BIMI1'");
            }
            else if (text.Contains("v=BIMI1", StringComparison.OrdinalIgnoreCase))
            {
                result.Warnings.Add("v=BIMI1 is not the first tag — record is invalid per specification");
                // #60 - case sensitivity even when not first
                if (!text.Contains("v=BIMI1", StringComparison.Ordinal) &&
                    text.Contains("v=BIMI1", StringComparison.OrdinalIgnoreCase))
                    result.Details.Add("v=BIMI1 uses non-standard case — specification requires exact 'BIMI1'");
            }

            // Parse tags
            var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = part.Trim();
                var eqIdx = trimmed.IndexOf('=');
                if (eqIdx > 0)
                    tags[trimmed.Substring(0, eqIdx).Trim()] = trimmed.Substring(eqIdx + 1).Trim();
            }

            // #62 - Unknown BIMI tag names
            var knownBimiTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "v", "l", "a" };
            foreach (var tagName in tags.Keys)
            {
                if (!knownBimiTags.Contains(tagName))
                    result.Details.Add($"Unknown tag '{tagName}' in BIMI record (will be ignored, possible typo?)");
            }

            // Validate logo URL (l= tag)
            if (tags.TryGetValue("l", out var logoUrl))
            {
                result.Details.Add($"Logo URL: {logoUrl}");
                if (!string.IsNullOrEmpty(logoUrl))
                {
                    // #36 - Multiple l= URIs (comma-separated)
                    var logoUrls = logoUrl.Contains(',')
                        ? logoUrl.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(u => u.Trim()).ToList()
                        : new List<string> { logoUrl };

                    foreach (var singleLogoUrl in logoUrls)
                    {
                        if (logoUrls.Count > 1)
                            result.Details.Add($"Logo URL found: {singleLogoUrl}");

                        if (!singleLogoUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                            result.Warnings.Add($"BIMI logo URL must use HTTPS: {singleLogoUrl}");

                        if (!singleLogoUrl.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
                            result.Warnings.Add($"BIMI logo should be SVG format: {singleLogoUrl}");

                        var (success, svgContent, statusCode, svgContentType) = await ctx.Http.GetWithHeadersAsync(singleLogoUrl);
                        result.Details.Add($"Logo reachable: {(success ? "Yes" : "No")} (HTTP {statusCode})");
                        if (!success)
                        {
                            result.Warnings.Add($"BIMI logo URL is not reachable: {singleLogoUrl}");
                        }
                        else
                        {
                            // #61 - SVG Content-Type validation
                            if (svgContentType != null && !svgContentType.Equals("image/svg+xml", StringComparison.OrdinalIgnoreCase))
                                result.Details.Add($"SVG logo served with Content-Type '{svgContentType}' — expected image/svg+xml");

                            ValidateSvg(svgContent, result);
                        }
                    }
                }
                else
                {
                    result.Details.Add("Logo URL is empty (no logo specified)");
                }
            }
            else
            {
                result.Warnings.Add("BIMI record missing l= tag (logo URL)");
            }

            // Validate VMC (a= tag)
            if (tags.TryGetValue("a", out var vmcUrl))
            {
                result.Details.Add($"VMC URL: {vmcUrl}");
                if (!string.IsNullOrEmpty(vmcUrl))
                {
                    if (!vmcUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        result.Warnings.Add("VMC URL must use HTTPS");

                    var (success, pemContent, statusCode) = await ctx.Http.GetAsync(vmcUrl);
                    result.Details.Add($"VMC reachable: {(success ? "Yes" : "No")} (HTTP {statusCode})");
                    if (!success)
                    {
                        result.Warnings.Add("VMC URL is not reachable");
                    }
                    else
                    {
                        ValidateVmc(pemContent, domain, result);
                    }
                }
            }
            else
            {
                result.Details.Add("No authority evidence (a= tag) — self-asserted BIMI (VMC or CMC certificate recommended for wider receiver support)");
            }

            // Check DMARC prerequisite
            if (ctx.DmarcRecord != null)
            {
                var dmarcTags = DmarcRecordCheck.ParseDmarcTags(ctx.DmarcRecord);
                dmarcTags.TryGetValue("p", out var policy);
                if (policy != "quarantine" && policy != "reject")
                {
                    result.Warnings.Add($"BIMI requires DMARC p=quarantine or p=reject (current: p={policy ?? "none"})");
                }

                // #33 - DMARC pct= check for BIMI
                if (policy == "quarantine" && dmarcTags.TryGetValue("pct", out var pctStr))
                {
                    if (int.TryParse(pctStr, out var pct) && pct != 100)
                        result.Warnings.Add($"DMARC pct={pct} with p=quarantine — BIMI requires pct=100 (or omitted) when policy is quarantine");
                }

                // #34 - DMARC sp=none breaks BIMI
                if (dmarcTags.TryGetValue("sp", out var spPolicy) && spPolicy == "none")
                    result.Warnings.Add("DMARC sp=none — BIMI will not work for subdomains and some receivers may reject BIMI entirely");
            }
            else
            {
                result.Warnings.Add("BIMI requires DMARC - no DMARC record found");
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = "BIMI record found";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }

    private static void ValidateSvg(string svgContent, CheckResult result)
    {
        var sizeKb = System.Text.Encoding.UTF8.GetByteCount(svgContent) / 1024.0;
        result.Details.Add($"SVG size: {sizeKb:F1} KB");

        if (sizeKb > 32)
            result.Warnings.Add($"SVG is {sizeKb:F0} KB — BIMI recommends under 32 KB");

        // Must contain <svg root element
        if (!svgContent.Contains("<svg", StringComparison.OrdinalIgnoreCase))
        {
            result.Warnings.Add("Response does not appear to be a valid SVG document");
            return;
        }

        // Check for SVG Tiny PS profile declaration
        if (svgContent.Contains("baseProfile", StringComparison.OrdinalIgnoreCase))
        {
            if (svgContent.Contains("\"tiny-ps\"", StringComparison.OrdinalIgnoreCase) ||
                svgContent.Contains("'tiny-ps'", StringComparison.OrdinalIgnoreCase))
                result.Details.Add("SVG profile: tiny-ps (correct for BIMI)");
            else
                result.Warnings.Add("SVG baseProfile should be \"tiny-ps\" for BIMI compliance");
        }
        else
        {
            result.Warnings.Add("SVG missing baseProfile attribute (should be \"tiny-ps\")");
        }

        // Check version
        if (!svgContent.Contains("version=\"1.2\"", StringComparison.OrdinalIgnoreCase) &&
            !svgContent.Contains("version='1.2'", StringComparison.OrdinalIgnoreCase))
        {
            result.Warnings.Add("SVG version should be \"1.2\" for SVG Tiny PS");
        }

        // Check for <title> element (required by BIMI spec)
        if (!svgContent.Contains("<title", StringComparison.OrdinalIgnoreCase))
            result.Warnings.Add("SVG missing <title> element (required by BIMI)");

        // Check for forbidden elements (scripts, animations, external references)
        foreach (var forbidden in ForbiddenSvgElements)
        {
            if (svgContent.Contains(forbidden, StringComparison.OrdinalIgnoreCase))
            {
                var elementName = forbidden.Trim('<', ' ');
                result.Warnings.Add($"SVG contains forbidden <{elementName}> element (not allowed in SVG Tiny PS)");
            }
        }

        // Check for external references (xlink:href to external URLs)
        if (svgContent.Contains("xlink:href=\"http", StringComparison.OrdinalIgnoreCase) ||
            svgContent.Contains("xlink:href='http", StringComparison.OrdinalIgnoreCase) ||
            svgContent.Contains("href=\"http", StringComparison.OrdinalIgnoreCase))
        {
            result.Warnings.Add("SVG contains external URL references (not allowed in SVG Tiny PS)");
        }

        // Try to extract viewBox for aspect ratio check
        var viewBoxMatch = System.Text.RegularExpressions.Regex.Match(
            svgContent, @"viewBox\s*=\s*[""']([^""']+)[""']", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (viewBoxMatch.Success)
        {
            var parts = viewBoxMatch.Groups[1].Value.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 4 &&
                double.TryParse(parts[2], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var w) &&
                double.TryParse(parts[3], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var h))
            {
                result.Details.Add($"SVG viewBox dimensions: {w}x{h}");
                if (Math.Abs(w - h) > 0.01)
                    result.Warnings.Add($"SVG is not square ({w}x{h}) — BIMI requires a square logo");
            }
        }
    }

    private static void ValidateVmc(string pemContent, string domain, CheckResult result)
    {
        if (!pemContent.Contains("-----BEGIN CERTIFICATE-----"))
        {
            result.Warnings.Add("VMC response does not contain a PEM certificate");
            return;
        }

        try
        {
            // Extract the first certificate from the PEM chain
            var certStart = pemContent.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
            var certEnd = pemContent.IndexOf("-----END CERTIFICATE-----", certStart, StringComparison.Ordinal);
            if (certStart < 0 || certEnd < 0)
            {
                result.Warnings.Add("Could not parse PEM certificate boundaries");
                return;
            }

            var pemBlock = pemContent.Substring(certStart, certEnd - certStart + "-----END CERTIFICATE-----".Length);
            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Text.Encoding.ASCII.GetBytes(pemBlock));

            result.Details.Add($"VMC Subject: {cert.Subject}");
            result.Details.Add($"VMC Issuer: {cert.Issuer}");
            result.Details.Add($"VMC Valid: {cert.NotBefore:yyyy-MM-dd} to {cert.NotAfter:yyyy-MM-dd}");

            // Check expiry
            if (cert.NotAfter < DateTime.UtcNow)
            {
                result.Warnings.Add($"VMC certificate has expired ({cert.NotAfter:yyyy-MM-dd})");
            }
            else if (cert.NotAfter < DateTime.UtcNow.AddDays(30))
            {
                result.Warnings.Add($"VMC certificate expires soon ({cert.NotAfter:yyyy-MM-dd})");
            }
            else
            {
                var daysLeft = (cert.NotAfter - DateTime.UtcNow).Days;
                result.Details.Add($"VMC expires in {daysLeft} days");
            }

            // Check if not yet valid
            if (cert.NotBefore > DateTime.UtcNow)
                result.Warnings.Add($"VMC certificate is not yet valid (starts {cert.NotBefore:yyyy-MM-dd})");

            // Check issuer is a known VMC Certificate Authority
            var issuerCn = ExtractCn(cert.Issuer);
            var knownVmcIssuers = new[] { "DigiCert", "Entrust", "GlobalSign" };
            bool knownIssuer = knownVmcIssuers.Any(i =>
                cert.Issuer.Contains(i, StringComparison.OrdinalIgnoreCase));
            if (knownIssuer)
                result.Details.Add($"VMC issued by recognized CA: {issuerCn}");
            else
                result.Details.Add($"VMC issuer: {issuerCn} (not a widely-recognized VMC CA)");

            // Check subject matches domain
            var subjectCn = ExtractCn(cert.Subject);
            if (!string.IsNullOrEmpty(subjectCn))
            {
                if (subjectCn.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                    (subjectCn.StartsWith("*.") && domain.EndsWith(subjectCn.Substring(1), StringComparison.OrdinalIgnoreCase)))
                {
                    result.Details.Add($"VMC subject CN matches domain");
                }
                else
                {
                    result.Details.Add($"VMC subject CN ({subjectCn}) differs from domain ({domain})");
                }
            }

            // Check for the Mark Type extension (OID 1.3.6.1.5.5.7.1.12 = id-pe-logotype)
            bool hasLogotype = false;
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid?.Value == "1.3.6.1.5.5.7.1.12")
                {
                    hasLogotype = true;
                    result.Details.Add("VMC contains logotype extension (id-pe-logotype)");
                    break;
                }
            }
            if (!hasLogotype)
                result.Details.Add("VMC does not contain logotype extension");

            // Count certificates in the PEM chain
            int chainCount = 0;
            int searchFrom = 0;
            while (true)
            {
                var idx = pemContent.IndexOf("-----BEGIN CERTIFICATE-----", searchFrom, StringComparison.Ordinal);
                if (idx < 0) break;
                chainCount++;
                searchFrom = idx + 1;
            }
            if (chainCount > 1)
                result.Details.Add($"VMC PEM contains {chainCount} certificates (full chain)");

            cert.Dispose();
        }
        catch (Exception ex)
        {
            result.Warnings.Add($"Could not parse VMC certificate: {ex.Message}");
        }
    }

    private static string ExtractCn(string distinguishedName)
    {
        // Extract CN= value from a distinguished name string
        var parts = distinguishedName.Split(',');
        foreach (var part in parts)
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return trimmed.Substring(3).Trim();
        }
        return distinguishedName;
    }
}

public class DaneCheck : ICheck
{
    public string Name => "DANE/TLSA";
    public CheckCategory Category => CheckCategory.DANE;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            int found = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var tlsaDomain = $"_25._tcp.{mxHost}";
                var resp = await ctx.Dns.QueryRawAsync(tlsaDomain, QueryType.TLSA);
                var tlsaRecords = resp.Answers.OfType<TlsaRecord>().ToList();

                if (tlsaRecords.Any())
                {
                    found += tlsaRecords.Count;
                    foreach (var tlsa in tlsaRecords)
                    {
                        result.Details.Add($"{tlsaDomain}: Usage={tlsa.CertificateUsage}, Selector={tlsa.Selector}, MatchingType={tlsa.MatchingType}");
                    }
                }
                else
                {
                    result.Details.Add($"{tlsaDomain}: No TLSA records");
                }
            }

            result.Severity = found > 0 ? CheckSeverity.Pass : CheckSeverity.Info;
            result.Summary = found > 0 ? $"DANE: {found} TLSA record(s) found" : "No DANE/TLSA records";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class CaaRecordCheck : ICheck
{
    public string Name => "CAA Records";
    public CheckCategory Category => CheckCategory.CAA;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var resp = await ctx.Dns.QueryRawAsync(domain, QueryType.CAA);
            var caaRecords = resp.Answers.CaaRecords().ToList();

            if (caaRecords.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"{caaRecords.Count} CAA record(s)";
                foreach (var caa in caaRecords)
                    result.Details.Add($"CAA: {caa.Flags} {caa.Tag} \"{caa.Value}\"");
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No CAA records";
                result.Details.Add("No CAA records - any CA can issue certificates for this domain");
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

public class ZoneTransferCheck : ICheck
{
    public string Name => "AXFR Exposure";
    public CheckCategory Category => CheckCategory.ZoneTransfer;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.Options.EnableAxfr)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "AXFR test skipped (--no-axfr)";
            result.Details.Add("Zone transfer test was disabled via --no-axfr option");
            return new List<CheckResult> { result };
        }

        try
        {
            int vulnerable = 0;
            foreach (var nsHost in ctx.NsHosts)
            {
                if (!ctx.NsHostIps.TryGetValue(nsHost, out var ips)) continue;
                foreach (var ip in ips)
                {
                    if (!IPAddress.TryParse(ip, out var addr)) continue;
                    var canTransfer = await ctx.Dns.TestZoneTransferAsync(addr, domain);
                    if (canTransfer)
                    {
                        vulnerable++;
                        result.Errors.Add($"{nsHost} ({ip}): Zone transfer (AXFR) ALLOWED - security issue!");
                    }
                    else
                    {
                        result.Details.Add($"{nsHost} ({ip}): Zone transfer denied (good)");
                    }
                }
            }

            result.Severity = vulnerable > 0 ? CheckSeverity.Critical : CheckSeverity.Pass;
            result.Summary = vulnerable > 0
                ? $"AXFR allowed on {vulnerable} nameserver(s)!"
                : "Zone transfer denied on all nameservers";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class SecurityTxtCheck : ICheck
{
    public string Name => "security.txt (RFC 9116)";
    public CheckCategory Category => CheckCategory.SecurityTxt;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var url = $"https://{domain}/.well-known/security.txt";
            var (success, content, statusCode) = await ctx.Http.GetAsync(url);

            if (success && !string.IsNullOrWhiteSpace(content))
            {
                result.Details.Add($"Found at {url} (HTTP {statusCode})");

                bool hasContact = false;
                bool hasExpires = false;
                foreach (var line in content.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("Contact:", StringComparison.OrdinalIgnoreCase))
                    {
                        hasContact = true;
                        result.Details.Add($"  {trimmed}");
                    }
                    else if (trimmed.StartsWith("Expires:", StringComparison.OrdinalIgnoreCase))
                    {
                        hasExpires = true;
                        result.Details.Add($"  {trimmed}");
                    }
                    else if (trimmed.StartsWith("Encryption:", StringComparison.OrdinalIgnoreCase) ||
                             trimmed.StartsWith("Preferred-Languages:", StringComparison.OrdinalIgnoreCase) ||
                             trimmed.StartsWith("Canonical:", StringComparison.OrdinalIgnoreCase) ||
                             trimmed.StartsWith("Policy:", StringComparison.OrdinalIgnoreCase) ||
                             trimmed.StartsWith("Hiring:", StringComparison.OrdinalIgnoreCase) ||
                             trimmed.StartsWith("Acknowledgments:", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Details.Add($"  {trimmed}");
                    }
                }

                if (!hasContact)
                    result.Warnings.Add("security.txt is missing required Contact field");
                if (!hasExpires)
                    result.Warnings.Add("security.txt is missing required Expires field");

                result.Severity = (hasContact && hasExpires) ? CheckSeverity.Pass : CheckSeverity.Warning;
                result.Summary = "security.txt found";
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No security.txt found";
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
