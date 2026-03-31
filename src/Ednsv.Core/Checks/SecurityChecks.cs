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
            }

            if (dsRecords.Any() || dnskeys.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "DNSSEC is enabled";
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
                result.Details.Add($"TXT: {string.Join("", stsRecord.Text)}");

                // Fetch policy file
                var policyUrl = $"https://mta-sts.{domain}/.well-known/mta-sts.txt";
                var (success, content, statusCode) = await ctx.Http.GetAsync(policyUrl);

                if (success)
                {
                    result.Details.Add($"Policy fetched from {policyUrl} (HTTP {statusCode})");
                    foreach (var line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = line.Trim();
                        result.Details.Add($"  {trimmed}");

                        if (trimmed.StartsWith("mode:", StringComparison.OrdinalIgnoreCase))
                        {
                            var mode = trimmed.Substring(5).Trim();
                            if (mode == "enforce")
                                result.Details.Add("  Mode: enforce (strict)");
                            else if (mode == "testing")
                                result.Warnings.Add("MTA-STS mode is 'testing' - not enforcing");
                            else if (mode == "none")
                                result.Warnings.Add("MTA-STS mode is 'none' - disabled");
                        }
                    }

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
                result.Severity = CheckSeverity.Pass;
                result.Summary = "TLS-RPT configured";
                result.Details.Add($"TLS-RPT: {text}");
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
        "<animateTransform", "<use ", "<image "
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

            // Parse tags
            var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = part.Trim();
                var eqIdx = trimmed.IndexOf('=');
                if (eqIdx > 0)
                    tags[trimmed.Substring(0, eqIdx).Trim()] = trimmed.Substring(eqIdx + 1).Trim();
            }

            // Validate logo URL (l= tag)
            if (tags.TryGetValue("l", out var logoUrl))
            {
                result.Details.Add($"Logo URL: {logoUrl}");
                if (!string.IsNullOrEmpty(logoUrl))
                {
                    if (!logoUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        result.Warnings.Add("BIMI logo URL must use HTTPS");

                    if (!logoUrl.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
                        result.Warnings.Add("BIMI logo should be SVG format");

                    var (success, svgContent, statusCode) = await ctx.Http.GetAsync(logoUrl);
                    result.Details.Add($"Logo reachable: {(success ? "Yes" : "No")} (HTTP {statusCode})");
                    if (!success)
                    {
                        result.Warnings.Add("BIMI logo URL is not reachable");
                    }
                    else
                    {
                        ValidateSvg(svgContent, result);
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
                result.Details.Add("No VMC (a= tag) specified — self-asserted BIMI");
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
