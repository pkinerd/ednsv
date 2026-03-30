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

            if (tags.TryGetValue("l", out var logoUrl))
            {
                result.Details.Add($"Logo URL: {logoUrl}");
                if (!string.IsNullOrEmpty(logoUrl))
                {
                    if (!logoUrl.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
                        result.Warnings.Add("BIMI logo should be SVG format");

                    // Check reachability
                    var (success, _, statusCode) = await ctx.Http.GetAsync(logoUrl);
                    result.Details.Add($"Logo reachable: {(success ? "Yes" : "No")} (HTTP {statusCode})");
                    if (!success)
                        result.Warnings.Add("BIMI logo URL is not reachable");
                }
            }

            if (tags.TryGetValue("a", out var vmcUrl))
            {
                result.Details.Add($"VMC URL: {vmcUrl}");
                if (!string.IsNullOrEmpty(vmcUrl))
                {
                    var (success, _, statusCode) = await ctx.Http.GetAsync(vmcUrl);
                    result.Details.Add($"VMC reachable: {(success ? "Yes" : "No")} (HTTP {statusCode})");
                }
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
