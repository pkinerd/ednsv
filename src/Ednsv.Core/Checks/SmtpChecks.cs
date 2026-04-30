using System.Net;
using System.Net.Sockets;
using System.Text;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Checks;

public class SmtpTlsCertCheck : ICheck
{
    public string Name => "SMTP TLS Certificate";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to check TLS certificates";
                return new List<CheckResult> { result };
            }

            int unreachable = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);
                if (probe.CertSubject != null)
                {
                    result.Details.Add($"{mxHost}:");
                    result.Details.Add($"  Subject: {probe.CertSubject}");
                    result.Details.Add($"  Issuer: {probe.CertIssuer}");
                    result.Details.Add($"  Expires: {probe.CertExpiry:yyyy-MM-dd}");

                    if (probe.CertSans?.Any() == true)
                        result.Details.Add($"  SANs: {string.Join(", ", probe.CertSans)}");

                    // Check expiry
                    if (probe.CertExpiry < DateTime.UtcNow)
                    {
                        result.Errors.Add($"{mxHost}: Certificate EXPIRED on {probe.CertExpiry:yyyy-MM-dd}");
                    }
                    else if (probe.CertExpiry < DateTime.UtcNow.AddDays(30))
                    {
                        result.Warnings.Add($"{mxHost}: Certificate expires soon ({probe.CertExpiry:yyyy-MM-dd})");
                    }

                    // Check if domain is in SANs
                    var inSans = probe.CertSans?.Any(s =>
                        s.Equals(mxHost, StringComparison.OrdinalIgnoreCase) ||
                        (s.StartsWith("*.") && mxHost.EndsWith(s.Substring(1), StringComparison.OrdinalIgnoreCase))) ?? false;

                    if (!inSans)
                        result.Warnings.Add($"{mxHost}: MX hostname not found in certificate SANs");

                    // Show TLS protocol version
                    if (probe.TlsProtocol != default)
                        result.Details.Add($"  TLS Protocol: {probe.TlsProtocol}");
                }
                else if (probe.Connected && probe.SupportsStartTls)
                {
                    result.Warnings.Add($"{mxHost}: STARTTLS supported but TLS certificate could not be obtained ({probe.Error ?? "handshake failed"})");
                }
                else if (probe.Connected)
                {
                    result.Details.Add($"{mxHost}: Connected but STARTTLS not offered — no TLS certificate to check");
                }
                else
                {
                    unreachable++;
                    result.Details.Add($"{mxHost}: Could not connect ({probe.Error ?? "unknown error"})");
                }
            }

            result.Severity = result.Errors.Any() ? CheckSeverity.Error :
                             result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"Checked TLS certificates for {ctx.MxHosts.Count} MX host(s)";
            result.AdjustForUnreachableHosts(ctx.MxHosts.Count, unreachable);
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class SmtpTlsChainCheck : ICheck
{
    public string Name => "SMTP TLS Certificate Chain";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to check certificate chains";
                return new List<CheckResult> { result };
            }

            int unreachable = 0;
            int hostsChecked = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);
                if (probe.Certificate == null)
                {
                    if (!probe.Connected)
                        unreachable++;
                    continue;
                }

                hostsChecked++;
                result.Details.Add($"{mxHost}:");

                var intermediates = probe.CertChainIntermediates ?? new List<System.Security.Cryptography.X509Certificates.X509Certificate2>();
                if (intermediates.Count > 0)
                {
                    result.Details.Add($"  Intermediate CA(s) served ({intermediates.Count}):");
                    foreach (var ic in intermediates)
                        result.Details.Add($"    {ic.Subject}");
                }
                else
                {
                    // The leaf cert is itself self-signed — no intermediates expected
                    if (string.Equals(probe.Certificate.Subject, probe.Certificate.Issuer, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Details.Add($"  Self-signed leaf certificate — no intermediates needed");
                    }
                    else
                    {
                        result.Warnings.Add(
                            $"{mxHost}: Server is not serving intermediate CA certificate(s). " +
                            $"Issuer '{probe.Certificate.Issuer}' is not the same as Subject — clients without the intermediate cached locally may fail to verify the chain.");
                    }
                }
            }

            result.Severity = result.Errors.Any() ? CheckSeverity.Error :
                              result.Warnings.Any() ? CheckSeverity.Warning :
                              hostsChecked == 0 ? CheckSeverity.Info : CheckSeverity.Pass;
            result.Summary = hostsChecked == 0
                ? "No TLS-enabled MX hosts to check certificate chains"
                : $"Checked certificate chain completeness for {hostsChecked} MX host(s)";
            result.AdjustForUnreachableHosts(ctx.MxHosts.Count, unreachable);
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class DaneTlsaCertMatchCheck : ICheck
{
    public string Name => "DANE TLSA Cert Match";
    public CheckCategory Category => CheckCategory.DANE;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            bool anyTlsa = false;
            foreach (var mxHost in ctx.MxHosts)
            {
                var tlsaDomain = $"_25._tcp.{mxHost}";
                var resp = await ctx.Dns.QueryRawAsync(tlsaDomain, DnsClient.QueryType.TLSA);
                var tlsaRecords = resp.Answers.OfType<DnsClient.Protocol.TlsaRecord>().ToList();
                if (!tlsaRecords.Any()) continue;

                anyTlsa = true;
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);
                if (probe.CertSubject != null)
                {
                    result.Details.Add($"{mxHost}: TLSA records found, certificate available");

                    // Determine if any TLSA record has usage=3 (DANE-EE)
                    var hasDaneEe = tlsaRecords.Any(t => (int)t.CertificateUsage == 3);

                    // Check SAN match — DANE-EE (usage=3) exempts hostname checks per RFC 7671 §5.1
                    var inSans = probe.CertSans?.Any(s =>
                        s.Equals(mxHost, StringComparison.OrdinalIgnoreCase) ||
                        (s.StartsWith("*.") && mxHost.EndsWith(s.Substring(1), StringComparison.OrdinalIgnoreCase))) ?? false;

                    if (inSans)
                        result.Details.Add($"  SAN match: Yes");
                    else if (hasDaneEe)
                        result.Details.Add($"  {mxHost}: Certificate SAN does not match MX hostname (acceptable for DANE-EE usage=3)");
                    else
                        result.Warnings.Add($"{mxHost}: Certificate SAN does not match MX hostname");

                    // Check expiry — DANE-EE (usage=3) exempts expiry checks per RFC 7671 §5.1
                    if (probe.CertExpiry < DateTime.UtcNow && !hasDaneEe)
                        result.Errors.Add($"{mxHost}: Certificate expired (DANE validation would fail)");
                    else if (probe.CertExpiry < DateTime.UtcNow && hasDaneEe)
                        result.Details.Add($"  {mxHost}: Certificate expired but DANE-EE (usage=3) does not require expiry validation");

                    if (hasDaneEe)
                        result.Details.Add($"  DANE-EE (usage=3): hostname and expiry checks are not required per RFC 7671 §5.1");

                    // Validate TLSA digest against actual certificate
                    foreach (var tlsa in tlsaRecords)
                    {
                        var usage = (int)tlsa.CertificateUsage;
                        var usageDesc = usage switch
                        {
                            0 => "CA constraint (PKIX-TA)",
                            1 => "Service cert constraint (PKIX-EE)",
                            2 => "Trust anchor assertion (DANE-TA)",
                            3 => "Domain-issued cert (DANE-EE)",
                            _ => $"Unknown ({usage})"
                        };
                        result.Details.Add($"  TLSA Usage={usage} ({usageDesc}), Selector={(int)tlsa.Selector}, MatchingType={(int)tlsa.MatchingType}");

                        // #42: DANE-TA (usage=2) chain validation warning
                        if (usage == 2)
                            result.Warnings.Add($"{mxHost}: DANE-TA (usage=2): validation should include the full certificate chain, not just the leaf certificate — intermediary CA matching not performed");

                        // Compute digest from cert and compare
                        byte[]? dataToHash = null;
                        if (probe.Certificate != null)
                        {
                            if ((int)tlsa.Selector == 0) // Full certificate
                                dataToHash = probe.Certificate.RawData;
                            else if ((int)tlsa.Selector == 1) // SubjectPublicKeyInfo
                                dataToHash = probe.Certificate.PublicKey.ExportSubjectPublicKeyInfo();
                        }

                        if (dataToHash != null)
                        {
                            byte[]? computed = null;
                            if ((int)tlsa.MatchingType == 1) // SHA-256
                                computed = System.Security.Cryptography.SHA256.HashData(dataToHash);
                            else if ((int)tlsa.MatchingType == 2) // SHA-512
                                computed = System.Security.Cryptography.SHA512.HashData(dataToHash);
                            else if ((int)tlsa.MatchingType == 0) // Exact match
                                computed = dataToHash;

                            if (computed != null)
                            {
                                var computedHex = Convert.ToHexString(computed).ToLowerInvariant();
                                var certAssocData = tlsa.CertificateAssociationData.ToArray();
                                var tlsaHex = Convert.ToHexString(certAssocData).ToLowerInvariant();
                                if (computedHex == tlsaHex)
                                    result.Details.Add($"  TLSA digest MATCH (verified)");
                                else
                                    result.Warnings.Add($"{mxHost}: TLSA digest does NOT match certificate (DANE validation would fail)");
                            }
                        }
                    }
                }
                else
                {
                    result.Warnings.Add($"{mxHost}: TLSA records present but no certificate to validate against");
                }
            }

            if (!anyTlsa)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No TLSA records to match against certificates";
            }
            else
            {
                result.Severity = result.Errors.Any() ? CheckSeverity.Error :
                                 result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
                result.Summary = "DANE TLSA certificate match check completed";
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

public class SmtpBannerCheck : ICheck
{
    public string Name => "SMTP Banner Validation";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            int unreachable = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);
                if (probe.Connected)
                {
                    result.Details.Add($"{mxHost}: Banner: {probe.Banner}");

                    // RFC 5321 §4.2: Response must start with "220"
                    if (!probe.Banner.StartsWith("220"))
                    {
                        result.Warnings.Add($"{mxHost}: Banner does not start with 220 (RFC 5321 §4.2)");
                    }
                    else
                    {
                        // RFC 5321 §4.3.1: "220 <domain> <text>" format expected
                        var bannerBody = probe.Banner.Length > 4 ? probe.Banner.Substring(4).Trim() : "";
                        if (string.IsNullOrEmpty(bannerBody))
                            result.Warnings.Add($"{mxHost}: Banner has no hostname after 220 (RFC 5321 §4.3.1)");
                        else
                        {
                            var bannerHost = bannerBody.Split(' ')[0];
                            // Warn if banner hostname is not an FQDN (no dots)
                            if (!bannerHost.Contains('.'))
                                result.Warnings.Add($"{mxHost}: Banner hostname '{bannerHost}' is not an FQDN (RFC 5321 §4.1.2)");
                        }
                    }

                    // Check if hostname in banner matches MX — mismatch is common
                    // for large providers using shared/load-balanced banners
                    if (!probe.Banner.Contains(mxHost, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Details.Add($"  Banner hostname differs from MX FQDN (common for load-balanced MX)");
                    }
                }
                else
                {
                    unreachable++;
                    result.Details.Add($"{mxHost}: Could not connect");
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"Checked SMTP banners for {ctx.MxHosts.Count} MX host(s)";
            result.AdjustForUnreachableHosts(ctx.MxHosts.Count, unreachable);
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Cross-checks reverse DNS (PTR) of MX server IPs against SMTP banner hostname.
/// MXToolbox flags mismatches as a deliverability concern.
/// </summary>
public class SmtpBannerRdnsMatchCheck : ICheck
{
    public string Name => "SMTP Banner vs Reverse DNS";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to check banner/rDNS match";
                return new List<CheckResult> { result };
            }

            int matched = 0, mismatched = 0, skipped = 0;

            foreach (var mxHost in ctx.MxHosts)
            {
                if (!ctx.MxHostIps.TryGetValue(mxHost, out var ips) || !ips.Any())
                {
                    skipped++;
                    continue;
                }

                // Get banner hostname
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);

                if (!probe.Connected || string.IsNullOrEmpty(probe.Banner))
                {
                    result.Details.Add($"{mxHost}: Could not connect or no banner");
                    skipped++;
                    continue;
                }

                // Extract banner hostname (format: "220 hostname ...")
                string? bannerHost = null;
                if (probe.Banner.StartsWith("220") && probe.Banner.Length > 4)
                    bannerHost = probe.Banner.Substring(4).Trim().Split(' ')[0].TrimEnd('.');

                if (string.IsNullOrEmpty(bannerHost))
                {
                    skipped++;
                    continue;
                }

                foreach (var ip in ips)
                {
                    var ptrs = await ctx.Dns.ResolvePtrAsync(ip);
                    if (!ptrs.Any())
                    {
                        result.Warnings.Add($"{mxHost} ({ip}): No PTR record to compare with banner '{bannerHost}'");
                        mismatched++;
                        continue;
                    }

                    var ptrMatch = ptrs.Any(p =>
                        p.TrimEnd('.').Equals(bannerHost, StringComparison.OrdinalIgnoreCase));

                    if (ptrMatch)
                    {
                        matched++;
                        result.Details.Add($"{mxHost} ({ip}): PTR matches banner hostname '{bannerHost}'");
                    }
                    else
                    {
                        mismatched++;
                        result.Warnings.Add(
                            $"{mxHost} ({ip}): PTR [{string.Join(", ", ptrs.Select(p => p.TrimEnd('.')))}] " +
                            $"does not match banner hostname '{bannerHost}'");
                    }
                }
            }

            if (mismatched > 0)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"{mismatched} MX IP(s) have rDNS/banner hostname mismatch";
                result.Warnings.Add("Reverse DNS should match the SMTP banner hostname for best deliverability");
            }
            else if (matched > 0)
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"All {matched} MX IP(s) have matching rDNS and banner hostname";
            }
            else
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "Could not compare rDNS and banner (no data)";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "Banner/rDNS match check failed";
        }

        return new List<CheckResult> { result };
    }
}

/// <summary>
/// Reports SMTP connection and transaction timing — slow response times indicate
/// server issues and can cause delivery timeouts. Similar to MXToolbox SMTP timing.
/// </summary>
public class SmtpTransactionTimingCheck : ICheck
{
    public string Name => "SMTP Transaction Timing";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to measure timing";
                return new List<CheckResult> { result };
            }

            bool anySlow = false;
            int unreachable = 0;

            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);

                if (!probe.Connected)
                {
                    unreachable++;
                    result.Details.Add($"{mxHost}: Could not connect ({probe.Error ?? "timeout"})");
                    continue;
                }

                var parts = new List<string>();

                if (probe.ConnectTimeMs > 0)
                {
                    parts.Add($"Connect: {probe.ConnectTimeMs}ms");
                    if (probe.ConnectTimeMs > 5000)
                    {
                        anySlow = true;
                        result.Warnings.Add($"{mxHost}: Slow connection ({probe.ConnectTimeMs}ms > 5000ms)");
                    }
                }

                if (probe.BannerTimeMs > 0)
                {
                    parts.Add($"Banner: {probe.BannerTimeMs}ms");
                    if (probe.BannerTimeMs > 5000)
                    {
                        anySlow = true;
                        result.Warnings.Add($"{mxHost}: Slow banner response ({probe.BannerTimeMs}ms > 5000ms)");
                    }
                }

                if (probe.EhloTimeMs > 0)
                {
                    parts.Add($"EHLO: {probe.EhloTimeMs}ms");
                    if (probe.EhloTimeMs > 5000)
                    {
                        anySlow = true;
                        result.Warnings.Add($"{mxHost}: Slow EHLO response ({probe.EhloTimeMs}ms > 5000ms)");
                    }
                }

                if (probe.TlsTimeMs > 0)
                    parts.Add($"TLS: {probe.TlsTimeMs}ms");

                long total = probe.ConnectTimeMs + probe.BannerTimeMs + probe.EhloTimeMs + probe.TlsTimeMs;
                if (total > 0)
                {
                    result.Details.Add($"{mxHost}: {string.Join(", ", parts)} (Total: {total}ms)");
                    if (total > 15000)
                    {
                        anySlow = true;
                        result.Warnings.Add($"{mxHost}: Total SMTP transaction time {total}ms exceeds 15s");
                    }
                }
                else
                {
                    result.Details.Add($"{mxHost}: Timing data not available");
                }
            }

            result.Severity = anySlow ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.AdjustForUnreachableHosts(ctx.MxHosts.Count, unreachable);
            result.Summary = anySlow
                ? "Slow SMTP response times detected"
                : $"SMTP timing acceptable for {ctx.MxHosts.Count} MX host(s)";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
            result.Summary = "SMTP timing check failed";
        }

        return new List<CheckResult> { result };
    }
}

public class EhloCapabilitiesCheck : ICheck
{
    public string Name => "EHLO Capabilities";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            int unreachable = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);
                if (probe.Connected && probe.EhloCapabilities.Any())
                {
                    result.Details.Add($"{mxHost} EHLO capabilities:");
                    foreach (var cap in probe.EhloCapabilities)
                    {
                        var trimmed = cap.Trim();
                        if (trimmed.Length > 4) // skip code prefix
                            result.Details.Add($"  {trimmed.Substring(4).Trim()}");
                        else
                            result.Details.Add($"  {trimmed}");
                    }

                    // Check for important extensions
                    var capText = string.Join(" ", probe.EhloCapabilities);
                    var extensions = new[] { "STARTTLS", "SIZE", "8BITMIME", "SMTPUTF8", "CHUNKING", "PIPELINING" };
                    foreach (var ext in extensions)
                    {
                        if (!capText.Contains(ext, StringComparison.OrdinalIgnoreCase))
                            result.Details.Add($"  Missing: {ext}");
                    }

                    // Highlight SMTPUTF8/EAI readiness (RFC 6531 — optional extension)
                    if (capText.Contains("SMTPUTF8", StringComparison.OrdinalIgnoreCase))
                        result.Details.Add($"  {mxHost} supports SMTPUTF8 (internationalized email addresses/EAI ready)");
                    else
                        result.Details.Add($"  {mxHost}: No SMTPUTF8 (internationalized email not supported — optional per RFC 6531)");
                }
                else
                {
                    if (!probe.Connected) unreachable++;
                    result.Details.Add($"{mxHost}: Could not retrieve EHLO capabilities");
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Info : CheckSeverity.Pass;
            result.Summary = "EHLO capabilities retrieved";
            result.AdjustForUnreachableHosts(ctx.MxHosts.Count, unreachable);
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class SubmissionPortsCheck : ICheck
{
    public string Name => "Submission Ports";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            // Probe all submission ports in parallel (port probes are cached)
            var probeTasks = new List<(string host, int port, Task<bool> task)>();
            foreach (var mxHost in ctx.MxHosts)
            {
                foreach (var port in new[] { 587, 465 })
                {
                    var h = mxHost;
                    var p = port;
                    probeTasks.Add((h, p, Task.Run(() => ctx.Smtp.ProbePortAsync(h, p))));
                }
            }

            await Task.WhenAll(probeTasks.Select(t => t.task));

            // SMTP probe open 587 ports in parallel for TLS details
            var smtpProbeTasks = new List<(string host, Task<SmtpProbeResult> task)>();
            foreach (var mxHost in ctx.MxHosts)
            {
                var port587 = probeTasks.First(t => t.host == mxHost && t.port == 587).task.Result;
                if (port587)
                {
                    var h = mxHost;
                    smtpProbeTasks.Add((h, Task.Run(() => ctx.Smtp.ProbeSmtpAsync(h, 587))));
                }
            }
            if (smtpProbeTasks.Count > 0)
                await Task.WhenAll(smtpProbeTasks.Select(t => t.task));

            foreach (var mxHost in ctx.MxHosts)
            {
                var port587 = probeTasks.First(t => t.host == mxHost && t.port == 587).task.Result;
                var port465 = probeTasks.First(t => t.host == mxHost && t.port == 465).task.Result;

                result.Details.Add($"{mxHost}:");
                result.Details.Add($"  Port 587 (submission): {(port587 ? "Open" : "Closed/Filtered")}");
                result.Details.Add($"  Port 465 (SMTPS): {(port465 ? "Open" : "Closed/Filtered")}");

                if (port465)
                    result.Details.Add($"  Port 465 (implicit TLS) is open — TLS certificate and version details not probed (only port 25/587 STARTTLS is checked)");

                if (port587)
                {
                    var probe587 = smtpProbeTasks.FirstOrDefault(t => t.host == mxHost).task?.Result;
                    if (probe587?.Connected == true)
                    {
                        if (probe587.SupportsStartTls)
                            result.Details.Add($"  Port 587 TLS: {probe587.TlsProtocol} ({probe587.TlsCipherSuite ?? "unknown cipher"})");
                        else
                            result.Warnings.Add($"{mxHost}: Port 587 open but STARTTLS not offered");
                    }
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Info;
            result.Summary = result.Warnings.Any()
                ? "Submission port issues detected"
                : "Submission port probe completed";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

internal static class SmtpResponseAnalyzer
{
    private static readonly string[] BlocklistIndicators = { "spamhaus", "barracuda", "blocklist", "blacklist", "blocked", "denied", "reject", "dnsbl", "rbl", "cbl", "sbl", "xbl", "Client host" };

    /// <summary>
    /// Determines if an SMTP rejection response indicates our source IP was blocked
    /// rather than the recipient address being refused.
    /// </summary>
    public static bool IsSourceIpBlocked(string response)
    {
        if (string.IsNullOrEmpty(response)) return false;
        // 5.7.1 with blocklist keywords = our IP is blocked
        return response.Contains("5.7.1") &&
               BlocklistIndicators.Any(kw => response.Contains(kw, StringComparison.OrdinalIgnoreCase));
    }
}

public class PostmasterAddressCheck : ICheck
{
    public string Name => "Postmaster Address";
    public CheckCategory Category => CheckCategory.Postmaster;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to check postmaster";
                return new List<CheckResult> { result };
            }

            int acceptedCount = 0;
            int rejectedCount = 0;
            int ipBlockedCount = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var (accepted, response) = await ctx.Smtp.ProbeRcptDetailedAsync(mxHost, $"postmaster@{domain}");
                result.Details.Add($"postmaster@{domain} via {mxHost}: {(accepted ? "Accepted" : "Rejected")}");
                if (!accepted)
                {
                    result.Details.Add($"  Server response: {response}");
                    if (SmtpResponseAnalyzer.IsSourceIpBlocked(response))
                    {
                        ipBlockedCount++;
                        result.Details.Add($"  Note: Rejection appears to be IP-based blocking, not address refusal");
                    }
                    else
                    {
                        result.Warnings.Add($"postmaster@{domain} rejected by {mxHost} ({response})");
                    }
                    rejectedCount++;
                }
                else
                {
                    acceptedCount++;
                }
            }

            if (rejectedCount > 0 && ipBlockedCount == rejectedCount)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "postmaster@ check inconclusive — our source IP is blocklisted by the server";
            }
            else if (rejectedCount > ipBlockedCount && rejectedCount - ipBlockedCount == ctx.MxHosts.Count - ipBlockedCount)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "postmaster@ not accepted on any MX (RFC 5321 §4.5.1 requires it)";
            }
            else if (rejectedCount > ipBlockedCount)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"postmaster@ rejected on {rejectedCount - ipBlockedCount}/{ctx.MxHosts.Count} MX host(s)";
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = ctx.MxHosts.Count > 1
                    ? $"postmaster@ accepted on all {ctx.MxHosts.Count} MX hosts"
                    : "postmaster@ accepted";
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

public class AbuseAddressCheck : ICheck
{
    public string Name => "Abuse Address";
    public CheckCategory Category => CheckCategory.Abuse;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to check abuse@";
                return new List<CheckResult> { result };
            }

            int acceptedCount = 0;
            int rejectedCount = 0;
            int ipBlockedCount = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var (accepted, response) = await ctx.Smtp.ProbeRcptDetailedAsync(mxHost, $"abuse@{domain}");
                result.Details.Add($"abuse@{domain} via {mxHost}: {(accepted ? "Accepted" : "Rejected")}");
                if (!accepted)
                {
                    result.Details.Add($"  Server response: {response}");
                    if (SmtpResponseAnalyzer.IsSourceIpBlocked(response))
                    {
                        ipBlockedCount++;
                        result.Details.Add($"  Note: Rejection appears to be IP-based blocking, not address refusal");
                    }
                    else
                    {
                        result.Warnings.Add($"abuse@{domain} rejected by {mxHost} ({response})");
                    }
                    rejectedCount++;
                }
                else
                {
                    acceptedCount++;
                }
            }

            if (rejectedCount > 0 && ipBlockedCount == rejectedCount)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "abuse@ check inconclusive — our source IP is blocklisted by the server";
            }
            else if (rejectedCount > ipBlockedCount && rejectedCount - ipBlockedCount == ctx.MxHosts.Count - ipBlockedCount)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "abuse@ not accepted on any MX (RFC 2142 recommends it)";
            }
            else if (rejectedCount > ipBlockedCount)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"abuse@ rejected on {rejectedCount - ipBlockedCount}/{ctx.MxHosts.Count} MX host(s)";
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = ctx.MxHosts.Count > 1
                    ? $"abuse@ accepted on all {ctx.MxHosts.Count} MX hosts"
                    : "abuse@ accepted";
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

public class OpenRelayCheck : ICheck
{
    public string Name => "Open Relay Test";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.Options.EnableOpenRelay)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Open relay test skipped (use --open-relay to enable)";
            return new List<CheckResult> { result };
        }

        if (!ctx.MxHosts.Any())
        {
            result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
            result.Summary = "No MX hosts to test";
            return new List<CheckResult> { result };
        }

        try
        {
            var relayDetected = false;
            foreach (var mxHost in ctx.MxHosts)
            {
                // Test relay through the cached SMTP service
                var relayResult = await ctx.Smtp.TestRelayAsync(mxHost, domain);
                result.Details.Add($"{mxHost}: {relayResult.description}");

                if (relayResult.isRelay)
                {
                    relayDetected = true;
                    result.Errors.Add($"{mxHost}: Server appears to be an open relay — accepts mail for external destinations");
                }
            }

            if (relayDetected)
            {
                result.Severity = CheckSeverity.Critical;
                result.Summary = "Open relay detected — server accepts mail for external domains";
                result.Errors.Add("Open relays are abused by spammers and will get your server blocklisted");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No open relay — server correctly rejects external relay attempts";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Could not test open relay";
            result.Details.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }

}

public class CatchAllDetectionCheck : ICheck
{
    public string Name => "Catch-All Detection";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (!ctx.Options.EnableCatchAll)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Catch-all test skipped (use --catch-all to enable)";
            return new List<CheckResult> { result };
        }

        if (!ctx.MxHosts.Any())
        {
            result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
            result.Summary = "No MX hosts to test";
            return new List<CheckResult> { result };
        }

        try
        {
            var mxHost = ctx.MxHosts.First();
            // Generate a random address that should not exist
            var randomLocal = $"ednsv-probe-{Guid.NewGuid():N}";
            var randomAddress = $"{randomLocal}@{domain}";

            var accepted = await ctx.Smtp.ProbeRcptAsync(mxHost, randomAddress);
            result.Details.Add($"Probed {randomAddress} via {mxHost}: {(accepted ? "Accepted" : "Rejected")}");

            if (accepted)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "Catch-all detected — server accepts mail for any address";
                result.Warnings.Add("Server accepted a random non-existent address — catch-all/accept-all is configured");
                result.Warnings.Add("Catch-all increases spam exposure and makes it harder to detect typos in recipient addresses");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "No catch-all — server rejects unknown recipients";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "Could not test catch-all";
            result.Details.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class SmtpStarttlsEnforcementCheck : ICheck
{
    public string Name => "STARTTLS Enforcement";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to check STARTTLS";
                return new List<CheckResult> { result };
            }

            var missingTls = new List<string>();
            int unreachable = 0;
            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.GetOrProbeSmtpAsync(mxHost);

                if (!probe.Connected)
                {
                    unreachable++;
                    result.Details.Add($"{mxHost}: Could not connect");
                    continue;
                }

                if (probe.SupportsStartTls)
                {
                    result.Details.Add($"{mxHost}: STARTTLS supported (TLS {probe.TlsProtocol})");
                }
                else
                {
                    missingTls.Add(mxHost);
                    result.Errors.Add($"{mxHost}: STARTTLS NOT offered — mail transmitted in plaintext");
                }
            }

            if (missingTls.Any())
            {
                result.Severity = CheckSeverity.Error;
                result.Summary = $"{missingTls.Count} MX host(s) missing STARTTLS — major deliverability risk";
                result.Errors.Add("Gmail, Outlook, and other major providers may refuse or flag mail from servers without TLS");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "All MX hosts support STARTTLS";
                result.AdjustForUnreachableHosts(ctx.MxHosts.Count, unreachable);
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

public class SmtpIpv6ConnectivityCheck : ICheck
{
    public string Name => "SMTP IPv6 Connectivity";
    public CheckCategory Category => CheckCategory.IPv6;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = ctx.SeverityForMissing(ctx.MxLookupFailed);
                result.Summary = "No MX hosts to check IPv6 connectivity";
                return new List<CheckResult> { result };
            }

            int hasAaaa = 0;
            int reachable = 0;
            int unreachable = 0;

            // Resolve AAAA records for all MX hosts, then probe all IPv6 addresses
            // concurrently using the cached port probe service
            var probes = new List<(string host, string addr, Task<bool> task)>();
            foreach (var mxHost in ctx.MxHosts)
            {
                var v6Addrs = await ctx.Dns.ResolveAAAAAsync(mxHost);
                if (!v6Addrs.Any())
                {
                    result.Details.Add($"{mxHost}: No AAAA records");
                    continue;
                }

                hasAaaa++;
                foreach (var addr in v6Addrs)
                {
                    probes.Add((mxHost, addr, ctx.Smtp.ProbePortAsync(addr, 25)));
                }
            }

            if (probes.Count > 0)
                await Task.WhenAll(probes.Select(p => p.task));

            foreach (var (host, addr, task) in probes)
            {
                if (task.Result)
                {
                    reachable++;
                    result.Details.Add($"{host} [{addr}]: Port 25 reachable over IPv6");
                }
                else
                {
                    unreachable++;
                    result.Warnings.Add($"{host} [{addr}]: AAAA exists but port 25 unreachable over IPv6");
                }
            }

            if (hasAaaa == 0)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX hosts have AAAA records — IPv6 not applicable";
            }
            else if (unreachable > 0)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"{unreachable} MX IPv6 address(es) unreachable — stale AAAA records cause delivery delays";
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"{reachable} MX IPv6 address(es) reachable";
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
