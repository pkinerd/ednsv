using System.Net.Sockets;
using System.Text;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class SmtpTlsCertCheck : ICheck
{
    public string Name => "SMTP TLS Certificate";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX hosts to check TLS certificates";
                return new List<CheckResult> { result };
            }

            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.Smtp.ProbeSmtpAsync(mxHost, 25);
                if (probe.Certificate != null)
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
                }
                else if (probe.Connected)
                {
                    result.Warnings.Add($"{mxHost}: Connected but no TLS certificate obtained");
                }
                else
                {
                    result.Details.Add($"{mxHost}: Could not connect ({probe.Error ?? "unknown error"})");
                }
            }

            result.Severity = result.Errors.Any() ? CheckSeverity.Error :
                             result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"Checked TLS certificates for {ctx.MxHosts.Count} MX host(s)";
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

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
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
                var probe = await ctx.Smtp.ProbeSmtpAsync(mxHost, 25);
                if (probe.Certificate != null)
                {
                    result.Details.Add($"{mxHost}: TLSA records found, certificate available");
                    // Check SAN match
                    var inSans = probe.CertSans?.Any(s =>
                        s.Equals(mxHost, StringComparison.OrdinalIgnoreCase) ||
                        (s.StartsWith("*.") && mxHost.EndsWith(s.Substring(1), StringComparison.OrdinalIgnoreCase))) ?? false;

                    if (inSans)
                        result.Details.Add($"  SAN match: Yes");
                    else
                        result.Warnings.Add($"{mxHost}: Certificate SAN does not match MX hostname");

                    if (probe.CertExpiry < DateTime.UtcNow)
                        result.Errors.Add($"{mxHost}: Certificate expired (DANE validation would fail)");

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

                        // Compute digest from cert and compare
                        byte[]? dataToHash = null;
                        if ((int)tlsa.Selector == 0) // Full certificate
                            dataToHash = probe.Certificate.RawData;
                        else if ((int)tlsa.Selector == 1) // SubjectPublicKeyInfo
                            dataToHash = probe.Certificate.PublicKey.ExportSubjectPublicKeyInfo();

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

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.Smtp.ProbeSmtpAsync(mxHost, 25);
                if (probe.Connected)
                {
                    result.Details.Add($"{mxHost}: Banner: {probe.Banner}");

                    // Check if banner starts with 220
                    if (!probe.Banner.StartsWith("220"))
                    {
                        result.Warnings.Add($"{mxHost}: Banner does not start with 220");
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
                    result.Details.Add($"{mxHost}: Could not connect");
                }
            }

            result.Severity = result.Warnings.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
            result.Summary = $"Checked SMTP banners for {ctx.MxHosts.Count} MX host(s)";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class EhloCapabilitiesCheck : ICheck
{
    public string Name => "EHLO Capabilities";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            foreach (var mxHost in ctx.MxHosts)
            {
                var probe = await ctx.Smtp.ProbeSmtpAsync(mxHost, 25);
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
                }
                else
                {
                    result.Details.Add($"{mxHost}: Could not retrieve EHLO capabilities");
                }
            }

            result.Severity = CheckSeverity.Info;
            result.Summary = "EHLO capabilities retrieved";
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

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            // Throttle to 2 concurrent probes to avoid looking like a port scan
            using var semaphore = new SemaphoreSlim(2);
            var probeTasks = new List<(string host, int port, Task<bool> task)>();
            foreach (var mxHost in ctx.MxHosts)
            {
                foreach (var port in new[] { 587, 465 })
                {
                    var h = mxHost;
                    var p = port;
                    var task = Task.Run(async () =>
                    {
                        await semaphore.WaitAsync();
                        try { return await ctx.Smtp.ProbePortAsync(h, p); }
                        finally { semaphore.Release(); }
                    });
                    probeTasks.Add((h, p, task));
                }
            }

            await Task.WhenAll(probeTasks.Select(t => t.task));

            foreach (var mxHost in ctx.MxHosts)
            {
                var port587 = probeTasks.First(t => t.host == mxHost && t.port == 587).task.Result;
                var port465 = probeTasks.First(t => t.host == mxHost && t.port == 465).task.Result;

                result.Details.Add($"{mxHost}:");
                result.Details.Add($"  Port 587 (submission): {(port587 ? "Open" : "Closed/Filtered")}");
                result.Details.Add($"  Port 465 (SMTPS): {(port465 ? "Open" : "Closed/Filtered")}");
            }

            result.Severity = CheckSeverity.Info;
            result.Summary = "Submission port probe completed";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class PostmasterAddressCheck : ICheck
{
    public string Name => "Postmaster Address";
    public CheckCategory Category => CheckCategory.Postmaster;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX hosts to check postmaster";
                return new List<CheckResult> { result };
            }

            var mxHost = ctx.MxHosts.First();
            var accepted = await ctx.Smtp.ProbeRcptAsync(mxHost, $"postmaster@{domain}");
            result.Details.Add($"postmaster@{domain} via {mxHost}: {(accepted ? "Accepted" : "Rejected/Unknown")}");

            if (!accepted)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "postmaster@ not accepted (RFC 5321 §4.5.1 requires it)";
                result.Warnings.Add($"postmaster@{domain} was not accepted - RFC 5321 requires this address");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "postmaster@ accepted";
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

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (!ctx.MxHosts.Any())
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No MX hosts to check abuse@";
                return new List<CheckResult> { result };
            }

            var mxHost = ctx.MxHosts.First();
            var accepted = await ctx.Smtp.ProbeRcptAsync(mxHost, $"abuse@{domain}");
            result.Details.Add($"abuse@{domain} via {mxHost}: {(accepted ? "Accepted" : "Rejected/Unknown")}");

            if (!accepted)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "abuse@ not accepted (RFC 2142 recommends it)";
                result.Warnings.Add($"abuse@{domain} was not accepted - RFC 2142 recommends this address");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = "abuse@ accepted";
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

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
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
            result.Severity = CheckSeverity.Info;
            result.Summary = "No MX hosts to test";
            return new List<CheckResult> { result };
        }

        try
        {
            var relayDetected = false;
            foreach (var mxHost in ctx.MxHosts)
            {
                // Test relay: use an external sender and external recipient
                // If the server accepts RCPT TO for an address outside its domain
                // when MAIL FROM is also outside its domain, it's an open relay
                var relayResult = await TestRelayAsync(mxHost, domain);
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

    private async Task<(bool isRelay, string description)> TestRelayAsync(string mxHost, string domain)
    {
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var timeout = TimeSpan.FromSeconds(10);
            var connectTask = client.ConnectAsync(mxHost, 25);
            if (await Task.WhenAny(connectTask, Task.Delay(timeout)) != connectTask)
                return (false, "Connection timed out");
            await connectTask;

            var stream = client.GetStream();
            stream.ReadTimeout = 10000;
            stream.WriteTimeout = 10000;

            await ReadSmtpLineAsync(stream); // banner
            await WriteSmtpLineAsync(stream, "EHLO ednsv-relay-test.invalid");
            await ReadSmtpMultiLineAsync(stream);

            // Use a clearly non-existent external sender and recipient
            // to test if the server will relay mail it has no business handling
            await WriteSmtpLineAsync(stream, "MAIL FROM:<relay-test@ednsv-probe.invalid>");
            var mailResp = await ReadSmtpLineAsync(stream);
            if (!mailResp.StartsWith("250"))
            {
                await WriteSmtpLineAsync(stream, "QUIT");
                return (false, $"MAIL FROM rejected ({mailResp.Substring(0, Math.Min(50, mailResp.Length))}) — not an open relay");
            }

            // Try to relay to an external domain (not the target domain)
            await WriteSmtpLineAsync(stream, "RCPT TO:<relay-test@ednsv-probe.invalid>");
            var rcptResp = await ReadSmtpLineAsync(stream);

            await WriteSmtpLineAsync(stream, "QUIT");

            if (rcptResp.StartsWith("250") || rcptResp.StartsWith("251"))
                return (true, $"RCPT TO for external address ACCEPTED ({rcptResp.Substring(0, Math.Min(50, rcptResp.Length))})");

            return (false, $"RCPT TO for external address rejected ({rcptResp.Substring(0, Math.Min(50, rcptResp.Length))}) — not an open relay");
        }
        catch (Exception ex)
        {
            return (false, $"Error: {ex.Message}");
        }
        finally
        {
            client?.Dispose();
        }
    }

    private static async Task<string> ReadSmtpLineAsync(NetworkStream stream)
    {
        var buffer = new byte[4096];
        var sb = new StringBuilder();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var read = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
            if (read > 0) sb.Append(Encoding.ASCII.GetString(buffer, 0, read));
        }
        catch { }
        return sb.ToString().TrimEnd('\r', '\n');
    }

    private static async Task<List<string>> ReadSmtpMultiLineAsync(NetworkStream stream)
    {
        var lines = new List<string>();
        var buffer = new byte[8192];
        var sb = new StringBuilder();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (true)
            {
                var read = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                if (read == 0) break;
                sb.Append(Encoding.ASCII.GetString(buffer, 0, read));
                var allLines = sb.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (allLines.Any(l => l.TrimEnd('\r').Length >= 4 && l[3] == ' '))
                    break;
            }
        }
        catch { }
        foreach (var line in sb.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries))
            lines.Add(line.TrimEnd('\r'));
        return lines;
    }

    private static async Task WriteSmtpLineAsync(NetworkStream stream, string line)
    {
        var data = Encoding.ASCII.GetBytes(line + "\r\n");
        await stream.WriteAsync(data, 0, data.Length);
        await stream.FlushAsync();
    }
}

public class CatchAllDetectionCheck : ICheck
{
    public string Name => "Catch-All Detection";
    public CheckCategory Category => CheckCategory.SMTP;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
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
            result.Severity = CheckSeverity.Info;
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
