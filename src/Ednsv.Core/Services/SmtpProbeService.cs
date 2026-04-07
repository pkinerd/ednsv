using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Ednsv.Core.Services;

public class SmtpProbeResult
{
    public bool Connected { get; set; }
    public string Banner { get; set; } = "";
    public bool SupportsStartTls { get; set; }
    public List<string> EhloCapabilities { get; set; } = new();
    public X509Certificate2? Certificate { get; set; }
    public string? CertSubject { get; set; }
    public string? CertIssuer { get; set; }
    public DateTime? CertExpiry { get; set; }
    public List<string>? CertSans { get; set; }
    public System.Security.Authentication.SslProtocols TlsProtocol { get; set; }
    public string? TlsCipherSuite { get; set; }
    public int? SmtpMaxSize { get; set; }
    public bool SupportsRequireTls { get; set; }
    public long ConnectTimeMs { get; set; }
    public long BannerTimeMs { get; set; }
    public long EhloTimeMs { get; set; }
    public long TlsTimeMs { get; set; }
    public string? Error { get; set; }
}

public class SmtpProbeService
{
    private readonly TimeSpan _timeout = TimeSpan.FromSeconds(10);
    private static int MaxRetries = 3;
    public static void SetMaxRetries(int value) => MaxRetries = value;
    private readonly ConcurrentDictionary<string, SmtpProbeResult> _probeCache = new();
    private readonly ConcurrentDictionary<string, bool> _portCache = new();
    private readonly ConcurrentDictionary<string, (bool accepted, string response)> _rcptCache = new();

    // Track keys loaded from disk cache
    private readonly ConcurrentDictionary<string, bool> _importedProbeKeys = new();
    private readonly ConcurrentDictionary<string, bool> _importedPortKeys = new();
    private readonly ConcurrentDictionary<string, bool> _importedRcptKeys = new();

    public async Task<SmtpProbeResult> ProbeSmtpAsync(string host, int port = 25)
    {
        var cacheKey = $"{host.ToLowerInvariant()}:{port}";
        if (_probeCache.TryGetValue(cacheKey, out var cached))
            return cached;

        SmtpProbeResult result = null!;
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            result = await ProbeSmtpAttemptAsync(host, port);
            if (result.Connected) break; // Got a real connection — no need to retry
        }

        _probeCache.TryAdd(cacheKey, result);
        return result;
    }

    private async Task<SmtpProbeResult> ProbeSmtpAttemptAsync(string host, int port)
    {
        var result = new SmtpProbeResult();
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var sw = Stopwatch.StartNew();
            var connectTask = client.ConnectAsync(host, port);
            if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
            {
                result.Error = "Connection timed out";
                return result;
            }
            await connectTask; // propagate exception if any
            result.ConnectTimeMs = sw.ElapsedMilliseconds;

            result.Connected = true;
            var stream = client.GetStream();
            stream.ReadTimeout = (int)_timeout.TotalMilliseconds;
            stream.WriteTimeout = (int)_timeout.TotalMilliseconds;

            // Read banner
            sw.Restart();
            result.Banner = await ReadLineAsync(stream);
            result.BannerTimeMs = sw.ElapsedMilliseconds;

            // Send EHLO
            sw.Restart();
            await WriteLineAsync(stream, "EHLO email-dns-validator");
            var ehloResponse = await ReadMultiLineAsync(stream);
            result.EhloCapabilities = ehloResponse;
            result.EhloTimeMs = sw.ElapsedMilliseconds;

            result.SupportsStartTls = ehloResponse.Any(l =>
                l.Contains("STARTTLS", StringComparison.OrdinalIgnoreCase));
            result.SupportsRequireTls = ehloResponse.Any(l =>
                l.Contains("REQUIRETLS", StringComparison.OrdinalIgnoreCase));

            // Parse SIZE from EHLO
            var sizeLine = ehloResponse.FirstOrDefault(l =>
                l.Contains("SIZE", StringComparison.OrdinalIgnoreCase));
            if (sizeLine != null)
            {
                var parts = sizeLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var p in parts)
                {
                    if (int.TryParse(p, out var size) && size > 0)
                    {
                        result.SmtpMaxSize = size;
                        break;
                    }
                }
            }

            // Try STARTTLS
            if (result.SupportsStartTls)
            {
                sw.Restart();
                await WriteLineAsync(stream, "STARTTLS");
                var tlsResponse = await ReadLineAsync(stream);

                if (tlsResponse.StartsWith("220"))
                {
                    try
                    {
                        var sslStream = new SslStream(stream, false,
                            (sender, cert, chain, errors) => true);
                        await sslStream.AuthenticateAsClientAsync(host);

                        result.TlsProtocol = sslStream.SslProtocol;
                        result.TlsCipherSuite = sslStream.NegotiatedCipherSuite.ToString();

                        if (sslStream.RemoteCertificate != null)
                        {
                            var cert2 = new X509Certificate2(sslStream.RemoteCertificate);
                            result.Certificate = cert2;
                            result.CertSubject = cert2.Subject;
                            result.CertIssuer = cert2.Issuer;
                            result.CertExpiry = cert2.NotAfter;
                            result.CertSans = GetSans(cert2);
                        }
                        result.TlsTimeMs = sw.ElapsedMilliseconds;
                    }
                    catch (Exception ex)
                    {
                        result.TlsTimeMs = sw.ElapsedMilliseconds;
                        result.Error = $"TLS negotiation failed: {ex.Message}";
                    }
                }
            }

            // QUIT
            try
            {
                await WriteLineAsync(stream, "QUIT");
            }
            catch { }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        finally
        {
            client?.Dispose();
        }

        return result;
    }

    public async Task<bool> ProbePortAsync(string host, int port)
    {
        var cacheKey = $"port:{host.ToLowerInvariant()}:{port}";
        if (_portCache.TryGetValue(cacheKey, out var cached))
            return cached;

        bool reachable = false;
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port);
                if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
                    reachable = false;
                else
                {
                    await connectTask;
                    reachable = true;
                }
            }
            catch
            {
                reachable = false;
            }
            if (reachable) break;
        }

        _portCache.TryAdd(cacheKey, reachable);
        return reachable;
    }

    public async Task<bool> ProbeRcptAsync(string host, string address)
    {
        var (accepted, _) = await ProbeRcptDetailedAsync(host, address);
        return accepted;
    }

    public async Task<(bool accepted, string response)> ProbeRcptDetailedAsync(string host, string address)
    {
        var cacheKey = $"{host.ToLowerInvariant()}|{address.ToLowerInvariant()}";
        if (_rcptCache.TryGetValue(cacheKey, out var cached))
            return cached;

        (bool accepted, string response) lastResult = default;
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            lastResult = await ProbeRcptAttemptAsync(host, address);
            // Got a server-level response (connected successfully) — no need to retry
            if (!lastResult.response.StartsWith("Error:") && !lastResult.response.StartsWith("Connection timed out"))
                break;
        }

        _rcptCache.TryAdd(cacheKey, lastResult);
        return lastResult;
    }

    private async Task<(bool accepted, string response)> ProbeRcptAttemptAsync(string host, string address)
    {
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var connectTask = client.ConnectAsync(host, 25);
            if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
                return (false, "Connection timed out");
            await connectTask;

            var stream = client.GetStream();
            stream.ReadTimeout = (int)_timeout.TotalMilliseconds;
            stream.WriteTimeout = (int)_timeout.TotalMilliseconds;

            await ReadLineAsync(stream); // banner
            await WriteLineAsync(stream, "EHLO email-dns-validator");
            await ReadMultiLineAsync(stream);

            await WriteLineAsync(stream, "MAIL FROM:<>");
            var mailResp = await ReadLineAsync(stream);
            if (!mailResp.StartsWith("250"))
                return (false, $"MAIL FROM rejected: {mailResp}");

            await WriteLineAsync(stream, $"RCPT TO:<{address}>");
            var rcptResp = await ReadLineAsync(stream);

            try { await WriteLineAsync(stream, "QUIT"); } catch { }

            var accepted = rcptResp.StartsWith("250") || rcptResp.StartsWith("251");
            return (accepted, rcptResp);
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

    private static List<string> GetSans(X509Certificate2 cert)
    {
        var sans = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.17") // SAN
            {
                var sanStr = ext.Format(true);
                // Split by both newlines and commas — Linux/OpenSSL uses comma-separated
                // format (DNS:a.com, DNS:b.com) while Windows uses newlines (DNS Name=a.com\n)
                foreach (var part in sanStr.Split(new[] { '\n', ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                        sans.Add(trimmed.Substring(9).Trim());
                    else if (trimmed.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
                        sans.Add(trimmed.Substring(4).Trim());
                }
            }
        }
        return sans;
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream)
    {
        var buffer = new byte[4096];
        var sb = new StringBuilder();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            var read = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
            if (read > 0)
                sb.Append(Encoding.ASCII.GetString(buffer, 0, read));
        }
        catch { }
        return sb.ToString().TrimEnd('\r', '\n');
    }

    private static async Task<List<string>> ReadMultiLineAsync(NetworkStream stream)
    {
        var lines = new List<string>();
        var buffer = new byte[8192];
        var sb = new StringBuilder();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            // Read potentially multiple chunks
            while (true)
            {
                var read = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                if (read == 0) break;
                sb.Append(Encoding.ASCII.GetString(buffer, 0, read));
                var text = sb.ToString();
                // Check if we have a final line (starts with "250 " not "250-")
                var allLines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                if (allLines.Any(l => l.TrimEnd('\r').Length >= 4 && l[3] == ' '))
                    break;
            }
        }
        catch { }
        foreach (var line in sb.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries))
            lines.Add(line.TrimEnd('\r'));
        return lines;
    }

    private static async Task WriteLineAsync(NetworkStream stream, string line)
    {
        var data = Encoding.ASCII.GetBytes(line + "\r\n");
        await stream.WriteAsync(data, 0, data.Length);
        await stream.FlushAsync();
    }

    // ── Cache export/import for disk persistence ─────────────────────────

    public Dictionary<string, SmtpProbeCacheEntry> ExportProbeCache()
    {
        var result = new Dictionary<string, SmtpProbeCacheEntry>();
        foreach (var kvp in _probeCache)
        {
            result[kvp.Key] = new SmtpProbeCacheEntry
            {
                Connected = kvp.Value.Connected,
                Banner = kvp.Value.Banner,
                SupportsStartTls = kvp.Value.SupportsStartTls,
                EhloCapabilities = kvp.Value.EhloCapabilities,
                CertSubject = kvp.Value.CertSubject,
                CertIssuer = kvp.Value.CertIssuer,
                CertExpiry = kvp.Value.CertExpiry,
                CertSans = kvp.Value.CertSans,
                CertRawBase64 = kvp.Value.Certificate != null ? Convert.ToBase64String(kvp.Value.Certificate.RawData) : null,
                TlsProtocol = kvp.Value.TlsProtocol.ToString(),
                TlsCipherSuite = kvp.Value.TlsCipherSuite,
                SmtpMaxSize = kvp.Value.SmtpMaxSize,
                SupportsRequireTls = kvp.Value.SupportsRequireTls,
                ConnectTimeMs = kvp.Value.ConnectTimeMs,
                BannerTimeMs = kvp.Value.BannerTimeMs,
                EhloTimeMs = kvp.Value.EhloTimeMs,
                TlsTimeMs = kvp.Value.TlsTimeMs,
                Error = kvp.Value.Error
            };
        }
        return result;
    }

    public void ImportProbeCache(Dictionary<string, SmtpProbeCacheEntry> entries)
    {
        foreach (var kvp in entries)
        {
            Enum.TryParse<System.Security.Authentication.SslProtocols>(kvp.Value.TlsProtocol, out var proto);
            X509Certificate2? cert = null;
            if (kvp.Value.CertRawBase64 != null)
            {
                try { cert = new X509Certificate2(Convert.FromBase64String(kvp.Value.CertRawBase64)); }
                catch { /* ignore corrupt cached cert data */ }
            }
            _probeCache.TryAdd(kvp.Key, new SmtpProbeResult
            {
                Connected = kvp.Value.Connected,
                Banner = kvp.Value.Banner,
                SupportsStartTls = kvp.Value.SupportsStartTls,
                EhloCapabilities = kvp.Value.EhloCapabilities,
                Certificate = cert,
                CertSubject = kvp.Value.CertSubject,
                CertIssuer = kvp.Value.CertIssuer,
                CertExpiry = kvp.Value.CertExpiry,
                CertSans = kvp.Value.CertSans,
                TlsProtocol = proto,
                TlsCipherSuite = kvp.Value.TlsCipherSuite,
                SmtpMaxSize = kvp.Value.SmtpMaxSize,
                SupportsRequireTls = kvp.Value.SupportsRequireTls,
                ConnectTimeMs = kvp.Value.ConnectTimeMs,
                BannerTimeMs = kvp.Value.BannerTimeMs,
                EhloTimeMs = kvp.Value.EhloTimeMs,
                TlsTimeMs = kvp.Value.TlsTimeMs,
                Error = kvp.Value.Error
            });
            _importedProbeKeys.TryAdd(kvp.Key, true);
        }
    }

    public Dictionary<string, bool> ExportPortCache()
        => _portCache.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

    public void ImportPortCache(Dictionary<string, bool> entries)
    {
        foreach (var kvp in entries)
        {
            _portCache.TryAdd(kvp.Key, kvp.Value);
            _importedPortKeys.TryAdd(kvp.Key, true);
        }
    }

    public Dictionary<string, RcptCacheEntry> ExportRcptCache()
    {
        var result = new Dictionary<string, RcptCacheEntry>();
        foreach (var kvp in _rcptCache)
        {
            result[kvp.Key] = new RcptCacheEntry
            {
                Accepted = kvp.Value.accepted,
                Response = kvp.Value.response
            };
        }
        return result;
    }

    public void ImportRcptCache(Dictionary<string, RcptCacheEntry> entries)
    {
        foreach (var kvp in entries)
        {
            _rcptCache.TryAdd(kvp.Key, (kvp.Value.Accepted, kvp.Value.Response));
            _importedRcptKeys.TryAdd(kvp.Key, true);
        }
    }

    // ── Recheck support ─────────────────────────────────────────────────

    public void RemoveImportedProbeEntries(Func<string, bool> predicate)
    {
        foreach (var key in _importedProbeKeys.Keys)
            if (predicate(key)) { _probeCache.TryRemove(key, out _); _importedProbeKeys.TryRemove(key, out _); }
    }

    public void RemoveImportedPortEntries(Func<string, bool> predicate)
    {
        foreach (var key in _importedPortKeys.Keys)
            if (predicate(key)) { _portCache.TryRemove(key, out _); _importedPortKeys.TryRemove(key, out _); }
    }

    public void RemoveImportedRcptEntries(Func<string, bool> predicate)
    {
        foreach (var key in _importedRcptKeys.Keys)
            if (predicate(key)) { _rcptCache.TryRemove(key, out _); _importedRcptKeys.TryRemove(key, out _); }
    }
}
