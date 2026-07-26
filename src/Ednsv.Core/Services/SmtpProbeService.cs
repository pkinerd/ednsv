using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Memory;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ednsv.Core.Services;

public class SmtpProbeResult
{
    public bool Connected { get; set; }
    public string Banner { get; set; } = "";
    public bool SupportsStartTls { get; set; }
    public List<string> EhloCapabilities { get; set; } = new();
    public X509Certificate2? Certificate { get; set; }
    public List<X509Certificate2>? CertChainIntermediates { get; set; }
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
    private readonly TimeSpan _timeout;
    private readonly TimeSpan _portTimeout;
    private const int PortMaxRetries = 2;
    private static volatile int MaxRetries = 3;
    public static void SetMaxRetries(int value) => MaxRetries = value;
    private readonly ProbeCache<SmtpProbeResult> _probeCache;
    private readonly ProbeCacheValue<bool> _portCache;

    /// <param name="timeoutSeconds">SMTP command/connect timeout. Default 10s.</param>
    /// <param name="portTimeoutSeconds">TCP port-open probe timeout. Default 5s.</param>
    /// <param name="persistToDisk">False when no cache directory is configured, so
    /// results are never queued for a write that will not happen.</param>
    /// <param name="warmSharedCache">False when nothing will republish this cache into
    /// the shared tier — see <see cref="ProbeCache{T}"/>.</param>
    /// <param name="smtpPort">Where the RCPT and relay probes open their mail
    /// transaction. Always 25 in production — it is the port an MX listens on, and
    /// nothing configures it. It exists so a test can point those probes at a stub on
    /// an ephemeral port: binding 25 needs privilege, and a listener on a well-known
    /// port is a process-wide resource that other tests probing localhost would then
    /// reach by accident.</param>
    public SmtpProbeService(TimeSpan? cacheTtl = null, double timeoutSeconds = 10, double portTimeoutSeconds = 5,
        RedisConnection? redis = null, bool persistToDisk = true, bool warmSharedCache = true,
        int smtpPort = 25)
    {
        _timeout = TimeSpan.FromSeconds(timeoutSeconds);
        _portTimeout = TimeSpan.FromSeconds(portTimeoutSeconds);
        _smtpPort = smtpPort;
        ProbeCacheL2<SmtpProbeResult>? probeL2 =
            redis != null && redis.Enabled
                ? new ProbeCacheL2<SmtpProbeResult>(redis, "smtp", cacheTtl,
                    r => JsonSerializer.Serialize(ToCacheEntry(r)),
                    json =>
                    {
                        var e = JsonSerializer.Deserialize<SmtpProbeCacheEntry>(json);
                        return e == null ? null : FromCacheEntry(e);
                    })
                : null;
        _cacheTtl = cacheTtl;
        _probeCache = new ProbeCache<SmtpProbeResult>(cacheTtl, probeL2, persistToDisk, warmSharedCache);
        _portCache = new ProbeCacheValue<bool>(cacheTtl, persistToDisk);
        _rcptBag = new WriteBag<(bool accepted, string response)>(cacheTtl, persistToDisk);
        _relayBag = new WriteBag<(bool isRelay, string description)>(cacheTtl, persistToDisk);
        _rcptCache = new ExpiringMap<string, (bool accepted, string response)>(cacheTtl);
        _relayCache = new ExpiringMap<string, (bool isRelay, string description)>(cacheTtl);
    }
    private readonly TimeSpan? _cacheTtl;
    private readonly int _smtpPort;
    // Not a ProbeCache: no L2, no in-flight dedup, and their own write queues. They
    // do expire, though — see ExpiringMap.
    private readonly ExpiringMap<string, (bool accepted, string response)> _rcptCache;
    private readonly ExpiringMap<string, (bool isRelay, string description)> _relayCache;

    // Plain dictionaries rather than ProbeCaches, so they carry their own write
    // queues — see WriteBag.
    private readonly WriteBag<(bool accepted, string response)> _rcptBag;
    private readonly WriteBag<(bool isRelay, string description)> _relayBag;

    // Counters for diagnostics
    private int _probesStarted;
    private int _probesCompleted;
    private int _portsStarted;
    private int _portsCompleted;
    public int ProbesStarted => _probesStarted;
    public int ProbesCompleted => _probesCompleted;
    public int PortsStarted => _portsStarted;
    public int PortsCompleted => _portsCompleted;

    /// <summary>Resets per-validation diagnostic counters.</summary>
    public void ResetCounters()
    {
        Interlocked.Exchange(ref _probesStarted, 0);
        Interlocked.Exchange(ref _probesCompleted, 0);
        Interlocked.Exchange(ref _portsStarted, 0);
        Interlocked.Exchange(ref _portsCompleted, 0);
    }

    /// <summary>
    /// Optional trace callback. Backed by <see cref="TraceContext.Sink"/>
    /// (AsyncLocal) so concurrent validations don't share a sink.
    /// </summary>
    public Action<string>? Trace
    {
        get => TraceContext.Sink;
        set => TraceContext.Sink = value;
    }

    public async Task<SmtpProbeResult> ProbeSmtpAsync(string host, int port = 25)
    {
        var cacheKey = $"smtp:{host.ToLowerInvariant()}:{port}";
        return await _probeCache.GetOrCreateAsync(cacheKey, async () =>
        {
            Interlocked.Increment(ref _probesStarted);
            Trace?.Invoke($"[SMTP] PROBE START {host}:{port}");
            var sw = Trace != null ? Stopwatch.StartNew() : null;
            SmtpProbeResult result = null!;
            SmtpProbeResult? bestResult = null;
            for (int attempt = 0; attempt < MaxRetries; attempt++)
            {
                result = await ProbeSmtpAttemptAsync(host, port);
                // Track the best result across retries — prefer TLS-successful probes
                if (bestResult == null || (result.Connected && result.SupportsStartTls && result.CertSubject != null))
                    bestResult = result;
                // Stop if we got a complete successful probe
                if (result.Connected && result.Error == null && (!result.SupportsStartTls || result.CertSubject != null))
                    break;
                Trace?.Invoke($"[SMTP] PROBE RETRY {host}:{port} attempt {attempt + 1}/{MaxRetries} ({result.Error ?? (result.Connected ? "TLS incomplete" : "not connected")})");
            }
            // Use the best result (prefer one with TLS cert if any attempt succeeded)
            result = bestResult!;
            Interlocked.Increment(ref _probesCompleted);
            if (Trace != null && sw != null)
                Trace($"[SMTP] PROBE DONE {host}:{port}: {sw.ElapsedMilliseconds}ms connected={result.Connected} tls={result.SupportsStartTls} connect={result.ConnectTimeMs}ms banner={result.BannerTimeMs}ms ehlo={result.EhloTimeMs}ms tls={result.TlsTimeMs}ms");
            return result;
        }, RecheckHelper.CacheDep.Smtp,
        // Cache successful probes and definitive failures (connection refused).
        // Only skip caching when all attempts timed out (transient).
        shouldPersist: result => result.Connected || result.Error != "Connection timed out");
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
                        List<X509Certificate2>? capturedIntermediates = null;
                        var sslStream = new SslStream(stream, false,
                            (sender, cert, chain, errors) =>
                            {
                                if (chain != null && cert != null)
                                {
                                    // ChainPolicy.ExtraStore holds the intermediate certificates the
                                    // peer sent in the TLS handshake (.NET populates it from
                                    // SSL_get_peer_cert_chain on Linux / the equivalent on Windows
                                    // before invoking this callback). chain.ChainElements is the
                                    // *built* chain and may include intermediates pulled from the
                                    // local OS trust store, so it is not a reliable indicator of
                                    // what the server actually served.
                                    using var leafCopy = new X509Certificate2(cert);
                                    var leafThumbprint = leafCopy.Thumbprint;
                                    capturedIntermediates = chain.ChainPolicy.ExtraStore
                                        .Cast<X509Certificate2>()
                                        .Where(c => c.Thumbprint != leafThumbprint &&
                                                    !string.Equals(c.Subject, c.Issuer, StringComparison.OrdinalIgnoreCase))
                                        .Select(c => new X509Certificate2(c.RawData))
                                        .ToList();
                                }
                                return true;
                            });
                        var authTask = sslStream.AuthenticateAsClientAsync(host);
                        if (await Task.WhenAny(authTask, Task.Delay(_timeout)) != authTask)
                        {
                            result.Error = "TLS handshake timed out";
                            result.TlsTimeMs = sw.ElapsedMilliseconds;
                            return result; // Allow retry — Connected is true but TLS failed
                        }
                        await authTask;

                        result.TlsProtocol = sslStream.SslProtocol;
                        result.TlsCipherSuite = sslStream.NegotiatedCipherSuite.ToString();

                        if (sslStream.RemoteCertificate != null)
                        {
                            var cert2 = new X509Certificate2(sslStream.RemoteCertificate);
                            result.Certificate = cert2;
                            result.CertChainIntermediates = capturedIntermediates;
                            result.CertSubject = cert2.Subject;
                            result.CertIssuer = cert2.Issuer;
                            result.CertExpiry = cert2.NotAfter;
                            result.CertSans = GetSans(cert2);
                        }
                        else
                        {
                            result.Error = "TLS succeeded but server did not provide a certificate";
                            result.TlsTimeMs = sw.ElapsedMilliseconds;
                            return result; // Allow retry
                        }
                        result.TlsTimeMs = sw.ElapsedMilliseconds;
                    }
                    catch (Exception ex)
                    {
                        result.TlsTimeMs = sw.ElapsedMilliseconds;
                        result.Error = $"TLS negotiation failed: {ex.Message}";
                        return result; // Allow retry
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
        bool allTimedOut = true;
        return await _portCache.GetOrCreateAsync(cacheKey, async () =>
        {
            Interlocked.Increment(ref _portsStarted);
            Trace?.Invoke($"[PORT] PROBE START {host}:{port}");
            var portSw = Trace != null ? Stopwatch.StartNew() : null;
            bool reachable = false;
            for (int attempt = 0; attempt < PortMaxRetries; attempt++)
            {
                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(host, port);
                    if (await Task.WhenAny(connectTask, Task.Delay(_portTimeout)) != connectTask)
                        reachable = false; // timeout — transient
                    else
                    {
                        await connectTask;
                        reachable = true;
                        allTimedOut = false;
                    }
                }
                catch
                {
                    reachable = false;
                    allTimedOut = false; // connection refused — definitive
                }
                if (reachable) break;
            }
            Interlocked.Increment(ref _portsCompleted);
            if (Trace != null && portSw != null)
                Trace($"[PORT] PROBE DONE {host}:{port}: {portSw.ElapsedMilliseconds}ms open={reachable}");
            return reachable;
        }, RecheckHelper.CacheDep.Port,
        // Cache open ports and definitive refusals. Only skip caching
        // when all attempts timed out (transient network issue).
        shouldPersist: result => result || !allTimedOut);
    }

    public async Task<bool> ProbeRcptAsync(string host, string address)
    {
        var (accepted, _) = await ProbeRcptDetailedAsync(host, address);
        return accepted;
    }

    public async Task<(bool accepted, string response)> ProbeRcptDetailedAsync(string host, string address)
    {
        var cacheKey = $"{host.ToLowerInvariant()}|{address.ToLowerInvariant()}";
        // CacheDep.Rcpt is what the Postmaster and Abuse categories declare, and this
        // is the only cache it names.
        if (_rcptCache.TryGetValue(cacheKey, out var cached, RecheckHelper.CacheDep.Rcpt))
            return cached;

        (bool accepted, string response) lastResult = (false, "");
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            lastResult = await ProbeRcptAttemptAsync(host, address);
            // Got a server-level response (connected successfully) — no need to retry
            if (!lastResult.response.StartsWith("Error:") && !lastResult.response.StartsWith("Connection timed out"))
                break;
        }

        // Only cache definitive server responses, not transient failures. Written
        // rather than added-if-absent: on a recheck the read above was bypassed on
        // purpose, and an add-if-absent would leave the entry that bypass exists to
        // replace — refetching every time and discarding the answer.
        if (!lastResult.response.StartsWith("Error:") && !lastResult.response.StartsWith("Connection timed out"))
        {
            _rcptCache.Set(cacheKey, lastResult);
            _rcptBag.Add(cacheKey, lastResult);
        }
        return lastResult;
    }

    private async Task<(bool accepted, string response)> ProbeRcptAttemptAsync(string host, string address)
    {
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var connectTask = client.ConnectAsync(host, _smtpPort);
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

    public async Task<(bool isRelay, string description)> TestRelayAsync(string mxHost, string domain)
    {
        var cacheKey = $"relay:{mxHost.ToLowerInvariant()}|{domain.ToLowerInvariant()}";
        // CacheDep.Smtp: the open-relay check reports under CheckCategory.SMTP, which
        // declares Smtp, and a relay verdict is an SMTP conversation with the MX. The
        // handshake cache was already refreshed by that flag; this one was not.
        if (_relayCache.TryGetValue(cacheKey, out var cached, RecheckHelper.CacheDep.Smtp))
            return cached;

        var result = await PerformRelayTestAsync(mxHost, domain);
        // Only cache definitive results, not transient failures. Written rather than
        // added-if-absent — see ProbeRcptDetailedAsync.
        if (!result.description.StartsWith("Error:") && !result.description.StartsWith("Connection timed out"))
        {
            _relayCache.Set(cacheKey, result);
            _relayBag.Add(cacheKey, result);
        }
        return result;
    }

    private async Task<(bool isRelay, string description)> PerformRelayTestAsync(string mxHost, string domain)
    {
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var connectTask = client.ConnectAsync(mxHost, _smtpPort);
            if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
                return (false, "Connection timed out");
            await connectTask;

            var stream = client.GetStream();
            stream.ReadTimeout = (int)_timeout.TotalMilliseconds;
            stream.WriteTimeout = (int)_timeout.TotalMilliseconds;

            await ReadLineAsync(stream); // banner
            await WriteLineAsync(stream, "EHLO ednsv-relay-test.invalid");
            await ReadMultiLineAsync(stream);

            // Use a clearly non-existent external sender and recipient
            await WriteLineAsync(stream, "MAIL FROM:<relay-test@ednsv-probe.invalid>");
            var mailResp = await ReadLineAsync(stream);
            if (!mailResp.StartsWith("250"))
            {
                await WriteLineAsync(stream, "QUIT");
                return (false, $"MAIL FROM rejected ({mailResp.Substring(0, Math.Min(50, mailResp.Length))}) — not an open relay");
            }

            // Try to relay to an external domain (not the target domain)
            await WriteLineAsync(stream, "RCPT TO:<relay-test@ednsv-probe.invalid>");
            var rcptResp = await ReadLineAsync(stream);

            await WriteLineAsync(stream, "QUIT");

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

    /// <summary>Evicts all cached SMTP probe/port/RCPT/relay results.</summary>
    // ── Cache export/import for disk persistence ─────────────────────────

    /// <summary>Convert a probe result to its serialisable DTO (certs → base64).
    /// Shared by disk persistence and the Redis L2.</summary>
    internal static SmtpProbeCacheEntry ToCacheEntry(SmtpProbeResult r) => new()
    {
        Connected = r.Connected, Banner = r.Banner,
        SupportsStartTls = r.SupportsStartTls, EhloCapabilities = r.EhloCapabilities,
        CertSubject = r.CertSubject, CertIssuer = r.CertIssuer,
        CertExpiry = r.CertExpiry, CertSans = r.CertSans,
        CertRawBase64 = r.Certificate != null ? Convert.ToBase64String(r.Certificate.RawData) : null,
        CertChainIntermediatesBase64 = r.CertChainIntermediates?.Select(c => Convert.ToBase64String(c.RawData)).ToList(),
        TlsProtocol = r.TlsProtocol.ToString(), TlsCipherSuite = r.TlsCipherSuite,
        SmtpMaxSize = r.SmtpMaxSize, SupportsRequireTls = r.SupportsRequireTls,
        ConnectTimeMs = r.ConnectTimeMs, BannerTimeMs = r.BannerTimeMs,
        EhloTimeMs = r.EhloTimeMs, TlsTimeMs = r.TlsTimeMs,
        Error = r.Error
    };

    /// <summary>Rebuild a probe result from its serialisable DTO (base64 → certs).
    /// Shared by disk persistence and the Redis L2. Corrupt cert data is ignored.</summary>
    internal static SmtpProbeResult FromCacheEntry(SmtpProbeCacheEntry e)
    {
        Enum.TryParse<System.Security.Authentication.SslProtocols>(e.TlsProtocol, out var proto);
        X509Certificate2? cert = null;
        if (e.CertRawBase64 != null)
        {
            try { cert = new X509Certificate2(Convert.FromBase64String(e.CertRawBase64)); }
            catch { /* ignore corrupt cached cert data */ }
        }
        List<X509Certificate2>? intermediates = null;
        if (e.CertChainIntermediatesBase64?.Count > 0)
        {
            intermediates = new List<X509Certificate2>();
            foreach (var b64 in e.CertChainIntermediatesBase64)
            {
                try { intermediates.Add(new X509Certificate2(Convert.FromBase64String(b64))); }
                catch { /* ignore corrupt cached cert data */ }
            }
        }
        return new SmtpProbeResult
        {
            Connected = e.Connected, Banner = e.Banner,
            SupportsStartTls = e.SupportsStartTls, EhloCapabilities = e.EhloCapabilities,
            Certificate = cert, CertChainIntermediates = intermediates,
            CertSubject = e.CertSubject, CertIssuer = e.CertIssuer,
            CertExpiry = e.CertExpiry, CertSans = e.CertSans,
            TlsProtocol = proto, TlsCipherSuite = e.TlsCipherSuite,
            SmtpMaxSize = e.SmtpMaxSize, SupportsRequireTls = e.SupportsRequireTls,
            ConnectTimeMs = e.ConnectTimeMs, BannerTimeMs = e.BannerTimeMs,
            EhloTimeMs = e.EhloTimeMs, TlsTimeMs = e.TlsTimeMs,
            Error = e.Error
        };
    }

    /// <summary>Import one record from a cache file — see
    /// <see cref="DnsResolverService.TryImportRecord"/>.</summary>
    public bool TryImportRecord(string type, string key, JsonNode? value, DateTime expiresUtc)
    {
        if (value == null) return false;
        try
        {
            switch (type)
            {
                case CacheTypes.Smtp:
                {
                    var entry = value.Deserialize<SmtpProbeCacheEntry>();
                    if (entry != null) _probeCache.Import(key, FromCacheEntry(entry), expiresUtc);
                    return true;
                }
                case CacheTypes.Port:
                    _portCache.Import(key, value.Deserialize<bool>(), expiresUtc);
                    return true;
                case CacheTypes.Rcpt:
                {
                    var entry = value.Deserialize<RcptCacheEntry>();
                    if (entry != null) _rcptCache.TryAdd(key, (entry.Accepted, entry.Response), expiresUtc);
                    return true;
                }
                case CacheTypes.Relay:
                {
                    var entry = value.Deserialize<RelayCacheEntry>();
                    if (entry != null) _relayCache.TryAdd(key, (entry.IsRelay, entry.Description), expiresUtc);
                    return true;
                }
                default:
                    return false;
            }
        }
        catch
        {
            return true;
        }
    }

    // ── Shared-cache recovery ────────────────────────────────────────────

    /// <summary>Republish cached SMTP probes into the shared L2. The port cache has no
    /// L2, so there is nothing to republish for it.</summary>
    public int WarmSharedCache() => _probeCache.WarmSharedCache();

    /// <summary>See <see cref="ProbeCache{T}.PruneSharedCacheIndex"/>.</summary>
    public void PruneSharedCacheIndex() => _probeCache.PruneSharedCacheIndex();

    /// <summary>See <see cref="ProbeCache{T}.SharedCacheIndexCount"/>.</summary>
    public int SharedCacheIndexCount => _probeCache.SharedCacheIndexCount;

    // The two maps that are not ProbeCaches — see DnsResolverService for why these are
    // counted at all, and ExpiringMap.Count for why an expired entry can still show up.
    public int RcptCacheCount => _rcptCache.Count;
    public int RelayCacheCount => _relayCache.Count;

    // ── Flush sources ────────────────────────────────────────────────────

    /// <summary>Everything this prober has fetched and not yet written out.</summary>
    public IEnumerable<PendingWrites> CollectPendingWrites()
    {
        yield return _probeCache.CollectPending(CacheTypes.Smtp,
            r => JsonSerializer.SerializeToNode(ToCacheEntry(r)));
        yield return _portCache.CollectPending(CacheTypes.Port,
            open => JsonSerializer.SerializeToNode(open));
        yield return _rcptBag.Collect(CacheTypes.Rcpt,
            v => JsonSerializer.SerializeToNode(new RcptCacheEntry { Accepted = v.accepted, Response = v.response }));
        yield return _relayBag.Collect(CacheTypes.Relay,
            v => JsonSerializer.SerializeToNode(new RelayCacheEntry { IsRelay = v.isRelay, Description = v.description }));
    }

}
