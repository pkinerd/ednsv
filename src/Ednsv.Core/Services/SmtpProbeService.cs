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
    public string? Error { get; set; }
}

public class SmtpProbeService
{
    private readonly TimeSpan _timeout = TimeSpan.FromSeconds(10);

    public async Task<SmtpProbeResult> ProbeSmtpAsync(string host, int port = 25)
    {
        var result = new SmtpProbeResult();
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
            {
                result.Error = "Connection timed out";
                return result;
            }
            await connectTask; // propagate exception if any

            result.Connected = true;
            var stream = client.GetStream();
            stream.ReadTimeout = (int)_timeout.TotalMilliseconds;
            stream.WriteTimeout = (int)_timeout.TotalMilliseconds;

            // Read banner
            result.Banner = await ReadLineAsync(stream);

            // Send EHLO
            await WriteLineAsync(stream, "EHLO ednsv.check");
            var ehloResponse = await ReadMultiLineAsync(stream);
            result.EhloCapabilities = ehloResponse;

            result.SupportsStartTls = ehloResponse.Any(l =>
                l.Contains("STARTTLS", StringComparison.OrdinalIgnoreCase));

            // Try STARTTLS
            if (result.SupportsStartTls)
            {
                await WriteLineAsync(stream, "STARTTLS");
                var tlsResponse = await ReadLineAsync(stream);

                if (tlsResponse.StartsWith("220"))
                {
                    try
                    {
                        var sslStream = new SslStream(stream, false,
                            (sender, cert, chain, errors) => true);
                        await sslStream.AuthenticateAsClientAsync(host);

                        if (sslStream.RemoteCertificate != null)
                        {
                            var cert2 = new X509Certificate2(sslStream.RemoteCertificate);
                            result.Certificate = cert2;
                            result.CertSubject = cert2.Subject;
                            result.CertIssuer = cert2.Issuer;
                            result.CertExpiry = cert2.NotAfter;
                            result.CertSans = GetSans(cert2);
                        }
                    }
                    catch (Exception ex)
                    {
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
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
                return false;
            await connectTask;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> ProbeRcptAsync(string host, string address)
    {
        TcpClient? client = null;
        try
        {
            client = new TcpClient();
            var connectTask = client.ConnectAsync(host, 25);
            if (await Task.WhenAny(connectTask, Task.Delay(_timeout)) != connectTask)
                return false;
            await connectTask;

            var stream = client.GetStream();
            stream.ReadTimeout = (int)_timeout.TotalMilliseconds;
            stream.WriteTimeout = (int)_timeout.TotalMilliseconds;

            await ReadLineAsync(stream); // banner
            await WriteLineAsync(stream, "EHLO ednsv.check");
            await ReadMultiLineAsync(stream);

            await WriteLineAsync(stream, "MAIL FROM:<>");
            var mailResp = await ReadLineAsync(stream);
            if (!mailResp.StartsWith("250")) return false;

            await WriteLineAsync(stream, $"RCPT TO:<{address}>");
            var rcptResp = await ReadLineAsync(stream);

            await WriteLineAsync(stream, "QUIT");

            return rcptResp.StartsWith("250") || rcptResp.StartsWith("251");
        }
        catch
        {
            return false;
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
                foreach (var line in sanStr.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                        sans.Add(trimmed.Substring(9));
                    else if (trimmed.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase))
                        sans.Add(trimmed.Substring(4));
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
}
