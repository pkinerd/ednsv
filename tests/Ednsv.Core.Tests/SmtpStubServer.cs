using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Ednsv.Core.Tests;

/// <summary>
/// A minimal SMTP responder for tests that need a <i>definitive</i> answer rather than
/// a connection failure — the difference decides whether a result is cached at all.
///
/// <para>It binds an ephemeral loopback port and the test points
/// <see cref="Ednsv.Core.Services.SmtpProbeService"/> at it. Not port 25: that needs
/// privilege, and a listener on the port every other test's localhost probe also uses
/// is a process-wide resource — the suite runs classes in parallel, so a stub there
/// answers probes that were meant to be refused.</para>
///
/// <para>Each connection is answered from the next entry of the RCPT response list, so
/// a test can make the server say something different the second time round and see
/// which answer the cache ends up holding.</para>
/// </summary>
public sealed class SmtpStubServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly string[] _rcptResponses;
    private readonly CancellationTokenSource _cts = new();
    private int _connections;

    /// <summary>Connections accepted so far — the only way to tell a cache hit from a
    /// refetch when both return the same answer.</summary>
    public int Connections => Volatile.Read(ref _connections);

    /// <summary>The ephemeral port this stub is listening on.</summary>
    public int Port { get; }

    private SmtpStubServer(TcpListener listener, string[] rcptResponses)
    {
        _listener = listener;
        _rcptResponses = rcptResponses;
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(AcceptLoopAsync);
    }

    /// <summary>Starts a stub on a free loopback port.</summary>
    public static SmtpStubServer Start(params string[] rcptResponses)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return new SmtpStubServer(listener, rcptResponses);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
            catch { return; }

            var index = Interlocked.Increment(ref _connections) - 1;
            _ = Task.Run(() => ServeAsync(client, index));
        }
    }

    private async Task ServeAsync(TcpClient client, int index)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                await SendAsync(stream, "220 stub.invalid ESMTP");

                while (true)
                {
                    var line = await ReadLineAsync(stream);
                    if (line == null) return;

                    if (line.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase)
                        || line.StartsWith("HELO", StringComparison.OrdinalIgnoreCase))
                    {
                        await SendAsync(stream, "250-stub.invalid");
                        await SendAsync(stream, "250 OK");
                    }
                    else if (line.StartsWith("MAIL FROM", StringComparison.OrdinalIgnoreCase))
                    {
                        await SendAsync(stream, "250 OK");
                    }
                    else if (line.StartsWith("RCPT TO", StringComparison.OrdinalIgnoreCase))
                    {
                        var responses = _rcptResponses;
                        await SendAsync(stream, responses[Math.Min(index, responses.Length - 1)]);
                    }
                    else if (line.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase))
                    {
                        await SendAsync(stream, "221 Bye");
                        return;
                    }
                    else
                    {
                        await SendAsync(stream, "250 OK");
                    }
                }
            }
            catch { /* the probe hangs up when it is done; that is not a failure */ }
        }
    }

    private static async Task SendAsync(NetworkStream stream, string line)
    {
        var bytes = Encoding.ASCII.GetBytes(line + "\r\n");
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
    }

    private static async Task<string?> ReadLineAsync(NetworkStream stream)
    {
        var sb = new StringBuilder();
        var buffer = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read == 0) return sb.Length > 0 ? sb.ToString() : null;
            if (buffer[0] == (byte)'\n') return sb.ToString().TrimEnd('\r');
            sb.Append((char)buffer[0]);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* already stopped */ }
        _cts.Dispose();
    }
}
