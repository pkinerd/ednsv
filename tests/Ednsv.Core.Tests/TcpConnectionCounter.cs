using System.Net;
using System.Net.Sockets;

namespace Ednsv.Core.Tests;

/// <summary>
/// Counts inbound TCP connections and hangs up. Enough to answer "was the attempt made
/// at all?" for a probe whose result is a failure either way — which is the only thing
/// that separates a bypassed cache read from a skipped one.
///
/// <para>Zone transfers go to port 53/tcp, which is privileged and may already be in
/// use, so <see cref="TryStart"/> returns null instead of throwing and callers
/// self-skip.</para>
/// </summary>
public sealed class TcpConnectionCounter : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private int _connections;

    public int Connections => Volatile.Read(ref _connections);

    private TcpConnectionCounter(TcpListener listener)
    {
        _listener = listener;
        _ = Task.Run(AcceptLoopAsync);
    }

    public static TcpConnectionCounter? TryStart(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            return new TcpConnectionCounter(listener);
        }
        catch
        {
            Console.WriteLine($"SKIPPED: cannot bind 127.0.0.1:{port}");
            return null;
        }
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                using var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                Interlocked.Increment(ref _connections);
            }
            catch { return; }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* already stopped */ }
        _cts.Dispose();
    }
}
