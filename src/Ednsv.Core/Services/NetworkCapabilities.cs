using System.Net;
using System.Net.Sockets;

namespace Ednsv.Core.Services;

/// <summary>
/// Host-level network capability probes, evaluated once and cached for the process
/// lifetime. Used so checks can distinguish "the target's IPv6 is broken" from
/// "the machine running this tool has no IPv6 route" — otherwise every IPv6 probe
/// on an IPv4-only host produces false-positive warnings blaming the target.
/// </summary>
public static class NetworkCapabilities
{
    private static readonly Lazy<bool> _hasIpv6 =
        new(DetectIpv6, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>True when the host has an outbound route to the public IPv6 internet.</summary>
    public static bool HasIpv6 => _hasIpv6.Value;

    private static bool DetectIpv6()
    {
        try
        {
            // "Connecting" a UDP socket sends no packets — it forces the OS to select
            // a route and source address for the destination, and throws when there is
            // no route to a public IPv6 address. This reflects real routability better
            // than merely having an address assigned, and costs no round-trip.
            using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(new IPEndPoint(IPAddress.Parse("2606:4700:4700::1111"), 53)); // Cloudflare public DNS
            return socket.LocalEndPoint is IPEndPoint local && !IPAddress.IsLoopback(local.Address);
        }
        catch
        {
            return false;
        }
    }
}
