using Ednsv.Core.Checks;

namespace Ednsv.Core.Tests;

/// <summary>
/// <c>EnableHttpProbes</c> covering the validator's own prefetch, not only the checks.
///
/// <para>Every HTTP check honours the flag, but before any of them run the validator
/// warms the HTTP cache — MTA-STS policy, security.txt, and a Certificate Transparency
/// search — and it fired those three unconditionally. So <c>--no-http</c>, and the
/// <c>--restricted-network</c> preset documented as leaving "only UDP/TCP 53 to the
/// configured resolver", still sent HTTPS to the domain and to crt.sh on every run.
/// A full validation pointed at a counting listener showed it: four connections to the
/// stand-in crt.sh with HTTP disabled (the request and its retries).</para>
///
/// <para>That end-to-end form takes over thirty seconds offline — the DNS sweep's
/// speculative timeouts dominate — so the request list is tested here instead, and
/// <c>ValidateAsync</c> fires exactly what it returns.</para>
/// </summary>
public sealed class HttpPrefetchGatingTests
{
    [Fact]
    public void NoHttpMeansNoPrefetch()
    {
        Assert.Empty(DomainValidator.HttpPrefetchRequests("example.com",
            new ValidationOptions { EnableHttpProbes = false }));
    }

    [Fact]
    public void RestrictedPresetMeansNoPrefetch()
    {
        // What --restricted-network sets.
        var restricted = new ValidationOptions
        {
            EnableSmtpProbes = false, EnableHttpProbes = false, EnableDnsbl = false, EnableDirectDns = false,
        };
        Assert.Empty(DomainValidator.HttpPrefetchRequests("example.com", restricted));
    }

    [Fact]
    public void HttpEnabled_PrefetchesWhatTheChecksRead()
    {
        var requests = DomainValidator.HttpPrefetchRequests("example.com",
            new ValidationOptions { CrtShBaseUrl = "https://ct.internal.example/" });

        Assert.Equal(new (string, int?)[]
        {
            ("https://mta-sts.example.com/.well-known/mta-sts.txt", null),
            ("https://example.com/.well-known/security.txt", 1),
            ("https://ct.internal.example/?q=example.com&output=json", 1),
        }, requests);
    }
}
