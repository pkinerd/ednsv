using System.Net;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// SPF macros in include:/redirect=/a:/mx: targets.
///
/// <para>Reported from a real domain whose whole record is Proofpoint's
/// <c>include:%{ir}.%{v}.%{d}.spf.has.pphosted.com</c>. The walkers queried that string
/// literally, found no SPF record, and SPF Recursive Expansion failed with a PermError
/// plus a void lookup — on a configuration that works for every real sender. The target
/// depends on the connecting IP and cannot be known without a message.</para>
/// </summary>
public sealed class SpfMacroTests
{
    private const string Proofpoint = "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all";

    // Nothing listens on loopback:53, so any query that slipped through would surface as
    // a lookup error — and the macro target must not be queried at all.
    private static CheckContext Context(string spf) => new()
    {
        Dns = new DnsResolverService(new[] { IPAddress.Loopback }),
        SpfRecord = spf,
    };

    [Theory]
    [InlineData("%{d}.spf.example.net", "example.com", "example.com.spf.example.net")]
    [InlineData("%{d2}.spf.example.net", "mail.example.com", "example.com.spf.example.net")]
    [InlineData("%{dr}.x.test", "a.b.c", "c.b.a.x.test")]
    [InlineData("%{d1r}.x.test", "a.b.c", "a.x.test")]
    [InlineData("%{o}.x.test", "inner.test", "outer.test.x.test")]
    [InlineData("_spf.%{D}", "example.com", "_spf.example.com")]
    [InlineData("plain.example.net", "example.com", "plain.example.net")]
    public void ExpandStaticMacros_ExpandsDomainMacros(string spec, string current, string expected)
    {
        var original = spec.Contains("%{o}") ? "outer.test" : current;
        Assert.Equal(expected, SpfHelpers.ExpandStaticMacros(spec, current, original));
    }

    [Theory]
    [InlineData("%{ir}.%{v}.%{d}.spf.has.pphosted.com")]
    [InlineData("%{i}._spf.example.com")]
    [InlineData("%{l}.%{d}")]
    [InlineData("%{s}.example.com")]
    [InlineData("%{h}.example.com")]
    [InlineData("broken%.example.com")]
    public void ExpandStaticMacros_ReturnsNull_WhenTargetDependsOnTheMessage(string spec)
    {
        Assert.Null(SpfHelpers.ExpandStaticMacros(spec, "example.com", "example.com"));
    }

    [Fact]
    public async Task Expansion_SenderDependentInclude_IsNotAPermError()
    {
        var r = Assert.Single(await new SpfExpansionCheck().RunAsync("example.com", Context(Proofpoint)));

        Assert.Equal(CheckSeverity.Pass, r.Severity);
        Assert.Empty(r.Errors);
        Assert.Empty(r.Warnings);
        Assert.Contains("Total DNS lookups: 1", r.Details);
        Assert.Contains("Void lookups: 0", r.Details);
        Assert.Contains(r.Details, d => d.Contains("%{ir}.%{v}.%{d}.spf.has.pphosted.com") && d.Contains("evaluation time"));
    }

    [Fact]
    public async Task LookupCount_SenderDependentInclude_CountsTheLookupButNotAVoid()
    {
        var r = Assert.Single(await new SpfLookupCountCheck().RunAsync("example.com", Context(Proofpoint)));

        Assert.Equal(CheckSeverity.Pass, r.Severity);
        Assert.Contains("DNS lookups: 1/10", r.Details);
        Assert.Contains("Void lookups: 0/2", r.Details);
    }

    [Fact]
    public async Task IncludeDepth_SenderDependentInclude_IsNotFollowed()
    {
        var r = Assert.Single(await new SpfIncludeDepthCheck().RunAsync("example.com", Context(Proofpoint)));

        Assert.Equal(CheckSeverity.Pass, r.Severity);
        Assert.Contains("Maximum nesting depth: 0", r.Details);
    }
}
