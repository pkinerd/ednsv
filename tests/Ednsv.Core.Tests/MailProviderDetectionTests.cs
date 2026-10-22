using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The provider inference, fed signals directly. Gathering them is a handful of cached
/// lookups other checks already make; what can go wrong is the reasoning — a suffix that
/// over-matches, a weak record promoted to a headline, a gateway mistaken for a mailbox —
/// and none of that needs a network to show.
/// </summary>
public sealed class MailProviderDetectionTests
{
    private static CheckResult Run(MailProviderSignals s)
    {
        var result = new CheckResult();
        MailProviderDetectionCheck.Describe(MailProviderDetectionCheck.Assess(s), s, result);
        return result;
    }

    private static MailProviderSignals WithMx(params string[] hosts)
    {
        var s = new MailProviderSignals { SmtpProbed = true };
        foreach (var h in hosts) s.MxHosts.Add(new MxHostSignals { Host = h });
        return s;
    }

    [Fact]
    public void GatewayInFrontOfMicrosoft365_NamesBoth()
    {
        var s = WithMx("mx0a-00123401.pphosted.com", "mx0b-00123401.pphosted.com");
        s.SpfIncludes.Add("spf.protection.outlook.com");
        s.DkimCnames.Add(("selector1", "selector1-contoso-com._domainkey.contoso.onmicrosoft.com"));
        s.AutodiscoverTargets.Add("autodiscover.outlook.com");
        s.ApexTxt.Add("MS=ms12345678");

        var r = Run(s);

        Assert.Equal(CheckSeverity.Info, r.Severity);
        Assert.Equal("Receiving: Proofpoint (hosted); mailbox: likely Microsoft 365 (Exchange Online)", r.Summary);
        Assert.Contains("Microsoft 365 tenant (from DKIM CNAME): contoso.onmicrosoft.com", r.Details);
        Assert.Contains(r.Details, d => d.StartsWith("Note: with Proofpoint (hosted) in front of Microsoft 365", StringComparison.Ordinal));
        Assert.Empty(r.Warnings);
        Assert.Empty(r.Errors);
    }

    [Fact]
    public void MailboxProviderAsMx_IsReceivingAndMailbox()
    {
        var r = Run(WithMx("aspmx.l.google.com", "alt1.aspmx.l.google.com"));
        Assert.Equal("Receiving and mailbox: Google Workspace", r.Summary);
    }

    [Fact]
    public void Microsoft365DnssecMx_IsRecognised()
    {
        var s = WithMx("contoso-com.l-v1.mx.microsoft");
        s.DkimCnames.Add(("selector1", "selector1-contoso-com._domainkey.contoso.n-v1.dkim.mail.microsoft"));
        var r = Run(s);
        Assert.Equal("Receiving and mailbox: Microsoft 365 (Exchange Online)", r.Summary);
        Assert.Contains("Microsoft 365 tenant (from DKIM CNAME): contoso.onmicrosoft.com", r.Details);
    }

    [Fact]
    public void VanityMx_IsIdentifiedFromPtr()
    {
        var s = WithMx("mx1.example.com");
        s.MxHosts[0].PtrNames.Add("us-smtp-inbound-1.mimecast.com");
        var r = Run(s);
        Assert.StartsWith("Receiving: Mimecast;", r.Summary);
        Assert.Contains(r.Details, d => d.Contains("via PTR us-smtp-inbound-1.mimecast.com", StringComparison.Ordinal));
    }

    [Fact]
    public void VanityMx_BannerOutranksPtr()
    {
        // The greeting is the server describing itself; the PTR only names the IP's owner.
        var s = WithMx("mail.example.com");
        s.MxHosts[0].Banner = "220 mx0a-00123401.pphosted.com ESMTP mfa-m0123401";
        s.MxHosts[0].PtrNames.Add("mail.example.com");
        var r = Run(s);
        Assert.Contains(r.Details, d => d.Contains("Proofpoint (hosted) — filtering gateway (via SMTP banner mx0a-00123401.pphosted.com)", StringComparison.Ordinal));
    }

    [Fact]
    public void SelfHostedExchange_IsReceivingAndMailbox()
    {
        var s = WithMx("mail.example.com");
        s.MxHosts[0].Banner = "220 EXCH01.corp.example.com Microsoft ESMTP MAIL Service ready at Wed, 21 Oct 2026 10:00:00 +0000";
        var r = Run(s);
        Assert.Equal($"Receiving and mailbox: {MailProviderCatalog.ExchangeOnPremName}", r.Summary);
    }

    [Fact]
    public void ExchangeHybrid_ReportsBothCandidates()
    {
        var s = WithMx("mail.example.com");
        s.MxHosts[0].Banner = "220 mail.example.com Microsoft ESMTP MAIL Service ready";
        s.SpfIncludes.Add("spf.protection.outlook.com");
        s.DkimCnames.Add(("selector1", "selector1-example-com._domainkey.example.onmicrosoft.com"));
        var r = Run(s);
        Assert.Equal($"Receiving: {MailProviderCatalog.ExchangeOnPremName}; mailbox: likely Microsoft 365 (Exchange Online) "
            + $"(also signals for {MailProviderCatalog.ExchangeOnPremName} — hybrid or migration?)", r.Summary);
    }

    [Fact]
    public void WeakSignalAlone_StaysOutOfTheSummary()
    {
        // google-site-verification is Search Console as often as it is Workspace.
        var s = WithMx("mx1.us1.ppe-hosted.com");
        s.ApexTxt.Add("google-site-verification=abc123");
        var r = Run(s);
        Assert.Equal("Receiving: Proofpoint Essentials; mailbox: not determinable from DNS", r.Summary);
        Assert.Contains(r.Details, d => d.Contains("verification TXT google-site-verification=… [+1]", StringComparison.Ordinal));
    }

    [Fact]
    public void SingleMediumSignal_IsOnlyPossible()
    {
        var s = WithMx("eu-smtp-inbound-1.mimecast.com");
        s.SpfIncludes.Add("_spf.google.com");
        Assert.Equal("Receiving: Mimecast; mailbox: possibly Google Workspace", Run(s).Summary);
    }

    [Fact]
    public void MixedMx_NotesTheGatewayBypass()
    {
        // The classic: Proofpoint at priority 10, the tenant's own endpoint left at 20.
        var s = WithMx("mx0a-00123401.pphosted.com", "contoso-com.mail.protection.outlook.com");
        var r = Run(s);
        Assert.StartsWith("Receiving: Proofpoint (hosted) + Microsoft 365 (Exchange Online);", r.Summary);
        Assert.Contains(r.Details, d => d.StartsWith("Note: MX hosts span several providers", StringComparison.Ordinal));
    }

    [Fact]
    public void Forwarder_SaysTheMailboxIsElsewhere()
    {
        var r = Run(WithMx("route1.mx.cloudflare.net", "route2.mx.cloudflare.net"));
        Assert.Equal("Receiving: Cloudflare Email Routing; mailbox: not determinable (mail is forwarded elsewhere)", r.Summary);
    }

    [Fact]
    public void UnrecognisedMx_NamesTheMtaSoftware()
    {
        var s = WithMx("mail.example.org");
        s.MxHosts[0].Banner = "220 mail.example.org ESMTP Postfix (Debian/GNU)";
        var r = Run(s);
        Assert.Equal("Receiving: unrecognised; mailbox: not determinable from DNS", r.Summary);
        Assert.Contains("  mail.example.org: unrecognised; greeting identifies Postfix (likely self-hosted)", r.Details);
    }

    [Theory]
    [InlineData("mx0a-001.pphosted.com", "Proofpoint (hosted)")]
    [InlineData("pphosted.com", "Proofpoint (hosted)")]
    [InlineData("PPHOSTED.COM.", "Proofpoint (hosted)")]
    [InlineData("notpphosted.com", null)]
    [InlineData("pphosted.com.attacker.example", null)]
    [InlineData("inbound-smtp.us-east-1.amazonaws.com", "Amazon SES inbound (receipt rules or WorkMail)")]
    [InlineData("ec2-198-51-100-1.compute-1.amazonaws.com", null)]
    [InlineData("vps-1a2b3c4d.vps.ovh.net", null)]
    [InlineData("mx1.mail.ovh.net", "OVHcloud Mail")]
    [InlineData("ip-198-51-100-1.ip.secureserver.net", null)]
    [InlineData("example-com.mail.protection.outlook.com", "Microsoft 365 (Exchange Online)")]
    public void HostSuffixMatching(string host, string? expected)
    {
        Assert.Equal(expected, MailProviderCatalog.MatchHost(host)?.Name);
    }

    [Theory]
    [InlineData("220 mx.google.com ESMTP abc123", "mx.google.com")]
    [InlineData("220-mx0a.pphosted.com ESMTP", "mx0a.pphosted.com")]
    [InlineData("220 ESMTP ready", null)]
    [InlineData("", null)]
    public void BannerHostParsing(string banner, string? expected)
    {
        Assert.Equal(expected, MailProviderCatalog.BannerHost(banner));
    }

    [Fact]
    public async Task NoMx_IsInfoWithoutAFailedLookup()
    {
        var ctx = new CheckContext { Dns = new DnsResolverService(nameservers: null), Options = new ValidationOptions() };
        var r = Assert.Single(await new MailProviderDetectionCheck().RunAsync("example.com", ctx));
        Assert.Equal(CheckSeverity.Info, r.Severity);

        ctx.MxLookupFailed = true;
        r = Assert.Single(await new MailProviderDetectionCheck().RunAsync("example.com", ctx));
        Assert.Equal(CheckSeverity.Warning, r.Severity);
    }

    [Fact]
    public async Task NullMx_SaysTheDomainReceivesNoMail()
    {
        var ctx = new CheckContext { Dns = new DnsResolverService(nameservers: null), MxHosts = new[] { "" } };
        var r = Assert.Single(await new MailProviderDetectionCheck().RunAsync("example.com", ctx));
        Assert.Equal("Null MX — domain does not receive mail", r.Summary);
    }
}
