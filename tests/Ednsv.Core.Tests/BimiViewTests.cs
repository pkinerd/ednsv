using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The structured BIMI view the web UI draws its logo preview and checklist from.
///
/// <para>Runs the real <see cref="BimiCheck"/> with no network: the BIMI record goes into
/// the DNS cache and the logo and certificate into the HTTP cache, through the same import
/// paths the disk and Redis tiers use. The certificate is minted here with a logotype
/// extension shaped the way the check parses it, so the hash comparison is real.</para>
/// </summary>
public sealed class BimiViewTests
{
    private const string Domain = "example.com";
    private const string LogoUrl = "https://bimi.example.net/logo.svg";
    private const string CertUrl = "https://bimi.example.net/vmc.pem";

    private const string Svg =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.2\" baseProfile=\"tiny-ps\" viewBox=\"0 0 100 100\">" +
        "<title>Example Corp</title><circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"#c00\"/></svg>";

    private static DateTime Later => DateTime.UtcNow.AddMinutes(10);

    private static CheckContext Context(string record, string? dmarc = "v=DMARC1; p=reject",
        string? pem = null, string svg = Svg, string selector = "default")
    {
        var dns = new DnsResolverService(new[] { IPAddress.Loopback });
        var entry = new DnsCacheEntry
        {
            Answers =
            {
                new DnsCacheRecord { Name = $"{selector}._bimi.{Domain}", Type = "TXT", Ttl = 300, Data = { ["Values"] = record } },
            },
        };
        Assert.True(dns.TryImportRecord(CacheTypes.Dns, $"q:{selector}._bimi.{Domain}:TXT", JsonSerializer.SerializeToNode(entry), Later));

        var http = new HttpProbeService();
        Assert.True(http.TryImportRecord(CacheTypes.HttpGetHeaders, LogoUrl, JsonSerializer.SerializeToNode(
            new HttpGetWithHeadersCacheEntry { Success = true, Content = svg, StatusCode = 200, ContentType = "image/svg+xml" }), Later));
        if (pem != null)
            Assert.True(http.TryImportRecord(CacheTypes.HttpGet, CertUrl, JsonSerializer.SerializeToNode(
                new HttpGetCacheEntry { Success = true, Content = pem, StatusCode = 200 }), Later));

        return new CheckContext { Dns = dns, Http = http, DmarcRecord = dmarc, Options = new ValidationOptions() };
    }

    /// <summary>A self-signed mark certificate: organisation, mark type and trademark
    /// attributes in the subject, and an RFC 3709 logotype extension carrying the SHA-256
    /// of <paramref name="logo"/>.</summary>
    private static string MarkCertificatePem(string logo, string markType = "Registered Mark")
    {
        var name = new X500DistinguishedNameBuilder();
        name.AddCommonName(Domain);
        name.AddOrganizationName("Example Corp");
        name.Add("1.3.6.1.4.1.53087.1.13", markType, UniversalTagNumber.UTF8String);
        name.Add("1.3.6.1.4.1.53087.1.2", "USPTO", UniversalTagNumber.UTF8String);
        name.Add("1.3.6.1.4.1.53087.1.4", "1234567", UniversalTagNumber.UTF8String);

        using var key = RSA.Create(2048);
        var req = new CertificateRequest(name.Build(), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.12", LogotypeExtension(logo), critical: false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return cert.ExportCertificatePem();
    }

    private static byte[] LogotypeExtension(string logo)
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())                                                         // LogotypeExtn
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true)))   // subjectLogo
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))   // direct
        using (w.PushSequence())                                                         // image SEQUENCE OF
        using (w.PushSequence())                                                         // LogotypeImage
        using (w.PushSequence())                                                         // LogotypeDetails
        {
            w.WriteCharacterString(UniversalTagNumber.IA5String, "image/svg+xml");
            using (w.PushSequence())                                                     // logotypeHash
            using (w.PushSequence())                                                     // HashAlgAndValue
            {
                using (w.PushSequence()) w.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1");
                w.WriteOctetString(SHA256.HashData(Encoding.UTF8.GetBytes(logo)));
            }
            using (w.PushSequence())                                                     // logotypeURI
                w.WriteCharacterString(UniversalTagNumber.IA5String, "data:image/svg+xml;base64,");
        }
        return w.Encode();
    }

    private static JsonObject Run(CheckContext ctx, out CheckResult result)
    {
        result = Assert.Single(new BimiCheck().RunAsync(Domain, ctx).GetAwaiter().GetResult());
        Assert.NotNull(result.Data);
        return result.Data!;
    }

    private static JsonObject Item(JsonObject view, string label) =>
        view["checklist"]!.AsArray().Select(n => n!.AsObject()).Single(i => (string?)i["label"] == label);

    [Fact]
    public void FullBimi_CarriesTheLogoCertificateAndAPassingChecklist()
    {
        var ctx = Context($"v=BIMI1; l={LogoUrl}; a={CertUrl}; avp=brand", pem: MarkCertificatePem(Svg));
        var view = Run(ctx, out var r);

        Assert.Equal(CheckSeverity.Pass, r.Severity);
        Assert.Equal("Example Corp", (string?)view["displayName"]);
        Assert.Equal("data:image/svg+xml;base64," + Convert.ToBase64String(Encoding.UTF8.GetBytes(Svg)),
            (string?)view["logo"]!["dataUri"]);
        Assert.Equal("Example Corp", (string?)view["logo"]!["title"]);

        var cert = view["certificate"]!;
        Assert.Equal("VMC", (string?)cert["type"]);
        Assert.Equal("Registered Mark", (string?)cert["markType"]);
        Assert.Equal("1234567", (string?)cert["trademarkRegistration"]);
        Assert.True((bool?)cert["logoHashMatches"]);

        foreach (var label in new[] { "BIMI record", "Logo URL", "SVG Tiny PS", "Mark certificate", "Logo matches certificate", "Policy (p=)" })
            Assert.Equal(BimiCheck.View.Pass, (string?)Item(view, label)["status"]);
    }

    [Fact]
    public void AvpAndLps_AreRecognisedTags_NotTypos()
    {
        // Both are in the current BIMI draft. They were reported as "Unknown tag … possible typo?".
        var view = Run(Context($"v=BIMI1; l={LogoUrl}; avp=personal; lps=news,offers"), out var r);

        Assert.DoesNotContain(r.Details, d => d.StartsWith("Unknown tag", StringComparison.Ordinal));
        Assert.Equal(BimiCheck.View.Pass, (string?)Item(view, "avp= (avatar preference)")["status"]);
        Assert.Equal("news,offers", (string?)Item(view, "lps= (local-part selectors)")["value"]);
    }

    [Fact]
    public void InvalidAvp_Warns()
    {
        var view = Run(Context($"v=BIMI1; l={LogoUrl}; avp=sometimes"), out var r);

        Assert.Equal(BimiCheck.View.Warn, (string?)Item(view, "avp= (avatar preference)")["status"]);
        Assert.Contains(r.Warnings, w => w.Contains("avp=sometimes", StringComparison.Ordinal));
    }

    [Fact]
    public void LogoDifferentFromTheCertifiedOne_FailsTheMatch()
    {
        var ctx = Context($"v=BIMI1; l={LogoUrl}; a={CertUrl}", pem: MarkCertificatePem("<svg>something else</svg>"));
        var view = Run(ctx, out _);

        Assert.False((bool?)view["certificate"]!["logoHashMatches"]);
        Assert.Equal(BimiCheck.View.Fail, (string?)Item(view, "Logo matches certificate")["status"]);
    }

    [Fact]
    public void PriorUseMark_IsACommonMarkCertificate()
    {
        var ctx = Context($"v=BIMI1; l={LogoUrl}; a={CertUrl}", pem: MarkCertificatePem(Svg, "Prior Use Mark"));
        Assert.Equal("CMC", (string?)Run(ctx, out _)["certificate"]!["type"]);
    }

    [Fact]
    public void SelfAsserted_AndDmarcNotEnforced_AreSaidPlainly()
    {
        var view = Run(Context($"v=BIMI1; l={LogoUrl}", dmarc: "v=DMARC1; p=none"), out var r);

        Assert.Equal(CheckSeverity.Warning, r.Severity);
        Assert.Equal("none — self-asserted", (string?)Item(view, "Mark certificate")["value"]);
        Assert.Equal(BimiCheck.View.Fail, (string?)Item(view, "Policy (p=)")["status"]);
    }

    [Fact]
    public void NonDefaultSelector_ChecksThatSelectorsRecord()
    {
        var ctx = Context($"v=BIMI1; l={LogoUrl}", selector: "brand2");
        ctx.Options.BimiSelector = "brand2";
        var view = Run(ctx, out var r);

        Assert.Equal("brand2", (string?)view["selector"]);
        Assert.Equal($"brand2._bimi.{Domain}", (string?)view["recordName"]);
        Assert.EndsWith("(selector 'brand2')", r.Summary);
    }

    [Fact]
    public void NonDefaultSelector_WithNoRecord_SaysWhichNameWasMissing()
    {
        var ctx = Context($"v=BIMI1; l={LogoUrl}");   // published under default only
        // The zone's answer for the other selector: NXDOMAIN, seeded rather than queried.
        Assert.True(ctx.Dns.TryImportRecord(CacheTypes.Dns, $"q:other._bimi.{Domain}:TXT",
            JsonSerializer.SerializeToNode(new DnsCacheEntry { ResponseCode = 3, HasError = true }), Later));
        ctx.Options.BimiSelector = "other";
        var r = Assert.Single(new BimiCheck().RunAsync(Domain, ctx).GetAwaiter().GetResult());

        Assert.Equal($"No BIMI record for selector 'other' (other._bimi.{Domain})", r.Summary);
    }

    [Theory]
    [InlineData("../etc")]
    [InlineData("a%b")]
    [InlineData("x/y")]
    [InlineData("a..b")]
    public void HostileSelectors_AreRefusedNotQueried(string selector)
    {
        // It is spliced into a lookup name, so it must be a DNS name and nothing else.
        Assert.False(BimiCheck.IsValidSelector(selector));

        var ctx = Context($"v=BIMI1; l={LogoUrl}");
        ctx.Options.BimiSelector = selector;
        var r = Assert.Single(new BimiCheck().RunAsync(Domain, ctx).GetAwaiter().GetResult());
        Assert.StartsWith("Invalid BIMI selector", r.Summary);
    }

    private static void SeedBimi(CheckContext ctx, string selector, string record) =>
        Assert.True(ctx.Dns.TryImportRecord(CacheTypes.Dns, $"q:{selector}._bimi.{Domain}:TXT", JsonSerializer.SerializeToNode(
            new DnsCacheEntry { Answers = { new DnsCacheRecord { Name = $"{selector}._bimi.{Domain}", Type = "TXT", Ttl = 300, Data = { ["Values"] = record } } } }),
            Later));

    private static List<string> Names(ValidationOptions o) => BimiCheck.Selectors(Domain, o).Select(s => s.Name).ToList();

    [Fact]
    public void SelectorPrecedence_FollowsDkim_PerDomainThenRequestThenDefaultsThenDefault()
    {
        var o = new ValidationOptions();
        Assert.Equal(new[] { "default" }, Names(o));

        o.DefaultBimiSelectors = new() { "default", "news" };
        Assert.Equal(new[] { "default", "news" }, Names(o));

        // Comma- or space-separated, de-duplicated case-insensitively.
        o.BimiSelector = "promo, Promo  offers";
        Assert.Equal(new[] { "promo", "offers" }, Names(o));

        // The validator page pre-fills its field, so the request always carries a list;
        // a per-domain entry has to beat it or no per-domain entry would ever be used.
        o.PerDomainBimiSelectors[Domain] = new() { "brand", "promo" };
        Assert.Equal(new[] { "brand", "promo" }, Names(o));
        Assert.Equal($"per-domain config for {Domain}", BimiCheck.Resolve(Domain, o).Source);

        o.ForceBimiSelectors = true;
        Assert.Equal(new[] { "promo", "offers" }, Names(o));
        Assert.Equal("request-forced, per-domain config overridden", BimiCheck.Resolve(Domain, o).Source);

        // Force with nothing requested is not an override.
        o.BimiSelector = " ";
        Assert.Equal(new[] { "brand", "promo" }, Names(o));
    }

    [Fact]
    public void SelectorList_IsCapped()
    {
        var o = new ValidationOptions { BimiSelector = string.Join(",", Enumerable.Range(1, 25).Select(i => $"s{i}")) };
        Assert.Equal(BimiCheck.MaxSelectors, BimiCheck.Selectors(Domain, o).Count);
    }

    [Fact]
    public void EachConfiguredSelector_GetsItsOwnResult()
    {
        var ctx = Context($"v=BIMI1; l={LogoUrl}");                // default
        SeedBimi(ctx, "brand2", $"v=BIMI1; l={LogoUrl}; avp=brand");
        ctx.Options.PerDomainBimiSelectors[Domain] = new() { "default", "brand2" };

        var results = new BimiCheck().RunAsync(Domain, ctx).GetAwaiter().GetResult();

        Assert.Equal(2, results.Count);
        Assert.Equal("default", (string?)results[0].Data!["selector"]);
        Assert.Equal("brand2", (string?)results[1].Data!["selector"]);
        Assert.EndsWith("(selector 'brand2')", results[1].Summary);
        // Each says which list it came from, so a list taken from the wrong place shows.
        Assert.All(results, r => Assert.Contains($"Selectors checked: default, brand2 (per-domain config for {Domain})", r.Details));
    }

    [Fact]
    public void HttpOff_StillChecksTheRecordAndDmarc_ButFetchesNothing()
    {
        // --no-http used to skip BIMI outright, though the record and the DMARC side are
        // DNS. Now only the fetches wait — and the UI can offer the viewer's browser.
        var ctx = Context($"v=BIMI1; l={LogoUrl}; a={CertUrl}", pem: MarkCertificatePem(Svg));
        ctx.Options.EnableHttpProbes = false;
        var view = Run(ctx, out var r);

        Assert.Equal(CheckSeverity.Info, r.Severity);
        Assert.StartsWith("BIMI record found — logo and certificate not checked", r.Summary);
        Assert.False((bool?)view["logo"]!["fetched"]);
        Assert.Null(view["logo"]!["dataUri"]);
        Assert.Equal(BimiCheck.View.Info, (string?)Item(view, "Logo URL")["status"]);
        Assert.Equal(BimiCheck.View.Info, (string?)Item(view, "Mark certificate")["status"]);
        Assert.Equal(BimiCheck.View.Pass, (string?)Item(view, "Policy (p=)")["status"]);
        // Nothing the certificate would have told us is claimed.
        Assert.Null(view["certificate"]!["type"]);
    }

    [Fact]
    public void TheView_SurvivesAJsonRoundTrip()
    {
        // In distributed mode the report — Data included — reaches the browser via a job
        // snapshot serialised into Redis and read back, so the view must come out as it went in.
        var ctx = Context($"v=BIMI1; l={LogoUrl}; a={CertUrl}", pem: MarkCertificatePem(Svg));
        Run(ctx, out var r);
        var opts = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

        var back = JsonSerializer.Deserialize<CheckResult>(JsonSerializer.Serialize(r, opts), opts)!;

        Assert.True(JsonNode.DeepEquals(r.Data, back.Data));
    }

    [Fact]
    public void OversizedLogo_IsValidatedButNotInlined()
    {
        var big = Svg.Replace("</svg>", "<desc>" + new string('x', BimiCheck.MaxInlineLogoBytes) + "</desc></svg>");
        var view = Run(Context($"v=BIMI1; l={LogoUrl}", svg: big), out _);

        Assert.Null(view["logo"]!["dataUri"]);
        Assert.Equal(BimiCheck.View.Warn, (string?)Item(view, "SVG Tiny PS")["status"]);
    }
}
