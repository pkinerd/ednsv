using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

public class TraceMaskerTests
{
    private readonly TraceMasker _masker = new("test-salt-for-deterministic-hashes");

    // ── DKIM selector masking ────────────────────────────────────────────

    [Fact]
    public void Mask_DkimSelector_MasksFullConstruct()
    {
        var input = "Checking google._domainkey.example.com";
        var output = _masker.Mask(input);

        Assert.DoesNotContain("google._domainkey", output);
        Assert.DoesNotContain("example.com", output);
        Assert.Contains("dkim:", output);
    }

    [Fact]
    public void Mask_DkimSelector_DifferentSelectorsProduceDifferentHashes()
    {
        var a = _masker.Mask("s1._domainkey.example.com");
        var b = _masker.Mask("s2._domainkey.example.com");

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Mask_DkimSelector_SameSelectorProducesSameHash()
    {
        var a = _masker.Mask("s1._domainkey.example.com");
        var b = _masker.Mask("s1._domainkey.example.com");

        Assert.Equal(a, b);
    }

    [Fact]
    public void Mask_DkimSelector_PreservesSurroundingText()
    {
        var output = _masker.Mask("TXT query for s1._domainkey.example.com returned NXDOMAIN");

        Assert.StartsWith("TXT query for dkim:", output);
        Assert.EndsWith("returned NXDOMAIN", output);
    }

    [Fact]
    public void Mask_DkimSelector_MultipleSelectorsInSameMessage()
    {
        var input = "s1._domainkey.example.com and s2._domainkey.example.com";
        var output = _masker.Mask(input);

        Assert.DoesNotContain("example.com", output);
        Assert.DoesNotContain("_domainkey", output);
        // Both should be masked
        Assert.Equal(2, output.Split("dkim:").Length - 1);
    }

    [Fact]
    public void Mask_DkimSelector_WithSubdomain()
    {
        var output = _masker.Mask("selector1._domainkey.mail.example.com");

        Assert.DoesNotContain("selector1", output);
        Assert.DoesNotContain("example.com", output);
        Assert.Contains("dkim:", output);
    }

    // ── Layered masking: DKIM + hostname interaction ─────────────────────

    [Fact]
    public void Mask_DkimAndHostname_BothMaskedInSameMessage()
    {
        // DKIM selector and a separate hostname in the same message
        var input = "CNAME s1._domainkey.example.com -> dkim.provider.com";
        var output = _masker.Mask(input);

        Assert.DoesNotContain("example.com", output);
        Assert.DoesNotContain("provider.com", output);
        Assert.DoesNotContain("s1", output);
        Assert.Contains("dkim:", output);
        Assert.Contains("h:", output);
    }

    [Fact]
    public void Mask_DkimSelector_DoesNotDoubleHash()
    {
        // The domain in selector._domainkey.domain should NOT also be
        // separately hashed by the hostname regex (it was consumed by DKIM)
        var input = "s1._domainkey.unique-test-domain.org";
        var output = _masker.Mask(input);

        // Should have exactly one dkim: token, no leftover hostname masking
        Assert.Equal(1, output.Split("dkim:").Length - 1);
        Assert.DoesNotContain("h:", output);
    }

    [Fact]
    public void Mask_DkimSelectorWithAlreadyMaskedDomain_StillMasksSelector()
    {
        // Simulate a double-mask scenario: domain was already masked by a prior pass
        var domainHash = _masker.Hash("example.com");
        var input = $"sel._domainkey.h:{domainHash}";
        var output = _masker.Mask(input);

        // The selector portion should be masked even though domain is already hashed
        Assert.DoesNotContain("sel._domainkey", output);
        Assert.Contains("dkim:", output);
    }

    // ── Existing masking still works ─────────────────────────────────────

    [Fact]
    public void Mask_Hostname_StillMasked()
    {
        var output = _masker.Mask("connecting to mail.example.com");
        Assert.DoesNotContain("example.com", output);
        Assert.Contains("h:", output);
    }

    [Fact]
    public void Mask_Email_StillMasked()
    {
        var output = _masker.Mask("postmaster@example.com not found");
        Assert.DoesNotContain("postmaster@example.com", output);
        Assert.Contains("e:", output);
    }

    [Fact]
    public void Mask_IPv4_StillMasked()
    {
        var output = _masker.Mask("connecting to 192.168.1.1");
        Assert.DoesNotContain("192.168.1.1", output);
        Assert.Contains("ip4:", output);
    }

    [Fact]
    public void Mask_NonPrivateHostnames_NotMasked()
    {
        var output = _masker.Mask("fetching from crt.sh");
        Assert.Contains("crt.sh", output);
    }

    // ── MaskResult ───────────────────────────────────────────────────────

    [Fact]
    public void MaskResult_MasksAllStringFields()
    {
        var result = new CheckResult
        {
            CheckName = "DKIM Selectors",
            Category = CheckCategory.DKIM,
            Severity = CheckSeverity.Pass,
            Summary = "Found selector at s1._domainkey.example.com",
            Details = { "Selector: s1", "Record at s1._domainkey.example.com" },
            Warnings = { "CNAME to dkim.provider.com broken" },
            Errors = { "No TXT at s1._domainkey.example.com" }
        };

        _masker.MaskResult(result);

        // Summary masked
        Assert.DoesNotContain("example.com", result.Summary);
        // Details masked
        Assert.All(result.Details, d => Assert.DoesNotContain("example.com", d));
        // Warnings masked
        Assert.DoesNotContain("provider.com", result.Warnings[0]);
        Assert.Contains("h:", result.Warnings[0]);
        // Errors masked
        Assert.DoesNotContain("example.com", result.Errors[0]);
        Assert.Contains("dkim:", result.Errors[0]);
    }

    // ── Ordering: email containing domain doesn't leak to hostname pass ──

    [Fact]
    public void Mask_EmailBeforeHostname_DomainNotDoubleMasked()
    {
        var input = "contact admin@example.com about example.com config";
        var output = _masker.Mask(input);

        // admin@example.com → e:hash, example.com → h:hash
        Assert.Contains("e:", output);
        Assert.Contains("h:", output);
        Assert.DoesNotContain("admin@", output);
        Assert.DoesNotContain("example.com", output);
    }
}
