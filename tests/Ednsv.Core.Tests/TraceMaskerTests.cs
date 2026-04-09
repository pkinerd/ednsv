using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

public class TraceMaskerTests
{
    private readonly TraceMasker _masker = new("test-salt-for-deterministic-hashes");

    // ── DKIM selector masking ────────────────────────────────────────────

    [Fact]
    public void Mask_DkimSelector_PreservesStructure()
    {
        var output = _masker.Mask("Checking google._domainkey.example.com");

        // Should produce: "Checking dkim:<hash>._domainkey.h:<hash>"
        Assert.DoesNotContain("google", output);
        Assert.DoesNotContain("example.com", output);
        Assert.Contains("dkim:", output);
        Assert.Contains("._domainkey.", output);
        Assert.Matches(@"dkim:[a-zA-Z0-9_-]{10}\._domainkey\.h:[a-zA-Z0-9_-]{10}", output);
    }

    [Fact]
    public void Mask_DkimSelector_DifferentSelectorsProduceDifferentHashes()
    {
        var a = _masker.Mask("s1._domainkey.example.com");
        var b = _masker.Mask("s2._domainkey.example.com");

        // Selector hashes differ, domain hashes are the same
        Assert.NotEqual(a, b);
        // Both share the same domain hash
        var domainHash = $"h:{_masker.Hash("example.com")}";
        Assert.Contains(domainHash, a);
        Assert.Contains(domainHash, b);
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
        // Structure preserved for both
        Assert.Equal(2, output.Split("._domainkey.").Length - 1);
        Assert.Equal(2, output.Split("dkim:").Length - 1);
    }

    [Fact]
    public void Mask_DkimSelector_WithSubdomain()
    {
        var output = _masker.Mask("selector1._domainkey.mail.example.com");

        Assert.DoesNotContain("selector1", output);
        Assert.DoesNotContain("example.com", output);
        Assert.Contains("._domainkey.", output);
        Assert.Contains("dkim:", output);
    }

    [Fact]
    public void Mask_DkimSelector_DomainHashMatchesStandaloneHostnameHash()
    {
        // The domain portion of a DKIM selector should hash the same as
        // a standalone hostname — allows cross-referencing in logs
        var dkimOutput = _masker.Mask("s1._domainkey.example.com");
        var hostOutput = _masker.Mask("connecting to example.com");

        var domainHash = $"h:{_masker.Hash("example.com")}";
        Assert.Contains(domainHash, dkimOutput);
        Assert.Contains(domainHash, hostOutput);
    }

    // ── Layered masking: DKIM + hostname interaction ─────────────────────

    [Fact]
    public void Mask_DkimAndHostname_BothMaskedInSameMessage()
    {
        var input = "CNAME s1._domainkey.example.com -> dkim.provider.com";
        var output = _masker.Mask(input);

        Assert.DoesNotContain("example.com", output);
        Assert.DoesNotContain("provider.com", output);
        Assert.DoesNotContain("s1._domainkey", output);
        Assert.Contains("dkim:", output);
        Assert.Contains("._domainkey.", output);
        Assert.Contains("h:", output);
    }

    [Fact]
    public void Mask_DkimSelector_DomainNotDoubleHashedByHostnamePass()
    {
        // The domain in dkim:hash._domainkey.h:hash should not be
        // re-matched by the hostname regex
        var input = "s1._domainkey.unique-test-domain.org";
        var output = _masker.Mask(input);

        // Count h: tokens — should be exactly one (the domain in the DKIM construct)
        Assert.Equal(1, output.Split("h:").Length - 1);
    }

    [Fact]
    public void Mask_DkimSelectorWithAlreadyMaskedDomain_StillMasksSelector()
    {
        // Simulate a double-mask scenario: domain was already masked by a prior pass
        var domainHash = _masker.Hash("example.com");
        var input = $"sel._domainkey.h:{domainHash}";
        var output = _masker.Mask(input);

        // The selector should be masked, already-masked domain preserved as-is
        Assert.DoesNotContain("sel._domainkey", output);
        Assert.Contains("dkim:", output);
        Assert.Contains("._domainkey.", output);
        Assert.Contains($"h:{domainHash}", output);
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

        // Summary masked — DKIM structure preserved
        Assert.DoesNotContain("example.com", result.Summary);
        Assert.Contains("._domainkey.", result.Summary);
        // Details masked
        Assert.All(result.Details, d => Assert.DoesNotContain("example.com", d));
        // Warnings masked
        Assert.DoesNotContain("provider.com", result.Warnings[0]);
        Assert.Contains("h:", result.Warnings[0]);
        // Errors masked — DKIM structure preserved
        Assert.DoesNotContain("example.com", result.Errors[0]);
        Assert.Contains("._domainkey.", result.Errors[0]);
    }

    // ── Ordering: email containing domain doesn't leak to hostname pass ──

    [Fact]
    public void Mask_EmailBeforeHostname_DomainNotDoubleMasked()
    {
        var input = "contact admin@example.com about example.com config";
        var output = _masker.Mask(input);

        Assert.Contains("e:", output);
        Assert.Contains("h:", output);
        Assert.DoesNotContain("admin@", output);
        Assert.DoesNotContain("example.com", output);
    }
}
