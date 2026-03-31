using Ednsv.Core.Models;

namespace Ednsv.Core;

/// <summary>
/// Shared source of check category descriptions used by both --help and --list-checks.
/// </summary>
public static class CheckDescriptions
{
    public static readonly IReadOnlyList<CategoryDescription> Categories = new List<CategoryDescription>
    {
        new("Delegation & NS", new[] { CheckCategory.Delegation, CheckCategory.SOA, CheckCategory.NS },
            "Validates the DNS delegation chain, authoritative nameservers, SOA records, and NS " +
            "configuration. Misconfigured delegation causes total mail delivery failure and DNS " +
            "resolution issues."),

        new("Basic DNS Records", new[] { CheckCategory.CNAME, CheckCategory.A, CheckCategory.AAAA },
            "Checks A, AAAA, and CNAME records for correctness. CNAME at the apex violates " +
            "RFC 1034 and breaks MX/NS lookups. Missing address records prevent connectivity."),

        new("MX Records", new[] { CheckCategory.MX },
            "Verifies MX record configuration including priority distribution, backup parity, " +
            "RFC 5321 violations (IP literals, CNAMEs), null MX (RFC 7505), and private IP usage. " +
            "MX misconfigurations directly prevent email delivery."),

        new("SPF (Sender Policy Framework)", new[] { CheckCategory.SPF },
            "Validates SPF records, DNS lookup limits (max 10), include depth, record size, macro " +
            "usage, IP overlaps, and subdomain coverage. SPF authorizes which servers may send mail " +
            "for your domain; failures lead to spoofing or legitimate mail being rejected."),

        new("DMARC", new[] { CheckCategory.DMARC },
            "Checks DMARC policy, inheritance, subdomain overrides, reporting URIs, and alignment " +
            "with SPF. DMARC ties SPF and DKIM together and tells receivers how to handle " +
            "authentication failures. Weak or missing DMARC policies enable domain spoofing."),

        new("DKIM & ARC", new[] { CheckCategory.DKIM },
            "Probes common DKIM selectors and ARC records, detecting broken CNAME delegations. " +
            "DKIM cryptographically signs messages to prove they haven't been tampered with; " +
            "missing or misconfigured DKIM weakens DMARC and harms deliverability."),

        new("Reverse DNS & FCrDNS", new[] { CheckCategory.PTR, CheckCategory.FCrDNS },
            "Verifies PTR records and forward-confirmed reverse DNS for mail server IPs. Many " +
            "receiving servers reject mail from IPs without valid reverse DNS, making this " +
            "essential for deliverability."),

        new("Blocklists (DNSBL)", new[] { CheckCategory.DNSBL, CheckCategory.DomainBL },
            "Checks mail server IPs and the domain against DNS-based blocklists. Blocklisted " +
            "IPs/domains will have mail rejected by most receivers."),

        new("DNSSEC", new[] { CheckCategory.DNSSEC },
            "Validates DNSSEC signing and checks for NSEC/NSEC3 zone walk exposure. DNSSEC " +
            "prevents DNS spoofing and cache poisoning, protecting email routing integrity."),

        new("Transport Security", new[] { CheckCategory.MTASTS, CheckCategory.TLSRPT, CheckCategory.DANE, CheckCategory.SMTP },
            "Tests MTA-STS policy, TLS-RPT reporting, DANE/TLSA records, SMTP TLS certificates, " +
            "TLS version, STARTTLS enforcement, EHLO capabilities, and submission ports. These " +
            "protect mail in transit from interception and downgrade attacks."),

        new("BIMI", new[] { CheckCategory.BIMI },
            "Validates Brand Indicators for Message Identification including SVG logos and VMC " +
            "certificates. BIMI displays your brand logo in supporting email clients, improving " +
            "trust and engagement."),

        new("Service Discovery", new[] { CheckCategory.SRV, CheckCategory.Autodiscover },
            "Checks mail-related SRV records and Autodiscover/Autoconfig endpoints. These enable " +
            "automatic mail client configuration, reducing support burden and misconfiguration."),

        new("Infrastructure", new[] { CheckCategory.CAA, CheckCategory.IPv6, CheckCategory.Wildcard,
            CheckCategory.TTL, CheckCategory.ZoneTransfer, CheckCategory.SecurityTxt, CheckCategory.TXT },
            "Validates CAA records, IPv6 readiness, wildcard DNS, TTL sanity, zone transfer " +
            "exposure (AXFR), security.txt, and TXT record hygiene. These checks cover " +
            "operational security, certificate issuance policy, and DNS best practices."),

        new("Address Verification", new[] { CheckCategory.Postmaster, CheckCategory.Abuse },
            "Verifies that postmaster@ and abuse@ addresses are deliverable per RFC 5321/2142. " +
            "These mandatory addresses enable other operators to report issues with your mail."),
    };

    /// <summary>
    /// Lazily-built lookup from CheckCategory to its CategoryDescription.
    /// </summary>
    private static readonly Lazy<Dictionary<CheckCategory, CategoryDescription>> _lookup = new(() =>
    {
        var dict = new Dictionary<CheckCategory, CategoryDescription>();
        foreach (var cat in Categories)
        {
            foreach (var c in cat.Categories)
                dict[c] = cat;
        }
        return dict;
    });

    /// <summary>
    /// Returns the category description for a given CheckCategory, or null if not mapped.
    /// </summary>
    public static CategoryDescription? GetForCategory(CheckCategory category)
    {
        return _lookup.Value.TryGetValue(category, out var desc) ? desc : null;
    }

    /// <summary>
    /// Returns a compact multi-line summary suitable for --help output.
    /// </summary>
    public static string GetHelpSummary()
    {
        var lines = new List<string>
        {
            "",
            "Checks performed (use --list-checks for details):",
        };

        foreach (var cat in Categories)
        {
            lines.Add($"  - {cat.Name}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// Returns a detailed multi-line listing for --list-checks output.
    /// </summary>
    public static string GetDetailedListing()
    {
        var lines = new List<string>
        {
            "ednsv performs 80+ automated checks across the following areas:",
            "",
        };

        foreach (var cat in Categories)
        {
            lines.Add($"  {cat.Name}");
            // Word-wrap description at ~76 chars with 4-space indent
            foreach (var line in WordWrap(cat.Description, 74))
            {
                lines.Add($"    {line}");
            }
            lines.Add("");
        }

        lines.Add("Use --catch-all and --open-relay to enable opt-in active probing checks.");
        lines.Add("Use --dkim-selectors to probe additional DKIM selectors beyond the defaults.");

        return string.Join(Environment.NewLine, lines);
    }

    private static IEnumerable<string> WordWrap(string text, int maxWidth)
    {
        var words = text.Split(' ');
        var currentLine = "";
        foreach (var word in words)
        {
            if (currentLine.Length == 0)
            {
                currentLine = word;
            }
            else if (currentLine.Length + 1 + word.Length <= maxWidth)
            {
                currentLine += " " + word;
            }
            else
            {
                yield return currentLine;
                currentLine = word;
            }
        }
        if (currentLine.Length > 0)
            yield return currentLine;
    }
}

public class CategoryDescription
{
    public string Name { get; }
    public CheckCategory[] Categories { get; }
    public string Description { get; }

    public CategoryDescription(string name, CheckCategory[] categories, string description)
    {
        Name = name;
        Categories = categories;
        Description = description;
    }
}
