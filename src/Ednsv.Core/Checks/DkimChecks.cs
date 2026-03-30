using DnsClient;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class DkimSelectorsCheck : ICheck
{
    public string Name => "DKIM Selectors";
    public CheckCategory Category => CheckCategory.DKIM;

    private static readonly string[] CommonSelectors =
    {
        "default", "google", "selector1", "selector2", "k1", "k2", "k3",
        "s1", "s2", "s3", "dkim", "mail", "email", "smtp",
        "google2048", "everlytickey1", "everlytickey2",
        "mandrill", "amazonses", "postmark", "sendgrid", "cm",
        "mxvault", "protonmail", "protonmail2", "protonmail3",
        "fm1", "fm2", "fm3", // FastMail
        "pic", "mailjet",
        "zoho", "turbo-smtp",
        "sig1", "smtpapi", "hs1", "hs2", "m1", "m2",
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        var found = new List<(string selector, string record)>();

        try
        {
            foreach (var selector in CommonSelectors)
            {
                var dkimDomain = $"{selector}._domainkey.{domain}";
                var txts = await ctx.Dns.GetTxtRecordsAsync(dkimDomain);
                var dkimRec = txts.FirstOrDefault(t => t.Text.Any(s =>
                    s.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("k=rsa", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("k=ed25519", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("p=", StringComparison.OrdinalIgnoreCase)));

                if (dkimRec != null)
                {
                    var text = string.Join("", dkimRec.Text);
                    found.Add((selector, text));
                }
                else
                {
                    // Check for CNAME
                    var chain = await ctx.Dns.ResolveCnameChainAsync(dkimDomain);
                    if (chain.Any())
                    {
                        // Follow CNAME and check TXT at target
                        var cTarget = chain.Last().Split(" -> ").Last();
                        var targetTxts = await ctx.Dns.GetTxtRecordsAsync(cTarget);
                        var targetDkim = targetTxts.FirstOrDefault(t => t.Text.Any(s =>
                            s.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase) ||
                            s.Contains("p=", StringComparison.OrdinalIgnoreCase)));

                        if (targetDkim != null)
                        {
                            var text = string.Join("", targetDkim.Text);
                            found.Add((selector, $"(via CNAME {string.Join(", ", chain)}) {text}"));
                        }
                    }
                }
            }

            if (found.Any())
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"Found {found.Count} DKIM selector(s)";

                foreach (var (selector, record) in found)
                {
                    result.Details.Add($"Selector: {selector}");
                    result.Details.Add($"  Record: {record}");

                    // Analyze key
                    var tags = ParseDkimTags(record);
                    if (tags.TryGetValue("k", out var keyType))
                        result.Details.Add($"  Key type: {keyType}");
                    if (tags.TryGetValue("p", out var pubKey))
                    {
                        if (string.IsNullOrEmpty(pubKey))
                        {
                            result.Warnings.Add($"Selector {selector}: Empty public key (revoked)");
                        }
                        else
                        {
                            // Estimate key size from base64 length
                            var keyBytes = pubKey.Length * 3 / 4;
                            var keyBits = keyBytes * 8;
                            result.Details.Add($"  Key size: ~{keyBits} bits");
                            if (keyBits < 1024)
                                result.Warnings.Add($"Selector {selector}: Key is only ~{keyBits} bits (recommended >= 2048)");
                            else if (keyBits < 2048)
                                result.Warnings.Add($"Selector {selector}: Key is ~{keyBits} bits (recommended >= 2048)");
                        }
                    }
                    if (tags.TryGetValue("t", out var flags))
                    {
                        if (flags.Contains("y", StringComparison.OrdinalIgnoreCase))
                            result.Warnings.Add($"Selector {selector}: Testing mode (t=y) - signatures not enforced");
                        result.Details.Add($"  Flags: {flags}");
                    }
                    if (tags.TryGetValue("h", out var hash))
                        result.Details.Add($"  Hash algorithms: {hash}");
                    if (tags.TryGetValue("s", out var service))
                        result.Details.Add($"  Service type: {service}");
                }
            }
            else
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "No DKIM selectors found";
                result.Warnings.Add($"Probed {CommonSelectors.Length} common selectors - none found");
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }

    private static Dictionary<string, string> ParseDkimTags(string record)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // Remove CNAME prefix if present
        var text = record;
        var parenIdx = text.IndexOf(')');
        if (text.StartsWith("(") && parenIdx >= 0)
            text = text.Substring(parenIdx + 1).Trim();

        foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            var eqIdx = trimmed.IndexOf('=');
            if (eqIdx > 0)
            {
                var key = trimmed.Substring(0, eqIdx).Trim();
                var value = trimmed.Substring(eqIdx + 1).Trim();
                tags[key] = value;
            }
        }
        return tags;
    }
}
