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
        var cnameSelectors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            // Try AXFR to discover selectors from zone data (if enabled and NS IPs available)
            var axfrSelectors = new List<string>();
            if (ctx.Options.EnableAxfr && ctx.NsHosts.Any())
            {
                bool axfrSucceeded = false;
                foreach (var nsHost in ctx.NsHosts)
                {
                    if (!ctx.NsHostIps.TryGetValue(nsHost, out var ips)) continue;
                    foreach (var ip in ips)
                    {
                        if (!System.Net.IPAddress.TryParse(ip, out var addr)) continue;
                        var discovered = await ctx.Dns.ExtractDkimSelectorsFromAxfrAsync(addr, domain);
                        if (discovered.Any())
                        {
                            axfrSucceeded = true;
                            axfrSelectors.AddRange(discovered);
                            result.Details.Add($"AXFR from {nsHost}: discovered {discovered.Count} selector(s): {string.Join(", ", discovered)}");
                            break; // One successful AXFR is enough
                        }
                    }
                    if (axfrSelectors.Any()) break;
                }
                if (!axfrSucceeded)
                    result.Details.Add("AXFR selector discovery: zone transfer denied (probing common selectors only)");
            }

            // Merge AXFR-discovered + user-provided + common selectors (deduped)
            var allSelectors = axfrSelectors
                .Concat(ctx.Options.AdditionalDkimSelectors)
                .Concat(CommonSelectors)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            // Probe selectors in parallel (10 concurrent DNS lookups)
            using var semaphore = new SemaphoreSlim(10);
            var probeTasks = allSelectors.Select(selector => Task.Run(async () =>
            {
                await semaphore.WaitAsync();
                try
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
                        return (selector, record: text, cnameChain: (string?)null, brokenCname: (string?)null);
                    }

                    // Check for CNAME delegation (common for ESP-managed DKIM)
                    var chain = await ctx.Dns.ResolveCnameChainAsync(dkimDomain);
                    if (chain.Any())
                    {
                        var cTarget = chain.Last().Split(" -> ").Last();
                        var targetTxts = await ctx.Dns.GetTxtRecordsAsync(cTarget);
                        var targetDkim = targetTxts.FirstOrDefault(t => t.Text.Any(s =>
                            s.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase) ||
                            s.Contains("p=", StringComparison.OrdinalIgnoreCase)));

                        if (targetDkim != null)
                        {
                            var text = string.Join("", targetDkim.Text);
                            return (selector, record: text, cnameChain: (string?)string.Join(" → ", chain), brokenCname: (string?)null);
                        }
                        else
                        {
                            // CNAME exists but target has no DKIM TXT — broken delegation
                            return (selector, record: (string?)null, cnameChain: (string?)string.Join(" → ", chain), brokenCname: cTarget);
                        }
                    }

                    return (selector, record: (string?)null, cnameChain: (string?)null, brokenCname: (string?)null);
                }
                finally { semaphore.Release(); }
            })).ToList();

            var probeResults = await Task.WhenAll(probeTasks);
            foreach (var pr in probeResults)
            {
                if (pr.record != null)
                {
                    found.Add((pr.selector, pr.record));
                    if (pr.cnameChain != null)
                        cnameSelectors[pr.selector] = pr.cnameChain;
                }
                else if (pr.brokenCname != null)
                {
                    result.Errors.Add($"Selector '{pr.selector}': CNAME delegation exists ({pr.cnameChain}) but target {pr.brokenCname} has no TXT record — DKIM verification will fail for this selector");
                }
            }

            if (found.Any())
            {
                int activeCount = 0;
                int revokedCount = 0;

                foreach (var (selector, record) in found)
                {
                    result.Details.Add($"Selector: {selector}");
                    if (cnameSelectors.TryGetValue(selector, out var cnameChain))
                        result.Details.Add($"  Delegated via CNAME: {cnameChain}");
                    result.Details.Add($"  Record: {record}");

                    // Analyze key
                    var tags = ParseDkimTags(record);
                    if (tags.TryGetValue("k", out var keyType))
                        result.Details.Add($"  Key type: {keyType}");
                    if (tags.TryGetValue("p", out var pubKey))
                    {
                        if (string.IsNullOrEmpty(pubKey))
                        {
                            revokedCount++;
                            result.Warnings.Add($"Selector {selector}: Empty public key (revoked)");
                        }
                        else
                        {
                            activeCount++;
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
                    else
                    {
                        activeCount++; // No p= tag means key might be valid
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

                if (activeCount > 0)
                {
                    result.Severity = result.Errors.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
                    var extra = new List<string>();
                    if (revokedCount > 0) extra.Add($"{revokedCount} revoked");
                    if (result.Errors.Any()) extra.Add($"{result.Errors.Count} broken CNAME(s)");
                    result.Summary = $"Found {activeCount} active DKIM selector(s)" +
                        (extra.Any() ? $" ({string.Join(", ", extra)})" : "");
                }
                else
                {
                    result.Severity = CheckSeverity.Warning;
                    result.Summary = $"Found {found.Count} DKIM selector(s) but all have revoked keys";
                }
            }
            else
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "No DKIM selectors found";
                result.Warnings.Add($"Probed {allSelectors.Count} selectors - none found");
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
