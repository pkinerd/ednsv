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
                // Detect wildcard DNS at *._domainkey.domain — if most probed selectors
                // return the identical record, it's a wildcard, not real selectors
                var distinctRecords = found.Select(f => f.record).Distinct().ToList();
                if (distinctRecords.Count == 1 && found.Count >= 10)
                {
                    result.Severity = CheckSeverity.Info;
                    result.Summary = "Wildcard DNS at *._domainkey — not real DKIM selectors";
                    result.Details.Add($"All {found.Count} probed selectors returned the identical record (wildcard DNS)");
                    result.Details.Add($"  Record: {distinctRecords[0]}");
                    result.Details.Add("Cannot determine actual DKIM selectors via probing when wildcard is present");
                    return new List<CheckResult> { result };
                }

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

                    // RFC 6376 §3.6.1: v=DKIM1 is required
                    if (!tags.TryGetValue("v", out var version) || !version.Equals("DKIM1", StringComparison.OrdinalIgnoreCase))
                    {
                        if (version == null)
                            result.Warnings.Add($"Selector {selector}: Missing v=DKIM1 tag (RFC 6376 §3.6.1 requires it)");
                        else
                            result.Errors.Add($"Selector {selector}: Invalid version '{version}' — expected DKIM1");
                    }

                    // RFC 6376 §3.6.1: k= must be rsa (default) or ed25519 (RFC 8463)
                    if (tags.TryGetValue("k", out var keyType))
                    {
                        result.Details.Add($"  Key type: {keyType}");
                        if (!keyType.Equals("rsa", StringComparison.OrdinalIgnoreCase) &&
                            !keyType.Equals("ed25519", StringComparison.OrdinalIgnoreCase))
                            result.Errors.Add($"Selector {selector}: Unknown key type '{keyType}' — must be 'rsa' or 'ed25519' (RFC 6376 §3.6.1)");
                    }

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
                                result.Errors.Add($"Selector {selector}: Key is only ~{keyBits} bits — too weak (RFC 8301 requires >= 1024 for RSA)");
                            else if (keyBits < 2048)
                                result.Warnings.Add($"Selector {selector}: Key is ~{keyBits} bits (RFC 8301 recommends >= 2048)");
                        }
                    }
                    else
                    {
                        result.Errors.Add($"Selector {selector}: Missing p= tag (public key is required, RFC 6376 §3.6.1)");
                    }
                    if (tags.TryGetValue("t", out var flags))
                    {
                        if (flags.Contains("y", StringComparison.OrdinalIgnoreCase))
                            result.Warnings.Add($"Selector {selector}: Testing mode (t=y) - signatures not enforced");
                        result.Details.Add($"  Flags: {flags}");
                    }
                    // RFC 6376 §3.6.1: h= hash algorithms
                    if (tags.TryGetValue("h", out var hash))
                    {
                        result.Details.Add($"  Hash algorithms: {hash}");
                        var algorithms = hash.Split(':', StringSplitOptions.RemoveEmptyEntries).Select(a => a.Trim()).ToList();
                        if (algorithms.Any(a => a.Equals("sha1", StringComparison.OrdinalIgnoreCase)))
                            result.Warnings.Add($"Selector {selector}: sha1 hash is deprecated (RFC 8301) — use sha256");
                        foreach (var algo in algorithms)
                            if (!algo.Equals("sha1", StringComparison.OrdinalIgnoreCase) && !algo.Equals("sha256", StringComparison.OrdinalIgnoreCase))
                                result.Warnings.Add($"Selector {selector}: Non-standard hash algorithm '{algo}'");
                    }
                    // RFC 6376 §3.6.1: s= service type (default is *, email is the other valid value)
                    if (tags.TryGetValue("s", out var service))
                    {
                        result.Details.Add($"  Service type: {service}");
                        var services = service.Split(':', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();
                        foreach (var svc in services)
                            if (!svc.Equals("*", StringComparison.Ordinal) && !svc.Equals("email", StringComparison.OrdinalIgnoreCase))
                                result.Warnings.Add($"Selector {selector}: Non-standard service type '{svc}' (RFC 6376 §3.6.1 allows '*' or 'email')");
                    }
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
