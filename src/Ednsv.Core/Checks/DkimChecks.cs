using DnsClient;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public class DkimSelectorsCheck : ICheck
{
    public string Name => "DKIM Selectors";
    public CheckCategory Category => CheckCategory.DKIM;

    public static readonly string[] CommonSelectors =
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

    // Known DKIM key record tags per RFC 6376 §3.6.1
    private static readonly HashSet<string> KnownDkimTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "v", "h", "k", "n", "p", "s", "t", "g"
    };

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx, CancellationToken cancellationToken = default)
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

            // Build selector list based on what sources are available:
            // - If user provided selectors: use user + any AXFR-discovered (skip defaults)
            // - If AXFR discovered selectors: use only those (skip defaults)
            // - Otherwise: fall back to common/default selectors
            var userProvided = ctx.Options.AdditionalDkimSelectors;
            List<string> allSelectors;
            string selectorSource;

            if (userProvided.Any() && axfrSelectors.Any())
            {
                allSelectors = userProvided
                    .Concat(axfrSelectors)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                selectorSource = "user-provided + AXFR-discovered";
            }
            else if (userProvided.Any())
            {
                allSelectors = userProvided
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                selectorSource = "user-provided";
            }
            else if (axfrSelectors.Any())
            {
                allSelectors = axfrSelectors
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                selectorSource = "AXFR-discovered";
            }
            else
            {
                allSelectors = CommonSelectors.ToList();
                selectorSource = "default list";
            }

            result.Details.Add($"DKIM selectors checked ({selectorSource}): {string.Join(", ", allSelectors)}");

            // Probe selectors concurrently using speculative (short-timeout) queries.
            // DKIM selector probing is best-effort — a timeout just means "couldn't check",
            // not an error. This avoids 30-45s waits per non-existent selector.
            var probeTasks = allSelectors.Select(async selector =>
            {
                var dkimDomain = $"{selector}._domainkey.{domain}";
                var txts = await ctx.Dns.GetTxtRecordsSpeculativeAsync(dkimDomain);

                // #2 - Multiple TXT RRs at same selector
                var dkimRecords = txts.Where(t => t.Text.Any(s =>
                    s.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("k=rsa", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("k=ed25519", StringComparison.OrdinalIgnoreCase) ||
                    s.Contains("p=", StringComparison.OrdinalIgnoreCase))).ToList();

                var multipleTxt = dkimRecords.Count > 1;
                var dkimRec = dkimRecords.FirstOrDefault();

                if (dkimRec != null)
                {
                    var text = string.Join("", dkimRec.Text);
                    return (selector, record: text, cnameChain: (string?)null, brokenCname: (string?)null, multipleTxt);
                }

                // Check for CNAME delegation (common for ESP-managed DKIM) — also speculative
                var cnameResp = await ctx.Dns.QuerySpeculativeAsync(dkimDomain, DnsClient.QueryType.CNAME);
                var cnameRec = cnameResp.Answers.CnameRecords().FirstOrDefault();
                if (cnameRec != null)
                {
                    var cTarget = cnameRec.CanonicalName.Value.TrimEnd('.');
                    var targetTxts = await ctx.Dns.GetTxtRecordsSpeculativeAsync(cTarget);
                    var targetDkim = targetTxts.FirstOrDefault(t => t.Text.Any(s =>
                        s.Contains("v=DKIM1", StringComparison.OrdinalIgnoreCase) ||
                        s.Contains("p=", StringComparison.OrdinalIgnoreCase)));

                    if (targetDkim != null)
                    {
                        var text = string.Join("", targetDkim.Text);
                        return (selector, record: text, cnameChain: $"{dkimDomain} → {cTarget}", brokenCname: (string?)null, multipleTxt: false);
                    }
                    else
                    {
                        return (selector, record: (string?)null, cnameChain: $"{dkimDomain} → {cTarget}", brokenCname: cTarget, multipleTxt: false);
                    }
                }

                return (selector, record: (string?)null, cnameChain: (string?)null, brokenCname: (string?)null, multipleTxt: false);
            }).ToList();

            var probeResults = await Task.WhenAll(probeTasks);
            foreach (var pr in probeResults)
            {
                if (pr.record != null)
                {
                    found.Add((pr.selector, pr.record));
                    if (pr.cnameChain != null)
                        cnameSelectors[pr.selector] = pr.cnameChain;
                    // #2 - Multiple TXT RRs
                    if (pr.multipleTxt)
                        result.Errors.Add($"Selector '{pr.selector}': Multiple TXT records found at {pr.selector}._domainkey.{domain} — results are undefined (RFC 6376 §3.6.1)");
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
                var activeKeyTypes = new List<string>(); // #54 - track key types for ed25519-only advisory

                foreach (var (selector, record) in found)
                {
                    result.Details.Add($"Selector: {selector}");
                    if (cnameSelectors.TryGetValue(selector, out var cnameChain))
                        result.Details.Add($"  Delegated via CNAME: {cnameChain}");
                    result.Details.Add($"  Record: {record}");

                    // #55 - Record length concern
                    if (record.Length > 450)
                        result.Details.Add($"  Record length: {record.Length} chars (may require DNS TCP fallback for large keys)");

                    // Analyze key
                    var (tags, duplicateTags, malformedEntries) = ParseDkimTags(record);

                    // #21 - Duplicate tags
                    foreach (var dupTag in duplicateTags)
                        result.Warnings.Add($"Selector {selector}: Duplicate tag '{dupTag}' in record (RFC 6376 §3.2: tags MUST NOT be duplicated)");

                    // #23 - Malformed tag entries
                    foreach (var badEntry in malformedEntries)
                        result.Warnings.Add($"Selector {selector}: Malformed tag entry '{badEntry}' (no '=' sign found)");

                    // #20 - v= must be first tag
                    var recordTrimmed = record.TrimStart();
                    if (tags.ContainsKey("v") && !recordTrimmed.StartsWith("v=", StringComparison.OrdinalIgnoreCase))
                        result.Warnings.Add($"Selector {selector}: v= tag is not the first tag in the record (RFC 6376 §3.6.1 requires it to be first)");

                    // RFC 6376 §3.6.1: v=DKIM1 is required
                    if (!tags.TryGetValue("v", out var version) || !version.Equals("DKIM1", StringComparison.OrdinalIgnoreCase))
                    {
                        if (version == null)
                            result.Warnings.Add($"Selector {selector}: Missing v=DKIM1 tag (RFC 6376 §3.6.1 requires it)");
                        else
                            result.Errors.Add($"Selector {selector}: Invalid version '{version}' — expected DKIM1");
                    }

                    // #22 - Deprecated g= tag
                    if (tags.ContainsKey("g"))
                        result.Warnings.Add($"Selector {selector}: Deprecated g= tag present (removed in RFC 6376, was in RFC 4871)");

                    // RFC 6376 §3.6.1: k= must be rsa (default) or ed25519 (RFC 8463)
                    var isEd25519 = false;
                    if (tags.TryGetValue("k", out var keyType))
                    {
                        result.Details.Add($"  Key type: {keyType}");
                        isEd25519 = keyType.Equals("ed25519", StringComparison.OrdinalIgnoreCase);
                        if (!keyType.Equals("rsa", StringComparison.OrdinalIgnoreCase) && !isEd25519)
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

                            // #5 - Validate p= is legal base64
                            try
                            {
                                Convert.FromBase64String(pubKey);
                            }
                            catch (FormatException)
                            {
                                result.Errors.Add($"Selector {selector}: p= value is not valid base64 — DKIM verification will always fail");
                            }

                            // #1 - Key size validation: branch on key type
                            if (isEd25519)
                            {
                                activeKeyTypes.Add("ed25519");
                                // Ed25519 public keys are exactly 256 bits (44 base64 chars)
                                result.Details.Add($"  Key size: 256 bits (Ed25519)");
                                if (pubKey.Length != 44)
                                    result.Warnings.Add($"Selector {selector}: Ed25519 public key should be exactly 44 base64 characters (256 bits), found {pubKey.Length} chars");
                            }
                            else
                            {
                                activeKeyTypes.Add("rsa");
                                // RSA key size estimation from base64 length
                                var keyBytes = pubKey.Length * 3 / 4;
                                var keyBits = keyBytes * 8;
                                result.Details.Add($"  Key size: ~{keyBits} bits");
                                if (keyBits < 1024)
                                    result.Errors.Add($"Selector {selector}: Key is only ~{keyBits} bits — too weak (RFC 8301 requires >= 1024 for RSA)");
                                else if (keyBits < 2048)
                                    result.Warnings.Add($"Selector {selector}: Key is ~{keyBits} bits (RFC 8301 recommends >= 2048)");
                                // #53 - RSA keys >4096 bits interoperability note
                                else if (keyBits > 4096)
                                    result.Details.Add($"  Key is ~{keyBits} bits — keys >4096 bits may have interoperability issues (RFC 8301)");
                            }
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
                        // #51 - Report t=s flag
                        if (flags.Contains("s", StringComparison.OrdinalIgnoreCase))
                            result.Details.Add($"  Strict subdomain mode (t=s): subdomains cannot use this key");
                        result.Details.Add($"  Flags: {flags}");
                    }
                    // RFC 6376 §3.6.1: h= hash algorithms
                    if (tags.TryGetValue("h", out var hash))
                    {
                        result.Details.Add($"  Hash algorithms: {hash}");
                        var algorithms = hash.Split(':', StringSplitOptions.RemoveEmptyEntries).Select(a => a.Trim()).ToList();
                        // #4 - sha1 MUST NOT be used (Error, not Warning)
                        if (algorithms.Any(a => a.Equals("sha1", StringComparison.OrdinalIgnoreCase)))
                            result.Errors.Add($"Selector {selector}: sha1 hash algorithm MUST NOT be used (RFC 8301 §3)");
                        // #3 - h= listing ONLY sha1 means key is unusable
                        if (algorithms.All(a => a.Equals("sha1", StringComparison.OrdinalIgnoreCase)))
                            result.Errors.Add($"Selector {selector}: h= lists only sha1 — key is unusable since sha1 MUST NOT be used (RFC 8301)");
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

                    // #50 - Display n= tag
                    if (tags.TryGetValue("n", out var notes))
                        result.Details.Add($"  Notes: {notes}");

                    // #52 - Unknown tags
                    foreach (var tag in tags.Keys)
                    {
                        if (!KnownDkimTags.Contains(tag))
                            result.Details.Add($"  Unknown tag '{tag}={tags[tag]}' (will be ignored, possible typo?)");
                    }
                }

                // #54 - Ed25519-only advisory
                if (activeCount > 0 && activeKeyTypes.Any() && activeKeyTypes.All(t => t == "ed25519"))
                    result.Warnings.Add("Only Ed25519 DKIM keys found — consider also publishing RSA keys for backward compatibility (RFC 8463)");

                if (activeCount > 0)
                {
                    result.Severity = result.Errors.Any() ? CheckSeverity.Warning : CheckSeverity.Pass;
                    var extra = new List<string>();
                    if (revokedCount > 0) extra.Add($"{revokedCount} revoked");
                    if (result.Errors.Any()) extra.Add($"{result.Errors.Count} error(s)");
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

    /// <summary>
    /// Parses DKIM tag-value pairs from a record string.
    /// Returns (tags dictionary, duplicate tag names, malformed entries).
    /// </summary>
    internal static (Dictionary<string, string> tags, List<string> duplicates, List<string> malformed) ParseDkimTags(string record)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var duplicates = new List<string>();
        var malformed = new List<string>();

        // Remove CNAME prefix if present
        var text = record;
        var parenIdx = text.IndexOf(')');
        if (text.StartsWith("(") && parenIdx >= 0)
            text = text.Substring(parenIdx + 1).Trim();

        foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            var eqIdx = trimmed.IndexOf('=');
            if (eqIdx > 0)
            {
                var key = trimmed.Substring(0, eqIdx).Trim();
                var value = trimmed.Substring(eqIdx + 1).Trim();
                // #21 - Detect duplicate tags
                if (tags.ContainsKey(key))
                    duplicates.Add(key);
                tags[key] = value;
            }
            else
            {
                // #23 - Malformed entry (no '=' sign)
                malformed.Add(trimmed);
            }
        }
        return (tags, duplicates, malformed);
    }

    /// <summary>
    /// Validates DKIM key record tags and adds findings to the result.
    /// Shared between DkimSelectorsCheck and ArcCheck.
    /// </summary>
    internal static void ValidateDkimKeyRecord(string label, string record, CheckResult result)
    {
        var (tags, duplicates, malformed) = ParseDkimTags(record);

        foreach (var dup in duplicates)
            result.Warnings.Add($"{label}: Duplicate tag '{dup}' (RFC 6376 §3.2)");
        foreach (var bad in malformed)
            result.Warnings.Add($"{label}: Malformed tag entry '{bad}' (no '=' sign)");

        if (!tags.TryGetValue("v", out var version) || !version.Equals("DKIM1", StringComparison.OrdinalIgnoreCase))
        {
            if (version == null)
                result.Warnings.Add($"{label}: Missing v=DKIM1 tag");
            else
                result.Errors.Add($"{label}: Invalid version '{version}' — expected DKIM1");
        }

        if (tags.TryGetValue("k", out var keyType))
        {
            result.Details.Add($"  {label} key type: {keyType}");
            var isEd25519 = keyType.Equals("ed25519", StringComparison.OrdinalIgnoreCase);
            if (!keyType.Equals("rsa", StringComparison.OrdinalIgnoreCase) && !isEd25519)
                result.Errors.Add($"{label}: Unknown key type '{keyType}'");
        }

        if (tags.TryGetValue("p", out var pubKey))
        {
            if (string.IsNullOrEmpty(pubKey))
            {
                result.Warnings.Add($"{label}: Empty public key (revoked)");
            }
            else
            {
                try { Convert.FromBase64String(pubKey); }
                catch (FormatException) { result.Errors.Add($"{label}: p= value is not valid base64"); }

                var isEd = tags.TryGetValue("k", out var kt) && kt.Equals("ed25519", StringComparison.OrdinalIgnoreCase);
                if (isEd)
                {
                    result.Details.Add($"  {label} key size: 256 bits (Ed25519)");
                }
                else
                {
                    var keyBits = pubKey.Length * 3 / 4 * 8;
                    result.Details.Add($"  {label} key size: ~{keyBits} bits");
                    if (keyBits < 1024)
                        result.Errors.Add($"{label}: Key is only ~{keyBits} bits — too weak (RFC 8301)");
                    else if (keyBits < 2048)
                        result.Warnings.Add($"{label}: Key is ~{keyBits} bits (RFC 8301 recommends >= 2048)");
                }
            }
        }
        else
        {
            result.Errors.Add($"{label}: Missing p= tag (public key required)");
        }

        if (tags.TryGetValue("h", out var hash))
        {
            var algorithms = hash.Split(':', StringSplitOptions.RemoveEmptyEntries).Select(a => a.Trim()).ToList();
            if (algorithms.Any(a => a.Equals("sha1", StringComparison.OrdinalIgnoreCase)))
                result.Errors.Add($"{label}: sha1 MUST NOT be used (RFC 8301)");
        }
    }
}
