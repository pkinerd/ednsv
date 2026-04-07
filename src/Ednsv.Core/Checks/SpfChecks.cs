using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using DnsClient;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

internal static class SpfHelpers
{
    /// <summary>
    /// Checks whether a TXT string is a valid SPF record identifier.
    /// Matches "v=spf1" exactly as a complete token (followed by space or end-of-string).
    /// Prevents false positives like "v=spf10".
    /// </summary>
    internal static bool IsSpfRecord(string s)
    {
        var trimmed = s.TrimStart();
        return trimmed.Equals("v=spf1", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("v=spf1 ", StringComparison.OrdinalIgnoreCase);
    }
}

public class SpfRecordCheck : ICheck
{
    public string Name => "SPF Record";
    public CheckCategory Category => CheckCategory.SPF;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            var txtRecords = await ctx.Dns.GetTxtRecordsAsync(domain);
            var spfRecords = txtRecords
                .Where(t => t.Text.Any(s => SpfHelpers.IsSpfRecord(s)))
                .ToList();

            if (spfRecords.Count == 0)
            {
                result.Severity = CheckSeverity.Error;
                result.Summary = "No SPF record found";
                result.Errors.Add("No SPF record — any server can claim to send email for this domain. Gmail, Outlook, and Yahoo may reject or junk mail without SPF");
                return new List<CheckResult> { result };
            }

            if (spfRecords.Count > 1)
            {
                result.Severity = CheckSeverity.Error;
                result.Summary = "Multiple SPF records found";
                result.Errors.Add($"Found {spfRecords.Count} SPF records - RFC 7208 requires exactly one");
                foreach (var spf in spfRecords)
                    result.Details.Add($"SPF: {string.Join("", spf.Text)}");
                return new List<CheckResult> { result };
            }

            var spfText = string.Join("", spfRecords[0].Text);
            ctx.SpfRecord = spfText;
            result.Details.Add($"SPF: {spfText}");

            // Check for non-ASCII
            if (spfText.Any(c => c > 127))
            {
                result.Warnings.Add("SPF record contains non-ASCII characters");
            }

            // Parse mechanisms
            var parts = spfText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts.Skip(1)) // skip v=spf1
            {
                result.Details.Add($"  Mechanism: {part}");
            }

            // Validate mechanism syntax (RFC 7208 §12)
            var validMechanisms = new[] { "all", "include:", "a", "a:", "a/", "mx", "mx:", "mx/", "ip4:", "ip6:", "ptr", "ptr:", "exists:", "redirect=", "exp=" };
            foreach (var part in parts.Skip(1))
            {
                var stripped = part.TrimStart('+', '-', '~', '?');
                if (!validMechanisms.Any(vm => stripped.StartsWith(vm, StringComparison.OrdinalIgnoreCase)))
                    result.Warnings.Add($"Unrecognized SPF mechanism: '{part}' — may cause PermError during evaluation");
            }

            // #16 - ip4/ip6 CIDR range validation
            foreach (var part in parts.Skip(1))
            {
                var stripped = part.TrimStart('+', '-', '~', '?');
                if (stripped.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase))
                {
                    var value = stripped.Substring(4);
                    var slashIdx = value.IndexOf('/');
                    var addrPart = slashIdx >= 0 ? value.Substring(0, slashIdx) : value;
                    if (!IPAddress.TryParse(addrPart, out _))
                    {
                        result.Errors.Add($"ip4:{value} — invalid IP address '{addrPart}'");
                    }
                    else if (slashIdx >= 0)
                    {
                        var cidrStr = value.Substring(slashIdx + 1);
                        if (!int.TryParse(cidrStr, out var cidr) || cidr < 0 || cidr > 32)
                            result.Errors.Add($"ip4:{value} — CIDR prefix length must be 0-32");
                        else if (cidr <= 16)
                        {
                            var count = (long)1 << (32 - cidr);
                            result.Warnings.Add($"Overly broad ip4 range /{cidr} authorizes {count} addresses");
                        }
                    }
                }
                else if (stripped.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase))
                {
                    var value = stripped.Substring(4);
                    var slashIdx = value.IndexOf('/');
                    var addrPart = slashIdx >= 0 ? value.Substring(0, slashIdx) : value;
                    if (!IPAddress.TryParse(addrPart, out _))
                    {
                        result.Errors.Add($"ip6:{value} — invalid IP address '{addrPart}'");
                    }
                    else if (slashIdx >= 0)
                    {
                        var cidrStr = value.Substring(slashIdx + 1);
                        if (!int.TryParse(cidrStr, out var cidr) || cidr < 0 || cidr > 128)
                            result.Errors.Add($"ip6:{value} — CIDR prefix length must be 0-128");
                        else if (cidr <= 48)
                        {
                            result.Warnings.Add($"Overly broad ip6 range /{cidr} authorizes a very large address space");
                        }
                    }
                }
            }

            // #19 - Duplicate redirect= or exp= modifiers
            var redirectCount = parts.Skip(1).Count(p => p.TrimStart('+', '-', '~', '?').StartsWith("redirect=", StringComparison.OrdinalIgnoreCase));
            var expCount = parts.Skip(1).Count(p => p.TrimStart('+', '-', '~', '?').StartsWith("exp=", StringComparison.OrdinalIgnoreCase));
            if (redirectCount > 1)
                result.Errors.Add("Duplicate 'redirect=' modifier — each modifier can appear only once (RFC 7208 §6)");
            if (expCount > 1)
                result.Errors.Add("Duplicate 'exp=' modifier — each modifier can appear only once (RFC 7208 §6)");

            // #37 - Mechanisms after all are unreachable
            var allIndex = -1;
            for (int i = 1; i < parts.Length; i++)
            {
                var stripped = parts[i].TrimStart('+', '-', '~', '?');
                if (stripped.Equals("all", StringComparison.OrdinalIgnoreCase))
                {
                    allIndex = i;
                    break;
                }
            }
            if (allIndex >= 0 && allIndex < parts.Length - 1)
            {
                // Check if any tokens after 'all' are mechanisms (not modifiers like redirect= or exp=)
                var mechanismsAfterAll = parts.Skip(allIndex + 1)
                    .Where(p =>
                    {
                        var s = p.TrimStart('+', '-', '~', '?');
                        return !s.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)
                            && !s.StartsWith("exp=", StringComparison.OrdinalIgnoreCase);
                    })
                    .Any();
                if (mechanismsAfterAll)
                    result.Warnings.Add("Mechanisms after 'all' are unreachable and will never be evaluated");
            }

            // #38 - redirect= ignored when all present
            var hasRedirectMod = parts.Skip(1).Any(p => p.TrimStart('+', '-', '~', '?').StartsWith("redirect=", StringComparison.OrdinalIgnoreCase));
            var hasAllMech = parts.Skip(1).Any(p => p.TrimStart('+', '-', '~', '?').Equals("all", StringComparison.OrdinalIgnoreCase));
            if (hasRedirectMod && hasAllMech)
                result.Warnings.Add("redirect= is ignored because an 'all' mechanism is present (RFC 7208 §6.1)");

            // Validate v=spf1 is the first token (RFC 7208 §4.5)
            if (!parts[0].Equals("v=spf1", StringComparison.OrdinalIgnoreCase))
                result.Warnings.Add($"First token is '{parts[0]}', expected 'v=spf1' (RFC 7208 §4.5)");

            // Check for deprecated ptr mechanism (RFC 7208 §5.5)
            if (parts.Any(p => p.TrimStart('+', '-', '~', '?').StartsWith("ptr", StringComparison.OrdinalIgnoreCase)))
            {
                result.Warnings.Add("SPF uses deprecated 'ptr' mechanism (RFC 7208 §5.5) — slow, unreliable, and should be replaced with ip4/ip6/include");
            }

            // Check all mechanism
            var allMech = parts.LastOrDefault(p => p.TrimStart('+', '-', '~', '?').StartsWith("all"));
            if (allMech != null)
            {
                result.Details.Add($"  Policy: {allMech}");
                if (allMech == "+all")
                {
                    result.Severity = CheckSeverity.Error;
                    result.Errors.Add("+all allows any server to send email - SPF is effectively disabled");
                }
                else if (allMech == "~all")
                {
                    // ~all (softfail) is the recommended policy when DMARC is enforced.
                    // It allows DKIM-signed forwarded mail to pass while DMARC catches
                    // unauthenticated mail. -all can break legitimate forwarding.
                    result.Severity = CheckSeverity.Pass;
                    result.Details.Add("~all (softfail) is the recommended policy when used with DMARC enforcement");
                }
                else if (allMech == "-all")
                {
                    result.Severity = CheckSeverity.Pass;
                    result.Details.Add("-all (hardfail) - note: ~all is generally preferred when DMARC is enforced, as -all can break legitimate mail forwarding");
                }
                else if (allMech == "?all")
                {
                    // #40 - ?all (neutral) provides no protection
                    result.Severity = CheckSeverity.Warning;
                    result.Warnings.Add("?all (neutral) provides no protection against spoofing");
                }
                else
                {
                    result.Severity = CheckSeverity.Pass;
                }
            }
            else
            {
                // RFC 7208 §5.1: redirect= replaces the entire record, so no 'all' is expected
                var hasRedirect = parts.Any(p => p.TrimStart('+', '-', '~', '?').StartsWith("redirect=", StringComparison.OrdinalIgnoreCase));
                if (hasRedirect)
                {
                    result.Severity = CheckSeverity.Pass;
                    result.Details.Add("Policy defined by redirect= target (no local 'all' expected)");
                }
                else
                {
                    result.Severity = CheckSeverity.Warning;
                    result.Warnings.Add("No 'all' mechanism and no redirect= — implicit ?all (neutral)");
                }
            }

            result.Summary = $"SPF record found: {allMech ?? (parts.Any(p => p.TrimStart('+', '-', '~', '?').StartsWith("redirect=", StringComparison.OrdinalIgnoreCase)) ? "redirect" : "no all mechanism")}";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }
}

public class SpfExpansionCheck : ICheck
{
    public string Name => "SPF Recursive Expansion";
    public CheckCategory Category => CheckCategory.SPF;

    private int _lookupCount;
    private int _voidLookupCount;
    private int _maxDepth;
    private readonly HashSet<string> _visitedDomains = new(StringComparer.OrdinalIgnoreCase);

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        _lookupCount = 0;
        _voidLookupCount = 0;
        _maxDepth = 0;
        _visitedDomains.Clear();

        try
        {
            if (ctx.SpfRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No SPF record to expand";
                return new List<CheckResult> { result };
            }

            await ExpandSpfAsync(ctx, domain, ctx.SpfRecord, result, 0);

            result.Details.Insert(0, $"Total DNS lookups: {_lookupCount}");
            result.Details.Insert(1, $"Void lookups: {_voidLookupCount}");
            result.Details.Insert(2, $"Max nesting depth: {_maxDepth}");

            result.Severity = CheckSeverity.Pass;
            result.Summary = $"SPF expanded: {_lookupCount} lookups, depth {_maxDepth}";
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }

    private static (string domain, string? cidr) SplitCidr(string value)
    {
        var slashIdx = value.IndexOf('/');
        if (slashIdx >= 0)
            return (value.Substring(0, slashIdx), value.Substring(slashIdx));
        return (value, null);
    }

    private static string QualifierPrefix(string part)
    {
        if (part.Length > 0 && "+-~?".Contains(part[0]))
            return part[0].ToString();
        return "+"; // implicit pass
    }

    private async Task ExpandSpfAsync(CheckContext ctx, string domain, string spf, CheckResult result, int depth)
    {
        if (depth > 10)
        {
            result.Warnings.Add($"SPF expansion truncated at depth {depth} (safety limit)");
            return;
        }
        if (!_visitedDomains.Add(domain))
        {
            result.Warnings.Add($"Circular SPF reference detected: {domain} was already visited in this chain");
            return;
        }
        if (depth > _maxDepth) _maxDepth = depth;
        var indent = new string(' ', depth * 2);

        var parts = spf.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            if (part.Equals("v=spf1", StringComparison.OrdinalIgnoreCase)) continue;
            var qualifier = QualifierPrefix(part);
            var mech = part.TrimStart('+', '-', '~', '?');
            var qualLabel = qualifier == "+" ? "" : $"({qualifier}) ";

            if (mech.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
            {
                _lookupCount++;
                var target = mech.Substring(8);
                result.Details.Add($"{indent}{qualLabel}include:{target}");
                var (txt, lookupError) = await GetSpfForDomainAsync(ctx, target);
                if (txt != null)
                    await ExpandSpfAsync(ctx, target, txt, result, depth + 1);
                else
                {
                    _voidLookupCount++;
                    if (lookupError != null)
                        result.Warnings.Add($"include:{target} — could not expand: {lookupError}");
                    else
                        result.Errors.Add($"include:{target} has no SPF record — this causes PermError (RFC 7208 §5.2)");
                }
            }
            else if (mech.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
            {
                _lookupCount++;
                var target = mech.Substring(9);
                result.Details.Add($"{indent}{qualLabel}redirect={target}");
                var (txt, lookupError) = await GetSpfForDomainAsync(ctx, target);
                if (txt != null)
                    await ExpandSpfAsync(ctx, target, txt, result, depth + 1);
                else
                {
                    _voidLookupCount++;
                    if (lookupError != null)
                        result.Warnings.Add($"redirect={target} — could not expand: {lookupError}");
                    else
                        result.Errors.Add($"redirect={target} has no SPF record — this causes PermError (RFC 7208 §6.1)");
                }
            }
            else if (mech.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || mech == "a"
                     || (mech.StartsWith("a/", StringComparison.OrdinalIgnoreCase)))
            {
                _lookupCount++;
                string raw = mech.Length > 2 && mech[1] == ':' ? mech.Substring(2) : (mech == "a" ? "" : mech.Substring(1));
                var (target, cidr) = raw.Length > 0 ? SplitCidr(raw) : (domain, null);
                if (string.IsNullOrEmpty(target)) target = domain;
                var cidrLabel = cidr ?? "";
                var ips = await ctx.Dns.ResolveAAsync(target);
                var ipsV6 = await ctx.Dns.ResolveAAAAAsync(target);
                var allIps = ips.Concat(ipsV6).ToList();
                result.Details.Add($"{indent}{qualLabel}a:{target}{cidrLabel} -> {string.Join(", ", allIps)}");
                if (!allIps.Any()) _voidLookupCount++;
            }
            else if (mech.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || mech == "mx"
                     || (mech.StartsWith("mx/", StringComparison.OrdinalIgnoreCase)))
            {
                _lookupCount++;
                string raw = mech.Length > 3 && mech[2] == ':' ? mech.Substring(3) : (mech == "mx" ? "" : mech.Substring(2));
                var (target, cidr) = raw.Length > 0 ? SplitCidr(raw) : (domain, null);
                if (string.IsNullOrEmpty(target)) target = domain;
                var cidrLabel = cidr ?? "";
                var mxRecs = await ctx.Dns.GetMxRecordsAsync(target);
                // #41 - mx: 10 MX sub-limit
                if (mxRecs.Count > 10)
                    result.Warnings.Add($"mx:{target} has {mxRecs.Count} MX records — only the first 10 will be evaluated (RFC 7208 §5.4)");
                foreach (var mx in mxRecs)
                {
                    var mxHost = mx.Exchange.Value.TrimEnd('.');
                    var ips = await ctx.Dns.ResolveAAsync(mxHost);
                    var ipsV6 = await ctx.Dns.ResolveAAAAAsync(mxHost);
                    var allIps = ips.Concat(ipsV6).ToList();
                    result.Details.Add($"{indent}{qualLabel}mx:{target}{cidrLabel} -> {mxHost} -> {string.Join(", ", allIps)}");
                }
                if (!mxRecs.Any()) _voidLookupCount++;
            }
            else if (mech.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase))
            {
                result.Details.Add($"{indent}{qualLabel}{mech}");
            }
            else if (mech.StartsWith("ip6:", StringComparison.OrdinalIgnoreCase))
            {
                result.Details.Add($"{indent}{qualLabel}{mech}");
            }
            else if (mech.StartsWith("exists:", StringComparison.OrdinalIgnoreCase))
            {
                _lookupCount++;
                var existsDomain = mech.Substring(7);
                if (existsDomain.Contains("%{"))
                    result.Details.Add($"{indent}{qualLabel}{mech} (macro — expands at evaluation time)");
                else
                    result.Details.Add($"{indent}{qualLabel}{mech}");
            }
            else if (mech.StartsWith("ptr", StringComparison.OrdinalIgnoreCase))
            {
                _lookupCount++;
                result.Details.Add($"{indent}{qualLabel}{mech} (deprecated)");
            }
            else if (mech.Equals("all", StringComparison.OrdinalIgnoreCase))
            {
                result.Details.Add($"{indent}{qualifier}all");
            }
            else if (mech.StartsWith("exp=", StringComparison.OrdinalIgnoreCase))
            {
                var expTarget = mech.Substring(4);
                result.Details.Add($"{indent}exp={expTarget}");
                // #39 - exp= target validation
                try
                {
                    var expTxts = await ctx.Dns.GetTxtRecordsAsync(expTarget);
                    if (!expTxts.Any())
                        result.Warnings.Add($"exp={expTarget} target has no TXT record — explanation string will not be available");
                }
                catch
                {
                    result.Warnings.Add($"exp={expTarget} target has no TXT record — explanation string will not be available");
                }
            }
            else
            {
                result.Details.Add($"{indent}(unrecognized: {part})");
            }
        }
    }

    private async Task<(string? spf, string? error)> GetSpfForDomainAsync(CheckContext ctx, string domain)
    {
        var errorsBefore = ctx.Dns.QueryErrors.Count;
        var txts = await ctx.Dns.GetTxtRecordsAsync(domain);
        var errorsAfter = ctx.Dns.QueryErrors.Count;

        if (errorsAfter > errorsBefore)
        {
            var error = ctx.Dns.QueryErrors.LastOrDefault() ?? "DNS query failed";
            return (null, error);
        }

        var spf = txts.FirstOrDefault(t => t.Text.Any(s => SpfHelpers.IsSpfRecord(s)));
        return spf != null ? (string.Join("", spf.Text), null) : (null, null);
    }
}

public class SpfLookupCountCheck : ICheck
{
    public string Name => "SPF Lookup Count";
    public CheckCategory Category => CheckCategory.SPF;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        try
        {
            if (ctx.SpfRecord == null)
            {
                result.Severity = CheckSeverity.Info;
                result.Summary = "No SPF record to check";
                return new List<CheckResult> { result };
            }

            int lookups = 0;
            int voidLookups = 0;
            await CountLookupsAsync(ctx, domain, ctx.SpfRecord, new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                l => lookups = l, v => voidLookups = v);

            result.Details.Add($"DNS lookups: {lookups}/10");
            result.Details.Add($"Void lookups: {voidLookups}/2");

            if (lookups > 10)
            {
                result.Severity = CheckSeverity.Error;
                result.Summary = $"SPF exceeds 10-lookup limit ({lookups} lookups)";
                result.Errors.Add($"RFC 7208 limits SPF to 10 DNS lookups. Found {lookups}");
            }
            else if (voidLookups > 2)
            {
                result.Severity = CheckSeverity.Error;
                result.Summary = $"SPF exceeds 2-void-lookup limit ({voidLookups} void)";
                result.Errors.Add($"RFC 7208 limits void lookups to 2. Found {voidLookups}");
            }
            else if (lookups > 8)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = $"SPF is close to 10-lookup limit ({lookups} lookups)";
                result.Warnings.Add("Consider optimizing SPF to stay well under the limit");
            }
            else
            {
                result.Severity = CheckSeverity.Pass;
                result.Summary = $"SPF uses {lookups}/10 lookups";
            }
        }
        catch (Exception ex)
        {
            result.Severity = CheckSeverity.Error;
            result.Errors.Add(ex.Message);
        }

        return new List<CheckResult> { result };
    }

    private async Task CountLookupsAsync(CheckContext ctx, string domain, string spf,
        HashSet<string> visited, Action<int> setLookups, Action<int> setVoids)
    {
        int lookups = 0;
        int voids = 0;

        async Task WalkAsync(string d, string s)
        {
            if (!visited.Add(d + "|" + s)) return;
            var parts = s.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var mech = part.TrimStart('+', '-', '~', '?');
                if (mech.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
                {
                    lookups++;
                    var target = mech.Substring(8);
                    var txt = await GetSpfAsync(ctx, target);
                    if (txt != null) await WalkAsync(target, txt); else voids++;
                }
                else if (mech.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
                {
                    lookups++;
                    var target = mech.Substring(9);
                    var txt = await GetSpfAsync(ctx, target);
                    if (txt != null) await WalkAsync(target, txt); else voids++;
                }
                else if (mech.StartsWith("a:", StringComparison.OrdinalIgnoreCase) || mech == "a")
                    lookups++;
                else if (mech.StartsWith("mx:", StringComparison.OrdinalIgnoreCase) || mech == "mx")
                    lookups++;
                else if (mech.StartsWith("exists:", StringComparison.OrdinalIgnoreCase))
                    lookups++;
                else if (mech.StartsWith("ptr", StringComparison.OrdinalIgnoreCase))
                    lookups++;
            }
        }

        await WalkAsync(domain, spf);
        setLookups(lookups);
        setVoids(voids);
    }

    private async Task<string?> GetSpfAsync(CheckContext ctx, string domain)
    {
        var txts = await ctx.Dns.GetTxtRecordsAsync(domain);
        var spf = txts.FirstOrDefault(t => t.Text.Any(s => SpfHelpers.IsSpfRecord(s)));
        return spf != null ? string.Join("", spf.Text) : null;
    }
}

public class SpfIncludeDepthCheck : ICheck
{
    public string Name => "SPF Include Depth";
    public CheckCategory Category => CheckCategory.SPF;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };

        if (ctx.SpfRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No SPF record";
            return new List<CheckResult> { result };
        }

        int maxDepth = 0;
        await MeasureDepthAsync(ctx, ctx.SpfRecord, 0, new HashSet<string>(StringComparer.OrdinalIgnoreCase), d => { if (d > maxDepth) maxDepth = d; });

        result.Details.Add($"Maximum nesting depth: {maxDepth}");
        if (maxDepth > 3)
        {
            result.Severity = CheckSeverity.Warning;
            result.Summary = $"SPF nesting depth {maxDepth} exceeds recommended limit of 3";
            result.Warnings.Add("Deep nesting can cause resolution timeouts");
        }
        else
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = $"SPF nesting depth: {maxDepth}";
        }

        return new List<CheckResult> { result };
    }

    private async Task MeasureDepthAsync(CheckContext ctx, string spf, int depth, HashSet<string> visited, Action<int> reportDepth)
    {
        reportDepth(depth);
        if (depth > 10) return;

        var parts = spf.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var mech = part.TrimStart('+', '-', '~', '?');
            string? target = null;
            if (mech.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
                target = mech.Substring(8);
            else if (mech.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
                target = mech.Substring(9);

            if (target != null && visited.Add(target))
            {
                var txts = await ctx.Dns.GetTxtRecordsAsync(target);
                var nextSpf = txts.FirstOrDefault(t => t.Text.Any(s => SpfHelpers.IsSpfRecord(s)));
                if (nextSpf != null)
                    await MeasureDepthAsync(ctx, string.Join("", nextSpf.Text), depth + 1, visited, reportDepth);
            }
        }
    }
}

public class SpfRecordSizeCheck : ICheck
{
    public string Name => "SPF Record Size";
    public CheckCategory Category => CheckCategory.SPF;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        await Task.CompletedTask;

        if (ctx.SpfRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No SPF record";
            return new List<CheckResult> { result };
        }

        var size = Encoding.UTF8.GetByteCount(ctx.SpfRecord);
        result.Details.Add($"SPF record size: {size} bytes");

        if (size > 512)
        {
            result.Severity = CheckSeverity.Error;
            result.Summary = $"SPF record ({size} bytes) exceeds 512-byte UDP limit";
            result.Errors.Add("Record may be truncated in UDP responses");
        }
        else if (size > 450)
        {
            result.Severity = CheckSeverity.Warning;
            result.Summary = $"SPF record ({size} bytes) approaching 512-byte limit";
            result.Warnings.Add("Consider shortening the SPF record");
        }
        else
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = $"SPF record size: {size} bytes";
        }

        return new List<CheckResult> { result };
    }
}

public class SpfMacrosCheck : ICheck
{
    public string Name => "SPF Macros";
    public CheckCategory Category => CheckCategory.SPF;

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        await Task.CompletedTask;

        if (ctx.SpfRecord == null)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = "No SPF record";
            return new List<CheckResult> { result };
        }

        var macroPattern = new Regex(@"%\{[a-zA-Z][^}]*\}");
        var matches = macroPattern.Matches(ctx.SpfRecord);

        if (matches.Count > 0)
        {
            result.Severity = CheckSeverity.Info;
            result.Summary = $"SPF contains {matches.Count} macro(s)";
            foreach (Match m in matches)
            {
                result.Details.Add($"Macro: {m.Value}");
                if (m.Value.Contains("%{p}", StringComparison.OrdinalIgnoreCase))
                {
                    result.Warnings.Add($"Deprecated %{{p}} macro found: {m.Value}");
                    result.Severity = CheckSeverity.Warning;
                }
            }
        }
        else
        {
            result.Severity = CheckSeverity.Pass;
            result.Summary = "No SPF macros detected";
        }

        return new List<CheckResult> { result };
    }
}
