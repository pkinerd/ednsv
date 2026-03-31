using System.Text;
using System.Text.RegularExpressions;
using DnsClient;
using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

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
                .Where(t => t.Text.Any(s => s.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (spfRecords.Count == 0)
            {
                result.Severity = CheckSeverity.Warning;
                result.Summary = "No SPF record found";
                result.Warnings.Add("No SPF record - any server can claim to send email for this domain");
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
                else
                {
                    result.Severity = CheckSeverity.Pass;
                }
            }
            else
            {
                result.Severity = CheckSeverity.Warning;
                result.Warnings.Add("No 'all' mechanism - implicit ?all (neutral)");
            }

            result.Summary = $"SPF record found: {allMech ?? "no all mechanism"}";
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

    public async Task<List<CheckResult>> RunAsync(string domain, CheckContext ctx)
    {
        var result = new CheckResult { CheckName = Name, Category = Category };
        _lookupCount = 0;
        _voidLookupCount = 0;
        _maxDepth = 0;

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
                var txt = await GetSpfForDomainAsync(ctx, target);
                if (txt != null)
                    await ExpandSpfAsync(ctx, target, txt, result, depth + 1);
                else
                    _voidLookupCount++;
            }
            else if (mech.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
            {
                _lookupCount++;
                var target = mech.Substring(9);
                result.Details.Add($"{indent}{qualLabel}redirect={target}");
                var txt = await GetSpfForDomainAsync(ctx, target);
                if (txt != null)
                    await ExpandSpfAsync(ctx, target, txt, result, depth + 1);
                else
                    _voidLookupCount++;
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
                result.Details.Add($"{indent}exp={mech.Substring(4)}");
            }
            else
            {
                result.Details.Add($"{indent}(unrecognized: {part})");
            }
        }
    }

    private async Task<string?> GetSpfForDomainAsync(CheckContext ctx, string domain)
    {
        var txts = await ctx.Dns.GetTxtRecordsAsync(domain);
        var spf = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)));
        return spf != null ? string.Join("", spf.Text) : null;
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
        var spf = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)));
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
                var nextSpf = txts.FirstOrDefault(t => t.Text.Any(s => s.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)));
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
