using System.CommandLine;
using System.Text;
using System.Text.Json;
using System.Web;
using Ednsv.Core;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Spectre.Console;

var domainArg = new Argument<string>("domain", "The domain name to validate (e.g., example.com)");
var formatOption = new Option<string>("--format", () => "text", "Output format: text, json, html, markdown");
formatOption.AddAlias("-f");
var noAxfrOption = new Option<bool>("--no-axfr", "Disable zone transfer (AXFR) testing");
var catchAllOption = new Option<bool>("--catch-all", "Enable catch-all detection (sends probe to random address)");
var openRelayOption = new Option<bool>("--open-relay", "Enable open relay testing (probes MX servers for relay misconfiguration)");
var dkimSelectorsOption = new Option<string[]>(
    "--dkim-selectors",
    "DKIM selectors to probe instead of defaults (comma-separated or repeated; combined with any discovered via AXFR)")
{
    AllowMultipleArgumentsPerToken = true
};
var listChecksOption = new Option<bool>("--list-checks", "Show detailed descriptions of all checks performed");
var verboseOption = new Option<bool>("--verbose", "Show why each check category matters alongside results");
var rootCommand = new RootCommand("ednsv - DNS Email Validation Tool" + CheckDescriptions.GetHelpSummary())
{
    domainArg,
    formatOption,
    noAxfrOption,
    catchAllOption,
    openRelayOption,
    dkimSelectorsOption,
    listChecksOption,
    verboseOption
};

// Make domain optional when --list-checks is used
domainArg.SetDefaultValue("");

rootCommand.SetHandler(async (string domain, string format, bool noAxfr, bool catchAll, bool openRelay, string[] dkimSelectors, bool listChecks, bool verbose) =>
{
    if (listChecks)
    {
        Console.WriteLine(CheckDescriptions.GetDetailedListing());
        return;
    }

    domain = domain.Trim().TrimEnd('.').ToLowerInvariant();

    if (string.IsNullOrWhiteSpace(domain))
    {
        Console.Error.WriteLine("Error: Please provide a domain name. Use --help for usage information.");
        return;
    }

    // Parse comma-separated selectors (--dkim-selectors s1,s2,s3 or --dkim-selectors s1 --dkim-selectors s2)
    var parsedSelectors = new List<string>();
    if (dkimSelectors != null)
    {
        foreach (var s in dkimSelectors)
        {
            foreach (var part in s.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = part.Trim();
                if (!string.IsNullOrEmpty(trimmed))
                    parsedSelectors.Add(trimmed);
            }
        }
    }

    var options = new ValidationOptions
    {
        EnableAxfr = !noAxfr,
        EnableCatchAll = catchAll,
        EnableOpenRelay = openRelay,
        AdditionalDkimSelectors = parsedSelectors
    };

    switch (format.ToLowerInvariant())
    {
        case "json":
            await RunJsonAsync(domain, options);
            break;
        case "html":
            await RunHtmlAsync(domain, options);
            break;
        case "markdown":
        case "md":
            await RunMarkdownAsync(domain, options);
            break;
        default:
            await RunInteractiveAsync(domain, options, verbose);
            break;
    }
}, domainArg, formatOption, noAxfrOption, catchAllOption, openRelayOption, dkimSelectorsOption, listChecksOption, verboseOption);

return await rootCommand.InvokeAsync(args);

static async Task RunInteractiveAsync(string domain, ValidationOptions options, bool verbose = false)
{
    AnsiConsole.Write(new Rule($"[bold blue]ednsv - Email DNS Validation[/]").RuleStyle("blue"));
    AnsiConsole.MarkupLine($"[bold]Domain:[/] {Markup.Escape(domain)}");
    AnsiConsole.MarkupLine($"[bold]Started:[/] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
    if (!options.EnableAxfr)
        AnsiConsole.MarkupLine("[grey]AXFR testing disabled[/]");
    if (verbose)
        AnsiConsole.MarkupLine("[grey]Verbose mode: showing check descriptions[/]");
    AnsiConsole.WriteLine();

    var validator = new DomainValidator();
    CheckCategory? currentCategory = null;
    var shownDescriptions = new HashSet<string>();
    var showingRunningLine = false;

    // Display results progressively as each check completes
    validator.OnCheckStarted += name =>
    {
        AnsiConsole.MarkupLine($"  [dim blue]● Running: {Markup.Escape(name)}…[/]");
        showingRunningLine = true;
    };

    validator.OnCheckCompleted += (name, check) =>
    {
        // Erase the "Running:" status line (only if it's still showing)
        if (showingRunningLine)
        {
            AnsiConsole.Write("\x1b[1A\x1b[2K");
            showingRunningLine = false;
        }

        // Print category header when category changes
        if (check.Category != currentCategory)
        {
            if (currentCategory != null)
                AnsiConsole.WriteLine();

            currentCategory = check.Category;
            AnsiConsole.Write(new Rule($"[bold]{check.Category}[/]").RuleStyle("grey"));

            if (verbose)
            {
                var catDesc = CheckDescriptions.GetForCategory(check.Category);
                if (catDesc != null && shownDescriptions.Add(catDesc.Name))
                {
                    AnsiConsole.MarkupLine($"  [dim]{Markup.Escape(catDesc.Description)}[/]");
                    AnsiConsole.WriteLine();
                }
            }
        }

        var icon = check.Severity switch
        {
            CheckSeverity.Pass => "[green]PASS[/]",
            CheckSeverity.Info => "[blue]INFO[/]",
            CheckSeverity.Warning => "[yellow]WARN[/]",
            CheckSeverity.Error => "[red]FAIL[/]",
            CheckSeverity.Critical => "[red bold]CRIT[/]",
            _ => "[grey]????[/]"
        };

        AnsiConsole.MarkupLine($"  {icon} [bold]{Markup.Escape(check.CheckName)}[/]: {Markup.Escape(check.Summary)}");

        foreach (var detail in check.Details)
            AnsiConsole.MarkupLine($"       [grey]{Markup.Escape(detail)}[/]");

        foreach (var warning in check.Warnings)
            AnsiConsole.MarkupLine($"       [yellow]⚠ {Markup.Escape(warning)}[/]");

        foreach (var error in check.Errors)
            AnsiConsole.MarkupLine($"       [red]✗ {Markup.Escape(error)}[/]");
    };

    var report = await validator.ValidateAsync(domain, options);

    // Summary
    AnsiConsole.WriteLine();
    AnsiConsole.Write(new Rule("[bold]Summary[/]").RuleStyle("grey"));

    var summaryTable = new Table()
        .Border(TableBorder.Rounded)
        .AddColumn("Metric")
        .AddColumn("Count");

    summaryTable.AddRow("[green]Pass[/]", report.PassCount.ToString());
    summaryTable.AddRow("[yellow]Warning[/]", report.WarningCount.ToString());
    summaryTable.AddRow("[red]Error[/]", report.ErrorCount.ToString());
    summaryTable.AddRow("[red bold]Critical[/]", report.CriticalCount.ToString());
    summaryTable.AddRow("[blue]Total Checks[/]", report.Results.Count.ToString());
    summaryTable.AddRow("[grey]Duration[/]", $"{report.Duration.TotalSeconds:F1}s");

    AnsiConsole.Write(summaryTable);
    AnsiConsole.WriteLine();

    // Overall verdict
    AnsiConsole.Write(new Rule("[bold]Verdict[/]").RuleStyle("grey"));

    if (report.CriticalCount > 0)
        AnsiConsole.MarkupLine("[red bold]CRITICAL issues found that need immediate attention![/]");
    else if (report.ErrorCount > 0)
        AnsiConsole.MarkupLine("[red]Errors found that should be addressed.[/]");
    else if (report.WarningCount > 0)
        AnsiConsole.MarkupLine("[yellow]Warnings found - review recommended.[/]");
    else
        AnsiConsole.MarkupLine("[green]All checks passed. Email configuration looks good![/]");
}

static async Task RunJsonAsync(string domain, ValidationOptions options)
{
    var validator = new DomainValidator();
    var report = await validator.ValidateAsync(domain, options);

    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    Console.WriteLine(JsonSerializer.Serialize(report, jsonOptions));
}

static async Task RunMarkdownAsync(string domain, ValidationOptions options)
{
    var validator = new DomainValidator();
    var report = await validator.ValidateAsync(domain, options);

    var sb = new StringBuilder();

    sb.AppendLine($"# ednsv — Email DNS Validation Report");
    sb.AppendLine();
    sb.AppendLine($"**Domain:** `{domain}`");
    sb.AppendLine($"**Date:** {report.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
    sb.AppendLine($"**Duration:** {report.Duration.TotalSeconds:F1}s");
    sb.AppendLine();

    // Summary table
    sb.AppendLine("## Summary");
    sb.AppendLine();
    sb.AppendLine("| Metric | Count |");
    sb.AppendLine("|--------|------:|");
    sb.AppendLine($"| Pass | {report.PassCount} |");
    sb.AppendLine($"| Warning | {report.WarningCount} |");
    sb.AppendLine($"| Error | {report.ErrorCount} |");
    sb.AppendLine($"| Critical | {report.CriticalCount} |");
    sb.AppendLine($"| **Total** | **{report.Results.Count}** |");
    sb.AppendLine();

    // Group results by category
    var grouped = report.Results.GroupBy(r => r.Category).OrderBy(g => g.Key);

    sb.AppendLine("## Results");
    sb.AppendLine();

    foreach (var group in grouped)
    {
        sb.AppendLine($"### {group.Key}");
        sb.AppendLine();

        foreach (var check in group)
        {
            var icon = check.Severity switch
            {
                CheckSeverity.Pass => "\u2705",
                CheckSeverity.Info => "\u2139\uFE0F",
                CheckSeverity.Warning => "\u26A0\uFE0F",
                CheckSeverity.Error => "\u274C",
                CheckSeverity.Critical => "\uD83D\uDED1",
                _ => "\u2753"
            };

            sb.AppendLine($"**{icon} {check.CheckName}** — {SeverityLabel(check.Severity)}");
            sb.AppendLine();
            sb.AppendLine($"> {MdText(check.Summary)}");
            sb.AppendLine();

            if (check.Details.Any())
            {
                foreach (var detail in check.Details)
                    sb.AppendLine($"- `{detail}`");
                sb.AppendLine();
            }

            if (check.Warnings.Any())
            {
                foreach (var warning in check.Warnings)
                    sb.AppendLine($"- \u26A0\uFE0F {MdText(warning)}");
                sb.AppendLine();
            }

            if (check.Errors.Any())
            {
                foreach (var error in check.Errors)
                    sb.AppendLine($"- \u274C {MdText(error)}");
                sb.AppendLine();
            }
        }
    }

    // Verdict
    sb.AppendLine("---");
    sb.AppendLine();
    sb.AppendLine("## Verdict");
    sb.AppendLine();
    if (report.CriticalCount > 0)
        sb.AppendLine("\uD83D\uDED1 **CRITICAL issues found that need immediate attention!**");
    else if (report.ErrorCount > 0)
        sb.AppendLine("\u274C **Errors found that should be addressed.**");
    else if (report.WarningCount > 0)
        sb.AppendLine("\u26A0\uFE0F **Warnings found — review recommended.**");
    else
        sb.AppendLine("\u2705 **All checks passed. Email configuration looks good!**");

    sb.AppendLine();
    sb.AppendLine("---");
    sb.AppendLine($"*Generated by [ednsv](https://github.com/pkinerd/ednsv) on {report.Timestamp:yyyy-MM-dd HH:mm:ss} UTC*");

    Console.Write(sb.ToString());
}

static async Task RunHtmlAsync(string domain, ValidationOptions options)
{
    var validator = new DomainValidator();
    var report = await validator.ValidateAsync(domain, options);

    var sb = new StringBuilder();
    var e = (string s) => HttpUtility.HtmlEncode(s);

    sb.AppendLine("<!DOCTYPE html>");
    sb.AppendLine("<html lang=\"en\">");
    sb.AppendLine("<head>");
    sb.AppendLine("<meta charset=\"UTF-8\">");
    sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
    sb.AppendLine($"<title>ednsv Report — {e(domain)}</title>");
    sb.AppendLine("<style>");
    sb.AppendLine(@"
:root {
  --pass: #16a34a; --pass-bg: #f0fdf4;
  --warn: #ca8a04; --warn-bg: #fefce8;
  --error: #dc2626; --error-bg: #fef2f2;
  --crit: #991b1b; --crit-bg: #fef2f2;
  --info: #2563eb; --info-bg: #eff6ff;
  --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0;
  --text: #1e293b; --muted: #64748b;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
.meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 1.5rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.75rem; margin-bottom: 2rem; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
.stat .value { font-size: 1.75rem; font-weight: 700; }
.stat .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
.stat.pass .value { color: var(--pass); }
.stat.warn .value { color: var(--warn); }
.stat.error .value { color: var(--error); }
.stat.crit .value { color: var(--crit); }
.category { margin-bottom: 1.5rem; }
.category h2 { font-size: 1.1rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; margin-bottom: 0.75rem; }
.check { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.5rem; border-left: 4px solid var(--border); }
.check.sev-pass { border-left-color: var(--pass); }
.check.sev-info { border-left-color: var(--info); }
.check.sev-warning { border-left-color: var(--warn); }
.check.sev-error { border-left-color: var(--error); }
.check.sev-critical { border-left-color: var(--crit); }
.check-header { display: flex; align-items: center; gap: 0.5rem; }
.badge { font-size: 0.7rem; font-weight: 600; padding: 0.15rem 0.5rem; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-pass { background: var(--pass-bg); color: var(--pass); }
.badge-info { background: var(--info-bg); color: var(--info); }
.badge-warning { background: var(--warn-bg); color: var(--warn); }
.badge-error { background: var(--error-bg); color: var(--error); }
.badge-critical { background: var(--crit-bg); color: var(--crit); }
.check-name { font-weight: 600; }
.check-summary { color: var(--muted); font-size: 0.9rem; margin-top: 0.25rem; }
details { margin-top: 0.5rem; }
summary { cursor: pointer; font-size: 0.8rem; color: var(--muted); }
.detail-list, .warning-list, .error-list { list-style: none; padding: 0; margin-top: 0.375rem; font-size: 0.825rem; }
.detail-list li { color: var(--muted); padding: 0.125rem 0; padding-left: 1rem; text-indent: -0.6rem; }
.detail-list li::before { content: '·'; margin-right: 0.4rem; }
.warning-list li { color: var(--warn); padding: 0.125rem 0; }
.warning-list li::before { content: '⚠ '; }
.error-list li { color: var(--error); padding: 0.125rem 0; }
.error-list li::before { content: '✗ '; }
.verdict { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; margin-top: 2rem; }
.verdict.v-pass { border-color: var(--pass); background: var(--pass-bg); }
.verdict.v-warn { border-color: var(--warn); background: var(--warn-bg); }
.verdict.v-error { border-color: var(--error); background: var(--error-bg); }
.verdict.v-crit { border-color: var(--crit); background: var(--crit-bg); }
.verdict p { font-size: 1.1rem; font-weight: 600; }
footer { text-align: center; margin-top: 2rem; font-size: 0.75rem; color: var(--muted); }
");
    sb.AppendLine("</style>");
    sb.AppendLine("</head>");
    sb.AppendLine("<body>");

    // Header
    sb.AppendLine($"<h1>ednsv &mdash; Email DNS Validation Report</h1>");
    sb.AppendLine($"<div class=\"meta\">Domain: <strong>{e(domain)}</strong> &middot; {e(report.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))} UTC &middot; {report.Duration.TotalSeconds:F1}s</div>");

    // Summary cards
    sb.AppendLine("<div class=\"summary\">");
    sb.AppendLine($"  <div class=\"stat pass\"><div class=\"value\">{report.PassCount}</div><div class=\"label\">Pass</div></div>");
    sb.AppendLine($"  <div class=\"stat warn\"><div class=\"value\">{report.WarningCount}</div><div class=\"label\">Warning</div></div>");
    sb.AppendLine($"  <div class=\"stat error\"><div class=\"value\">{report.ErrorCount}</div><div class=\"label\">Error</div></div>");
    sb.AppendLine($"  <div class=\"stat crit\"><div class=\"value\">{report.CriticalCount}</div><div class=\"label\">Critical</div></div>");
    sb.AppendLine($"  <div class=\"stat\"><div class=\"value\">{report.Results.Count}</div><div class=\"label\">Total</div></div>");
    sb.AppendLine("</div>");

    // Results grouped by category
    var grouped = report.Results.GroupBy(r => r.Category).OrderBy(g => g.Key);

    foreach (var group in grouped)
    {
        sb.AppendLine($"<div class=\"category\">");
        sb.AppendLine($"  <h2>{e(group.Key.ToString())}</h2>");

        foreach (var check in group)
        {
            var sevClass = check.Severity.ToString().ToLowerInvariant();
            var badgeLabel = check.Severity switch
            {
                CheckSeverity.Pass => "PASS",
                CheckSeverity.Info => "INFO",
                CheckSeverity.Warning => "WARN",
                CheckSeverity.Error => "FAIL",
                CheckSeverity.Critical => "CRIT",
                _ => "????"
            };

            sb.AppendLine($"  <div class=\"check sev-{sevClass}\">");
            sb.AppendLine($"    <div class=\"check-header\">");
            sb.AppendLine($"      <span class=\"badge badge-{sevClass}\">{badgeLabel}</span>");
            sb.AppendLine($"      <span class=\"check-name\">{e(check.CheckName)}</span>");
            sb.AppendLine($"    </div>");
            sb.AppendLine($"    <div class=\"check-summary\">{e(check.Summary)}</div>");

            if (check.Details.Any())
            {
                sb.AppendLine($"    <details><summary>Details ({check.Details.Count})</summary>");
                sb.AppendLine($"    <ul class=\"detail-list\">");
                foreach (var detail in check.Details)
                    sb.AppendLine($"      <li>{e(detail)}</li>");
                sb.AppendLine($"    </ul></details>");
            }

            if (check.Warnings.Any())
            {
                sb.AppendLine($"    <ul class=\"warning-list\">");
                foreach (var warning in check.Warnings)
                    sb.AppendLine($"      <li>{e(warning)}</li>");
                sb.AppendLine($"    </ul>");
            }

            if (check.Errors.Any())
            {
                sb.AppendLine($"    <ul class=\"error-list\">");
                foreach (var error in check.Errors)
                    sb.AppendLine($"      <li>{e(error)}</li>");
                sb.AppendLine($"    </ul>");
            }

            sb.AppendLine($"  </div>");
        }

        sb.AppendLine($"</div>");
    }

    // Verdict
    string verdictClass, verdictText;
    if (report.CriticalCount > 0)
    {
        verdictClass = "v-crit";
        verdictText = "CRITICAL issues found that need immediate attention!";
    }
    else if (report.ErrorCount > 0)
    {
        verdictClass = "v-error";
        verdictText = "Errors found that should be addressed.";
    }
    else if (report.WarningCount > 0)
    {
        verdictClass = "v-warn";
        verdictText = "Warnings found — review recommended.";
    }
    else
    {
        verdictClass = "v-pass";
        verdictText = "All checks passed. Email configuration looks good!";
    }

    sb.AppendLine($"<div class=\"verdict {verdictClass}\"><p>{e(verdictText)}</p></div>");
    sb.AppendLine($"<footer>Generated by ednsv on {e(report.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</footer>");

    sb.AppendLine("</body>");
    sb.AppendLine("</html>");

    Console.Write(sb.ToString());
}

static string SeverityLabel(CheckSeverity severity) => severity switch
{
    CheckSeverity.Pass => "Pass",
    CheckSeverity.Info => "Info",
    CheckSeverity.Warning => "Warning",
    CheckSeverity.Error => "Error",
    CheckSeverity.Critical => "Critical",
    _ => "Unknown"
};

/// <summary>
/// Light escaping for Markdown text: only escapes characters that would
/// break rendering in list items and blockquotes. Domain names, selectors,
/// and record values are left intact for readability.
/// </summary>
static string MdText(string text)
{
    return text
        .Replace("<", "&lt;")
        .Replace(">", "&gt;")
        .Replace("|", "\\|");
}
