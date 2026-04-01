using System.CommandLine;
using System.Text;
using System.Text.Json;
using System.Web;
using Ednsv.Core;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Spectre.Console;

var domainArg = new Argument<string[]>("domain", "One or more domain names to validate (e.g., example.com example.org)")
{
    Arity = ArgumentArity.ZeroOrMore
};
var domainsFileOption = new Option<string?>("--domains-file", "Read domains from a file (one domain per line)");
domainsFileOption.AddAlias("-F");
var formatOption = new Option<string>("--format", () => "text", "Output format: text, json, html, markdown");
formatOption.AddAlias("-f");
var outputOption = new Option<string?>("--output", "Write output to file instead of stdout");
outputOption.AddAlias("-o");
var noAxfrOption = new Option<bool>("--no-axfr", "Disable zone transfer (AXFR) testing");
var catchAllOption = new Option<bool>("--catch-all", "Enable catch-all detection (sends probe to random address)");
var openRelayOption = new Option<bool>("--open-relay", "Enable open relay testing (probes MX servers for relay misconfiguration)");
var openResolverOption = new Option<bool>("--open-resolver", "Enable open recursive resolver detection (probes NS servers with external domain)");
var openResolverDomainOption = new Option<string?>("--resolver-test-domain", "Domain to use for open resolver test (default: www.google.com)");
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
    domainsFileOption,
    formatOption,
    outputOption,
    noAxfrOption,
    catchAllOption,
    openRelayOption,
    openResolverOption,
    openResolverDomainOption,
    dkimSelectorsOption,
    listChecksOption,
    verboseOption
};

rootCommand.SetHandler(async (string[] domainArgs, string format, bool noAxfr, bool catchAll, bool openRelay, string[] dkimSelectors, bool listChecks, bool verbose) =>
{
    if (listChecks)
    {
        Console.WriteLine(CheckDescriptions.GetDetailedListing());
        return;
    }

    // Collect domains from positional args
    var domains = new List<string>();
    foreach (var d in domainArgs)
    {
        var trimmed = d.Trim().TrimEnd('.').ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(trimmed))
            domains.Add(trimmed);
    }

    // Collect domains from --domains-file
    var parseResult = rootCommand.Parse(args);
    var domainsFilePath = parseResult.GetValueForOption(domainsFileOption);
    if (!string.IsNullOrEmpty(domainsFilePath))
    {
        if (!File.Exists(domainsFilePath))
        {
            Console.Error.WriteLine($"Error: Domains file not found: {domainsFilePath}");
            return;
        }

        var lines = await File.ReadAllLinesAsync(domainsFilePath);
        foreach (var line in lines)
        {
            // Skip empty lines and comments
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
                continue;
            trimmed = trimmed.TrimEnd('.').ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(trimmed))
                domains.Add(trimmed);
        }
    }

    // Deduplicate while preserving order
    domains = domains.Distinct().ToList();

    if (domains.Count == 0)
    {
        Console.Error.WriteLine("Error: Please provide at least one domain name. Use --help for usage information.");
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

    // Resolve options that exceed SetHandler's 8-param limit
    var enableOpenResolver = parseResult.GetValueForOption(openResolverOption);
    var resolverTestDomain = parseResult.GetValueForOption(openResolverDomainOption);

    var options = new ValidationOptions
    {
        EnableAxfr = !noAxfr,
        EnableCatchAll = catchAll,
        EnableOpenRelay = openRelay,
        EnableOpenResolver = enableOpenResolver,
        OpenResolverTestDomain = resolverTestDomain ?? "www.google.com",
        AdditionalDkimSelectors = parsedSelectors
    };

    // For non-text formats, ensure UTF-8 output encoding (fixes piping/redirect)
    var fmt = format.ToLowerInvariant();
    if (fmt is "json" or "html" or "markdown" or "md")
        Console.OutputEncoding = Encoding.UTF8;

    // Resolve -o / --output: write to file or stdout
    var outputPath = parseResult.GetValueForOption(outputOption);
    TextWriter writer;
    StreamWriter? fileWriter = null;
    if (!string.IsNullOrEmpty(outputPath))
    {
        fileWriter = new StreamWriter(outputPath, false, new UTF8Encoding(false));
        writer = fileWriter;
    }
    else
    {
        writer = Console.Out;
    }

    try
    {
        switch (fmt)
        {
            case "json":
                await RunJsonAsync(domains, options, writer);
                break;
            case "html":
                await RunHtmlAsync(domains, options, writer);
                break;
            case "markdown":
            case "md":
                await RunMarkdownAsync(domains, options, writer);
                break;
            default:
                await RunInteractiveAsync(domains, options, verbose);
                break;
        }
    }
    finally
    {
        if (fileWriter != null)
        {
            await fileWriter.FlushAsync();
            fileWriter.Dispose();
            Console.Error.WriteLine($"Report written to {outputPath}");
        }
    }
}, domainArg, formatOption, noAxfrOption, catchAllOption, openRelayOption, dkimSelectorsOption, listChecksOption, verboseOption);

return await rootCommand.InvokeAsync(args);

static async Task RunInteractiveAsync(List<string> domains, ValidationOptions options, bool verbose = false)
{
    var reports = new List<ValidationReport>();

    for (int i = 0; i < domains.Count; i++)
    {
        var domain = domains[i];

        if (i > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.WriteLine();
        }

        if (domains.Count > 1)
            AnsiConsole.Write(new Rule($"[bold cyan]Domain {i + 1} of {domains.Count}[/]").RuleStyle("cyan"));

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
        reports.Add(report);

        // Per-domain summary
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

    // Multi-domain summary
    if (domains.Count > 1)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold cyan]Multi-Domain Summary[/]").RuleStyle("cyan"));
        AnsiConsole.WriteLine();

        var multiTable = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Domain")
            .AddColumn("[green]Pass[/]")
            .AddColumn("[yellow]Warn[/]")
            .AddColumn("[red]Error[/]")
            .AddColumn("[red bold]Crit[/]")
            .AddColumn("Total")
            .AddColumn("Duration")
            .AddColumn("Verdict");

        int totalPass = 0, totalWarn = 0, totalError = 0, totalCrit = 0, totalChecks = 0;
        var totalDuration = TimeSpan.Zero;

        foreach (var report in reports)
        {
            var verdict = report.CriticalCount > 0 ? "[red bold]CRITICAL[/]" :
                          report.ErrorCount > 0 ? "[red]ERRORS[/]" :
                          report.WarningCount > 0 ? "[yellow]WARNINGS[/]" :
                          "[green]PASS[/]";

            multiTable.AddRow(
                Markup.Escape(report.Domain),
                report.PassCount.ToString(),
                report.WarningCount.ToString(),
                report.ErrorCount.ToString(),
                report.CriticalCount.ToString(),
                report.Results.Count.ToString(),
                $"{report.Duration.TotalSeconds:F1}s",
                verdict
            );

            totalPass += report.PassCount;
            totalWarn += report.WarningCount;
            totalError += report.ErrorCount;
            totalCrit += report.CriticalCount;
            totalChecks += report.Results.Count;
            totalDuration += report.Duration;
        }

        multiTable.AddEmptyRow();
        multiTable.AddRow(
            "[bold]Total[/]",
            $"[bold]{totalPass}[/]",
            $"[bold]{totalWarn}[/]",
            $"[bold]{totalError}[/]",
            $"[bold]{totalCrit}[/]",
            $"[bold]{totalChecks}[/]",
            $"[bold]{totalDuration.TotalSeconds:F1}s[/]",
            ""
        );

        AnsiConsole.Write(multiTable);
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[bold]{reports.Count}[/] domains checked.");
    }
}

static async Task RunJsonAsync(List<string> domains, ValidationOptions options, TextWriter writer)
{
    var reports = new List<ValidationReport>();
    foreach (var domain in domains)
    {
        var validator = new DomainValidator();
        var report = await validator.ValidateAsync(domain, options);
        reports.Add(report);
    }

    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    if (reports.Count == 1)
    {
        await writer.WriteLineAsync(JsonSerializer.Serialize(reports[0], jsonOptions));
    }
    else
    {
        var summary = new
        {
            TotalDomains = reports.Count,
            TotalPass = reports.Sum(r => r.PassCount),
            TotalWarning = reports.Sum(r => r.WarningCount),
            TotalError = reports.Sum(r => r.ErrorCount),
            TotalCritical = reports.Sum(r => r.CriticalCount),
            Timestamp = DateTime.UtcNow,
            Reports = reports
        };
        await writer.WriteLineAsync(JsonSerializer.Serialize(summary, jsonOptions));
    }
}

static async Task RunMarkdownAsync(List<string> domains, ValidationOptions options, TextWriter writer)
{
    var reports = new List<ValidationReport>();
    foreach (var domain in domains)
    {
        var validator = new DomainValidator();
        var report = await validator.ValidateAsync(domain, options);
        reports.Add(report);
    }

    var sb = new StringBuilder();

    sb.AppendLine($"# ednsv — Email DNS Validation Report");
    sb.AppendLine();

    if (reports.Count > 1)
    {
        sb.AppendLine($"**Domains checked:** {reports.Count}");
        sb.AppendLine($"**Date:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();

        // Multi-domain summary table at top
        sb.AppendLine("## Multi-Domain Summary");
        sb.AppendLine();
        sb.AppendLine("| Domain | Pass | Warn | Error | Crit | Total | Duration | Verdict |");
        sb.AppendLine("|--------|-----:|-----:|------:|-----:|------:|---------:|---------|");

        foreach (var report in reports)
        {
            var verdict = report.CriticalCount > 0 ? "\uD83D\uDED1 CRITICAL" :
                          report.ErrorCount > 0 ? "\u274C ERRORS" :
                          report.WarningCount > 0 ? "\u26A0\uFE0F WARNINGS" :
                          "\u2705 PASS";

            sb.AppendLine($"| `{report.Domain}` | {report.PassCount} | {report.WarningCount} | {report.ErrorCount} | {report.CriticalCount} | {report.Results.Count} | {report.Duration.TotalSeconds:F1}s | {verdict} |");
        }

        var totalDuration = reports.Aggregate(TimeSpan.Zero, (acc, r) => acc + r.Duration);
        sb.AppendLine($"| **Total** | **{reports.Sum(r => r.PassCount)}** | **{reports.Sum(r => r.WarningCount)}** | **{reports.Sum(r => r.ErrorCount)}** | **{reports.Sum(r => r.CriticalCount)}** | **{reports.Sum(r => r.Results.Count)}** | **{totalDuration.TotalSeconds:F1}s** | |");
        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine();
    }

    // Per-domain reports
    foreach (var report in reports)
    {
        if (reports.Count > 1)
            sb.AppendLine($"## Domain: `{report.Domain}`");
        else
            sb.AppendLine();

        sb.AppendLine($"**Domain:** `{report.Domain}`");
        sb.AppendLine($"**Date:** {report.Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"**Duration:** {report.Duration.TotalSeconds:F1}s");
        sb.AppendLine();

        // Summary table
        sb.AppendLine(reports.Count > 1 ? "### Summary" : "## Summary");
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

        sb.AppendLine(reports.Count > 1 ? "### Results" : "## Results");
        sb.AppendLine();

        foreach (var group in grouped)
        {
            sb.AppendLine(reports.Count > 1 ? $"#### {group.Key}" : $"### {group.Key}");
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
        sb.AppendLine(reports.Count > 1 ? "### Verdict" : "## Verdict");
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

        if (reports.Count > 1)
        {
            sb.AppendLine("---");
            sb.AppendLine();
        }
    }

    sb.AppendLine("---");
    sb.AppendLine($"*Generated by [ednsv](https://github.com/pkinerd/ednsv) on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC*");

    await writer.WriteAsync(sb.ToString());
}

static async Task RunHtmlAsync(List<string> domains, ValidationOptions options, TextWriter writer)
{
    var reports = new List<ValidationReport>();
    foreach (var domain in domains)
    {
        var validator = new DomainValidator();
        var report = await validator.ValidateAsync(domain, options);
        reports.Add(report);
    }

    var sb = new StringBuilder();
    var e = (string s) => HttpUtility.HtmlEncode(s);

    var title = reports.Count == 1
        ? $"ednsv Report — {e(reports[0].Domain)}"
        : $"ednsv Report — {reports.Count} Domains";

    sb.AppendLine("<!DOCTYPE html>");
    sb.AppendLine("<html lang=\"en\">");
    sb.AppendLine("<head>");
    sb.AppendLine("<meta charset=\"UTF-8\">");
    sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
    sb.AppendLine($"<title>{title}</title>");
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
h2.domain-header { font-size: 1.3rem; margin-top: 2rem; margin-bottom: 0.5rem; padding-top: 1.5rem; border-top: 3px solid var(--info); }
.meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 1.5rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.75rem; margin-bottom: 2rem; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
.stat .value { font-size: 1.75rem; font-weight: 700; }
.stat .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
.stat.pass .value { color: var(--pass); }
.stat.warn .value { color: var(--warn); }
.stat.error .value { color: var(--error); }
.stat.crit .value { color: var(--crit); }
.multi-summary { margin-bottom: 2rem; }
.multi-summary table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.multi-summary th, .multi-summary td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
.multi-summary th { background: var(--bg); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; color: var(--muted); }
.multi-summary td.num { text-align: right; font-variant-numeric: tabular-nums; }
.multi-summary tr:last-child td { border-bottom: none; font-weight: 600; }
.multi-summary .verdict-pass { color: var(--pass); }
.multi-summary .verdict-warn { color: var(--warn); }
.multi-summary .verdict-error { color: var(--error); }
.multi-summary .verdict-crit { color: var(--crit); font-weight: 700; }
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

    if (reports.Count > 1)
    {
        sb.AppendLine($"<div class=\"meta\">{reports.Count} domains &middot; {e(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</div>");

        // Multi-domain summary table at top
        sb.AppendLine("<div class=\"multi-summary\">");
        sb.AppendLine("<h2>Summary</h2>");
        sb.AppendLine("<table>");
        sb.AppendLine("<thead><tr><th>Domain</th><th>Pass</th><th>Warn</th><th>Error</th><th>Crit</th><th>Total</th><th>Duration</th><th>Verdict</th></tr></thead>");
        sb.AppendLine("<tbody>");

        int totalPass = 0, totalWarn = 0, totalError = 0, totalCrit = 0, totalChecks = 0;
        var totalDuration = TimeSpan.Zero;

        foreach (var report in reports)
        {
            string verdictClass, verdictLabel;
            if (report.CriticalCount > 0) { verdictClass = "verdict-crit"; verdictLabel = "CRITICAL"; }
            else if (report.ErrorCount > 0) { verdictClass = "verdict-error"; verdictLabel = "ERRORS"; }
            else if (report.WarningCount > 0) { verdictClass = "verdict-warn"; verdictLabel = "WARNINGS"; }
            else { verdictClass = "verdict-pass"; verdictLabel = "PASS"; }

            sb.AppendLine($"<tr><td>{e(report.Domain)}</td><td class=\"num\">{report.PassCount}</td><td class=\"num\">{report.WarningCount}</td><td class=\"num\">{report.ErrorCount}</td><td class=\"num\">{report.CriticalCount}</td><td class=\"num\">{report.Results.Count}</td><td class=\"num\">{report.Duration.TotalSeconds:F1}s</td><td class=\"{verdictClass}\">{verdictLabel}</td></tr>");

            totalPass += report.PassCount;
            totalWarn += report.WarningCount;
            totalError += report.ErrorCount;
            totalCrit += report.CriticalCount;
            totalChecks += report.Results.Count;
            totalDuration += report.Duration;
        }

        sb.AppendLine($"<tr><td><strong>Total</strong></td><td class=\"num\">{totalPass}</td><td class=\"num\">{totalWarn}</td><td class=\"num\">{totalError}</td><td class=\"num\">{totalCrit}</td><td class=\"num\">{totalChecks}</td><td class=\"num\">{totalDuration.TotalSeconds:F1}s</td><td></td></tr>");
        sb.AppendLine("</tbody></table>");
        sb.AppendLine("</div>");
    }

    // Per-domain reports
    foreach (var report in reports)
    {
        if (reports.Count > 1)
            sb.AppendLine($"<h2 class=\"domain-header\">{e(report.Domain)}</h2>");

        sb.AppendLine($"<div class=\"meta\">Domain: <strong>{e(report.Domain)}</strong> &middot; {e(report.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"))} UTC &middot; {report.Duration.TotalSeconds:F1}s</div>");

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
                    sb.AppendLine($"    <ul class=\"detail-list\">");
                    foreach (var detail in check.Details)
                        sb.AppendLine($"      <li>{e(detail)}</li>");
                    sb.AppendLine($"    </ul>");
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

        sb.AppendLine($"<div class=\"verdict {verdictClass}\"><p>{e(report.Domain)}: {e(verdictText)}</p></div>");
    }

    sb.AppendLine($"<footer>Generated by ednsv on {e(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</footer>");

    sb.AppendLine("</body>");
    sb.AppendLine("</html>");

    await writer.WriteAsync(sb.ToString());
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
