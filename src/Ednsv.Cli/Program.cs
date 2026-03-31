using System.CommandLine;
using System.Text.Json;
using Ednsv.Core;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Spectre.Console;

var domainArg = new Argument<string>("domain", "The domain name to validate (e.g., example.com)");
var jsonOption = new Option<bool>("--json", "Output results as JSON");
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
    jsonOption,
    noAxfrOption,
    catchAllOption,
    openRelayOption,
    dkimSelectorsOption,
    listChecksOption,
    verboseOption
};

// Make domain optional when --list-checks is used
domainArg.SetDefaultValue("");

rootCommand.SetHandler(async (string domain, bool json, bool noAxfr, bool catchAll, bool openRelay, string[] dkimSelectors, bool listChecks, bool verbose) =>
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

    if (json)
    {
        await RunJsonAsync(domain, options);
    }
    else
    {
        await RunInteractiveAsync(domain, options, verbose);
    }
}, domainArg, jsonOption, noAxfrOption, catchAllOption, openRelayOption, dkimSelectorsOption, listChecksOption, verboseOption);

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
