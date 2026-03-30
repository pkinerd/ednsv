using System.CommandLine;
using System.Text.Json;
using Ednsv.Core;
using Ednsv.Core.Models;
using Spectre.Console;


var domainArg = new Argument<string>("domain", "The domain name to validate (e.g., example.com)");
var jsonOption = new Option<bool>("--json", "Output results as JSON");
var rootCommand = new RootCommand("ednsv - DNS Email Validation Tool")
{
    domainArg,
    jsonOption
};

rootCommand.SetHandler(async (string domain, bool json) =>
{
    domain = domain.Trim().TrimEnd('.').ToLowerInvariant();

    if (string.IsNullOrWhiteSpace(domain))
    {
        AnsiConsole.MarkupLine("[red]Error: Please provide a domain name.[/]");
        return;
    }

    if (json)
    {
        await RunJsonAsync(domain);
    }
    else
    {
        await RunInteractiveAsync(domain);
    }
}, domainArg, jsonOption);

return await rootCommand.InvokeAsync(args);

static async Task RunInteractiveAsync(string domain)
{
    AnsiConsole.Write(new Rule($"[bold blue]ednsv - Email DNS Validation[/]").RuleStyle("blue"));
    AnsiConsole.MarkupLine($"[bold]Domain:[/] {Markup.Escape(domain)}");
    AnsiConsole.MarkupLine($"[bold]Started:[/] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
    AnsiConsole.WriteLine();

    var validator = new DomainValidator();
    ValidationReport? report = null;

    await AnsiConsole.Status()
        .Spinner(Spinner.Known.Dots)
        .SpinnerStyle(Style.Parse("blue"))
        .StartAsync("Running checks...", async statusCtx =>
        {
            validator.OnCheckStarted += name =>
            {
                statusCtx.Status($"[blue]Running:[/] {Markup.Escape(name)}");
            };

            report = await validator.ValidateAsync(domain);
        });

    if (report == null) return;

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

    // Group results by category
    var grouped = report.Results.GroupBy(r => r.Category).OrderBy(g => g.Key);

    foreach (var group in grouped)
    {
        var categoryColor = group.Any(r => r.Severity == CheckSeverity.Critical) ? "red bold" :
                           group.Any(r => r.Severity == CheckSeverity.Error) ? "red" :
                           group.Any(r => r.Severity == CheckSeverity.Warning) ? "yellow" : "green";

        AnsiConsole.Write(new Rule($"[{categoryColor}]{group.Key}[/]").RuleStyle("grey"));

        foreach (var check in group)
        {
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
        }

        AnsiConsole.WriteLine();
    }

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

static async Task RunJsonAsync(string domain)
{
    var validator = new DomainValidator();
    var report = await validator.ValidateAsync(domain);

    var options = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    Console.WriteLine(JsonSerializer.Serialize(report, options));
}
