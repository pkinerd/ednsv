using System.CommandLine;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Web;
using Ednsv.Core;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;
using Spectre.Console;

var domainArg = new Argument<string[]>("domain", "One or more domain names to validate (e.g., example.com example.org)")
{
    Arity = ArgumentArity.ZeroOrMore
};
var domainsFileOption = new Option<string?>("--domains-file", "Read domains from a file. Plain text: one domain per line. CSV: uses 'domain' or 'fqdn' column; extra columns are included in the index/summary. A numeric 'total messages' (or 'messages'/'total') column is used for impact-based sorting");
domainsFileOption.AddAlias("-F");
var formatOption = new Option<string>("--format", () => "text", "Output format: text, json, html, markdown");
formatOption.AddAlias("-f");
var outputOption = new Option<string?>("--output", "Write output to file instead of stdout");
outputOption.AddAlias("-o");
var outputDirOption = new Option<string?>("--output-dir", "Write per-domain reports to separate files in this directory, plus an index and cross-domain issues file");
outputDirOption.AddAlias("-D");
var axfrOption = new Option<bool>("--axfr", "Enable zone transfer (AXFR) testing");
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
var dnsServerOption = new Option<string?>("--dns-server", "DNS server(s) for lookups (IP address, comma-separated for multiple; default: Google Public DNS). Multiple servers are load-balanced via round-robin");
dnsServerOption.AddAlias("-s");
var privateDnsblOption = new Option<bool>("--private-dnsbl", "Include blocklists that require a private/registered DNS resolver (Spamhaus, Barracuda, SURBL, URIBL). Off by default as they return false positives via public resolvers");
var cacheOption = new Option<string?>("--cache", "Persist probe cache to a directory between runs. Optionally specify a directory path (default: .ednsv-cache/ in current directory)");
cacheOption.Arity = ArgumentArity.ZeroOrOne;
cacheOption.AddAlias("-c");
var cacheTtlOption = new Option<int>("--cache-ttl", () => 24, "Cache time-to-live in hours (default: 24)");
var retryOption = new Option<bool>("--retry", "Double retry counts for more persistent probing (useful for unreliable networks)");
var retryErrorsOption = new Option<bool>("--retry-errors", "When using --cache, retry checks that previously resulted in errors or warnings while keeping successful cached results");
var recheckOption = new Option<string?>("--recheck", "Revalidate checks that previously reported issues at the specified severity or above (warning, error, critical). Only clears stale cached probes — fresh results from earlier in the same run are preserved.");
var listChecksOption = new Option<bool>("--list-checks", "Show detailed descriptions of all checks performed");
var verboseOption = new Option<bool>("--verbose", "Show why each check category matters alongside results");
var liveIndexOption = new Option<bool>("--live-index", "Rewrite the index and issues files after each domain completes (use with --output-dir)");
var rootCommand = new RootCommand("ednsv - DNS Email Validation Tool" + CheckDescriptions.GetHelpSummary())
{
    domainArg,
    domainsFileOption,
    formatOption,
    outputOption,
    outputDirOption,
    axfrOption,
    catchAllOption,
    openRelayOption,
    openResolverOption,
    openResolverDomainOption,
    dkimSelectorsOption,
    dnsServerOption,
    privateDnsblOption,
    cacheOption,
    cacheTtlOption,
    retryOption,
    retryErrorsOption,
    recheckOption,
    listChecksOption,
    verboseOption,
    liveIndexOption
};

rootCommand.SetHandler(async (string[] domainArgs, string format, bool axfr, bool catchAll, bool openRelay, string[] dkimSelectors, bool listChecks, bool verbose) =>
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

    // Collect domains from --domains-file (plain text or CSV)
    var parseResult = rootCommand.Parse(args);
    var domainsFilePath = parseResult.GetValueForOption(domainsFileOption);
    Dictionary<string, DomainMeta>? domainMeta = null;
    List<string>? csvExtraColumns = null;
    string? csvVolumeColumn = null;

    if (!string.IsNullOrEmpty(domainsFilePath))
    {
        if (!File.Exists(domainsFilePath))
        {
            Console.Error.WriteLine($"Error: Domains file not found: {domainsFilePath}");
            return;
        }

        var lines = await File.ReadAllLinesAsync(domainsFilePath);

        if (domainsFilePath.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
        {
            // CSV mode: parse header, extract domain column + metadata
            var (csvDomains, meta, extraCols, volCol) = ParseCsvDomainsFile(lines);
            if (csvDomains.Count == 0 && lines.Length > 1)
            {
                // ParseCsvDomainsFile already printed an error if header was bad
                return;
            }
            domains.AddRange(csvDomains);
            domainMeta = meta;
            csvExtraColumns = extraCols;
            csvVolumeColumn = volCol;
        }
        else
        {
            // Plain text: one domain per line
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
                    continue;
                trimmed = trimmed.TrimEnd('.').ToLowerInvariant();
                if (!string.IsNullOrWhiteSpace(trimmed))
                    domains.Add(trimmed);
            }
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
    var enablePrivateDnsbl = parseResult.GetValueForOption(privateDnsblOption);
    var dnsServerRaw = parseResult.GetValueForOption(dnsServerOption);

    // Parse custom DNS server(s)
    List<IPAddress>? dnsServers = null;
    if (!string.IsNullOrEmpty(dnsServerRaw))
    {
        dnsServers = new List<IPAddress>();
        foreach (var part in dnsServerRaw.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            if (!IPAddress.TryParse(trimmed, out var addr))
            {
                Console.Error.WriteLine($"Error: Invalid DNS server IP address: {trimmed}");
                return;
            }
            dnsServers.Add(addr);
        }
    }

    var options = new ValidationOptions
    {
        EnableAxfr = axfr,
        EnableCatchAll = catchAll,
        EnableOpenRelay = openRelay,
        EnableOpenResolver = enableOpenResolver,
        OpenResolverTestDomain = resolverTestDomain ?? "www.google.com",
        AdditionalDkimSelectors = parsedSelectors,
        EnablePrivateDnsbl = enablePrivateDnsbl
    };

    // --retry: double all retry counts
    var enableRetry = parseResult.GetValueForOption(retryOption);
    if (enableRetry)
        DnsResolverService.DoubleRetries();

    // --cache: resolve cache directory path
    var cacheRaw = parseResult.GetValueForOption(cacheOption);
    var cacheTtlHours = parseResult.GetValueForOption(cacheTtlOption);
    // --cache with no value defaults to ".ednsv-cache"; --cache <path> uses the given path
    // The option is string? — null means not specified, empty means specified without value
    string? cachePath = null;
    if (parseResult.FindResultFor(cacheOption) is not null)
        cachePath = string.IsNullOrEmpty(cacheRaw) ? ".ednsv-cache" : cacheRaw;
    var retryErrors = parseResult.GetValueForOption(retryErrorsOption);

    // --recheck: parse severity threshold
    var recheckRaw = parseResult.GetValueForOption(recheckOption);
    CheckSeverity? recheckSeverity = null;
    if (recheckRaw != null)
    {
        recheckSeverity = recheckRaw.ToLowerInvariant() switch
        {
            "warning" or "warn" => CheckSeverity.Warning,
            "error" or "err" => CheckSeverity.Error,
            "critical" or "crit" => CheckSeverity.Critical,
            _ => null
        };
        if (recheckSeverity == null)
        {
            Console.Error.WriteLine($"Invalid --recheck value '{recheckRaw}'. Use: warning, error, or critical");
            return;
        }
        if (cachePath == null)
        {
            Console.Error.WriteLine("--recheck requires --cache to be specified");
            return;
        }
    }

    // For non-text formats, ensure UTF-8 output encoding (fixes piping/redirect)
    var fmt = format.ToLowerInvariant();
    if (fmt is "json" or "html" or "markdown" or "md")
        Console.OutputEncoding = Encoding.UTF8;

    // Resolve -o / --output and -D / --output-dir
    var outputPath = parseResult.GetValueForOption(outputOption);
    var outputDir = parseResult.GetValueForOption(outputDirOption);

    if (!string.IsNullOrEmpty(outputPath) && !string.IsNullOrEmpty(outputDir))
    {
        Console.Error.WriteLine("Error: --output and --output-dir are mutually exclusive.");
        return;
    }

    // --output-dir mode: write each domain to a separate file + index
    if (!string.IsNullOrEmpty(outputDir))
    {
        if (fmt is "text" or "")
        {
            Console.Error.WriteLine("Error: --output-dir requires --format (json, html, or markdown).");
            return;
        }

        var liveIndex = parseResult.GetValueForOption(liveIndexOption);
        Directory.CreateDirectory(outputDir);
        await RunOutputDirAsync(domains, options, fmt, outputDir, verbose, liveIndex, dnsServers, domainMeta, csvExtraColumns, csvVolumeColumn, cachePath, cacheTtlHours, retryErrors, recheckSeverity);
        return;
    }

    // Single-file or stdout mode
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
        // Show progressive console output when writing formatted results to a file
        var showProgress = fileWriter != null;

        switch (fmt)
        {
            case "json":
                await RunJsonAsync(domains, options, writer, showProgress, verbose, dnsServers: dnsServers, cachePath: cachePath, cacheTtlHours: cacheTtlHours, retryErrors: retryErrors, recheckSeverity: recheckSeverity);
                break;
            case "html":
                await RunHtmlAsync(domains, options, writer, showProgress, verbose, dnsServers: dnsServers, cachePath: cachePath, cacheTtlHours: cacheTtlHours, retryErrors: retryErrors, recheckSeverity: recheckSeverity);
                break;
            case "markdown":
            case "md":
                await RunMarkdownAsync(domains, options, writer, showProgress, verbose, dnsServers: dnsServers, cachePath: cachePath, cacheTtlHours: cacheTtlHours, retryErrors: retryErrors, recheckSeverity: recheckSeverity);
                break;
            default:
                await RunInteractiveAsync(domains, options, verbose, dnsServers, cachePath, cacheTtlHours, retryErrors, recheckSeverity);
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
}, domainArg, formatOption, axfrOption, catchAllOption, openRelayOption, dkimSelectorsOption, listChecksOption, verboseOption);

return await rootCommand.InvokeAsync(args);

/// <summary>
/// Parses a CSV file, returning the list of domains plus per-domain metadata.
/// Looks for a "domain" or "fqdn" column (case-insensitive) for the domain.
/// Detects a volume column matching "total messages", "totalmessages", "messages", or "total".
/// </summary>
static (List<string> domains, Dictionary<string, DomainMeta> meta, List<string> extraColumns, string? volumeColumn)
    ParseCsvDomainsFile(string[] lines)
{
    var domains = new List<string>();
    var meta = new Dictionary<string, DomainMeta>(StringComparer.OrdinalIgnoreCase);

    if (lines.Length == 0)
        return (domains, meta, new List<string>(), null);

    // Parse header
    var headers = CsvSplitLine(lines[0]);
    int domainCol = -1;
    int volumeCol = -1;
    string? volumeHeader = null;

    for (int c = 0; c < headers.Count; c++)
    {
        var h = headers[c].Trim();
        var hLower = h.ToLowerInvariant();
        if (domainCol < 0 && hLower is "domain" or "fqdn")
            domainCol = c;
        if (volumeCol < 0 && hLower is "total messages" or "totalmessages" or "messages" or "total")
        {
            volumeCol = c;
            volumeHeader = h;
        }
    }

    if (domainCol < 0)
    {
        Console.Error.WriteLine("Error: CSV file must have a 'domain' or 'fqdn' column header.");
        return (domains, meta, new List<string>(), null);
    }

    // Build list of extra column headers (everything except the domain column)
    var extraColumns = new List<string>();
    for (int c = 0; c < headers.Count; c++)
    {
        if (c != domainCol)
            extraColumns.Add(headers[c].Trim());
    }

    // Parse data rows
    for (int i = 1; i < lines.Length; i++)
    {
        var line = lines[i].Trim();
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
            continue;

        var fields = CsvSplitLine(line);
        if (fields.Count <= domainCol)
            continue;

        var domain = fields[domainCol].Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(domain))
            continue;

        // Collect extra columns
        var cols = new Dictionary<string, string>();
        for (int c = 0; c < headers.Count; c++)
        {
            if (c == domainCol) continue;
            var val = c < fields.Count ? fields[c].Trim() : "";
            cols[headers[c].Trim()] = val;
        }

        long volume = 0;
        if (volumeCol >= 0 && volumeCol < fields.Count)
            long.TryParse(fields[volumeCol].Trim().Replace(",", ""), out volume);

        if (!meta.ContainsKey(domain))
        {
            domains.Add(domain);
            meta[domain] = new DomainMeta(cols, volume);
        }
    }

    return (domains, meta, extraColumns, volumeHeader);
}

/// <summary>
/// Splits a CSV line respecting quoted fields. Handles double-quote escaping.
/// </summary>
static List<string> CsvSplitLine(string line)
{
    var fields = new List<string>();
    var current = new StringBuilder();
    bool inQuotes = false;

    for (int i = 0; i < line.Length; i++)
    {
        var c = line[i];
        if (inQuotes)
        {
            if (c == '"')
            {
                if (i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++; // skip escaped quote
                }
                else
                {
                    inQuotes = false;
                }
            }
            else
            {
                current.Append(c);
            }
        }
        else
        {
            if (c == '"')
            {
                inQuotes = true;
            }
            else if (c == ',')
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }
    }
    fields.Add(current.ToString());
    return fields;
}

static async Task RunInteractiveAsync(List<string> domains, ValidationOptions options, bool verbose = false, List<IPAddress>? dnsServers = null, string? cachePath = null, int cacheTtlHours = 24, bool retryErrors = false, CheckSeverity? recheckSeverity = null)
{
    var reports = new List<ValidationReport>();
    // Share services across domains so cached lookups are reused
    var dns = new DnsResolverService(dnsServers);
    var smtp = new SmtpProbeService();
    var http = new HttpProbeService();

    // Load disk cache if specified
    if (cachePath != null)
    {
        var cacheResult = await DiskCacheService.LoadAsync(cachePath, TimeSpan.FromHours(cacheTtlHours), smtp, http, dns, retryErrors);
        if (cacheResult != null)
            AnsiConsole.MarkupLine($"[dim]Loaded cache ({cacheResult.Total} entries, {cacheResult.Age.TotalMinutes:F0}m old): {cacheResult.DnsQueries} DNS, {cacheResult.SmtpProbes} SMTP, {cacheResult.RcptProbes} RCPT, {cacheResult.HttpRequests} HTTP, {cacheResult.PtrLookups} PTR, {cacheResult.PortProbes} port[/]");
    }

    // Load previous domain results for --recheck
    Dictionary<string, DomainResultSummary>? previousResults = null;
    if (recheckSeverity != null && cachePath != null)
        previousResults = await DiskCacheService.LoadDomainResultsAsync(cachePath);

    // Periodic background flush (every 60s) + final save on dispose
    await using var cacheFlusher = cachePath != null
        ? new BackgroundCacheFlusher(cachePath, smtp, http, dns, TimeSpan.FromSeconds(60))
        : null;

    for (int i = 0; i < domains.Count; i++)
    {
        var domain = domains[i];

        // --recheck: clear stale cached probes for domains with previous issues
        if (recheckSeverity != null && previousResults != null &&
            previousResults.TryGetValue(domain.ToLowerInvariant(), out var prevResult))
        {
            var deps = RecheckHelper.GetDependenciesForIssues(prevResult, recheckSeverity.Value);
            if (deps != RecheckHelper.CacheDep.None)
            {
                RecheckHelper.ClearImportedEntriesForDomain(domain, deps, dns, smtp, http);
                AnsiConsole.MarkupLine($"[dim]Recheck: cleared stale cache for {Markup.Escape(domain)} ({deps})[/]");
            }
        }

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
        if (dnsServers?.Count > 0)
            AnsiConsole.MarkupLine($"[grey]DNS server: {Markup.Escape(string.Join(", ", dnsServers))}[/]");
        if (options.EnableAxfr)
            AnsiConsole.MarkupLine("[grey]AXFR testing enabled[/]");
        if (verbose)
            AnsiConsole.MarkupLine("[grey]Verbose mode: showing check descriptions[/]");
        AnsiConsole.WriteLine();

        var validator = new DomainValidator(dns, smtp, http);
        CheckCategory? currentCategory = null;
        var shownDescriptions = new HashSet<string>();
        var showingRunningLine = false;
        var slowChecks = new List<(string Name, TimeSpan Duration)>();
        var checkTimings = new Dictionary<string, TimeSpan>();
        var checkDnsHitsBefore = 0;
        var checkDnsMissesBefore = 0;

        // Track per-check timing
        validator.OnCheckTiming += (name, elapsed) =>
        {
            checkTimings[name] = elapsed;
            if (name == "Prefetch")
                AnsiConsole.MarkupLine($"  [dim]Prefetch: {elapsed.TotalSeconds:F1}s (dns:{dns.CacheHits}h/{dns.CacheMisses}m)[/]");
            else if (elapsed.TotalSeconds >= 1.0)
                slowChecks.Add((name, elapsed));
        };

        // Display results progressively as each check completes
        validator.OnCheckStarted += name =>
        {
            // Snapshot DNS counters before this check
            checkDnsHitsBefore = dns.CacheHits;
            checkDnsMissesBefore = dns.CacheMisses;
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

            // Build timing suffix
            var timingSuffix = "";
            if (checkTimings.TryGetValue(name, out var elapsed))
            {
                var hits = dns.CacheHits - checkDnsHitsBefore;
                var misses = dns.CacheMisses - checkDnsMissesBefore;
                timingSuffix = $" [dim]({elapsed.TotalSeconds:F1}s, dns:{hits}h/{misses}m)[/]";
            }

            AnsiConsole.MarkupLine($"  {icon} [bold]{Markup.Escape(check.CheckName)}[/]: {Markup.Escape(check.Summary)}{timingSuffix}");

            foreach (var detail in check.Details)
                AnsiConsole.MarkupLine($"       [grey]{Markup.Escape(detail)}[/]");

            foreach (var warning in check.Warnings)
                AnsiConsole.MarkupLine($"       [yellow]⚠ {Markup.Escape(warning)}[/]");

            foreach (var error in check.Errors)
                AnsiConsole.MarkupLine($"       [red]✗ {Markup.Escape(error)}[/]");
        };

        var report = await validator.ValidateAsync(domain, options);
        reports.Add(report);

        // Save domain result + flush cache to disk (non-blocking)
        if (cachePath != null)
            _ = DiskCacheService.SaveDomainResultAsync(cachePath, domain, BuildDomainResultSummary(report));
        cacheFlusher?.RequestFlush();

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

        // Show cache diagnostics and slow checks in verbose mode
        if (verbose)
        {
            AnsiConsole.MarkupLine($"[dim]DNS cache: {dns.CacheHits} hits, {dns.CacheMisses} misses ({dns.CacheSize} entries)[/]");
            if (slowChecks.Count > 0)
            {
                AnsiConsole.MarkupLine($"[dim]Slow checks (≥1s):[/]");
                foreach (var (name, duration) in slowChecks.OrderByDescending(x => x.Duration))
                    AnsiConsole.MarkupLine($"[dim]  {duration.TotalSeconds,5:F1}s  {Markup.Escape(name)}[/]");
            }
        }

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

    // Final cache save handled by cacheFlusher.DisposeAsync()
}

/// <summary>
/// Validates all domains, optionally showing progressive console output.
/// Used by non-text formatters when writing to a file so the user can
/// monitor progress while the formatted report is being built.
/// When verbose is true, shows the full interactive-style output with
/// category headers, details, warnings, and errors. When false, shows
/// a compact one-line-per-check view.
/// </summary>
static async Task<List<ValidationReport>> ValidateAllAsync(List<string> domains, ValidationOptions options, bool showProgress, bool verbose = false, List<IPAddress>? dnsServers = null, string? cachePath = null, int cacheTtlHours = 24, bool retryErrors = false, CheckSeverity? recheckSeverity = null)
{
    var reports = new List<ValidationReport>();
    // Share services across domains so cached lookups are reused
    var dns = new DnsResolverService(dnsServers);
    var smtp = new SmtpProbeService();
    var http = new HttpProbeService();

    // Load disk cache if specified
    if (cachePath != null)
    {
        var cacheResult = await DiskCacheService.LoadAsync(cachePath, TimeSpan.FromHours(cacheTtlHours), smtp, http, dns, retryErrors);
        if (cacheResult != null && showProgress)
            AnsiConsole.MarkupLine($"[dim]Loaded cache ({cacheResult.Total} entries, {cacheResult.Age.TotalMinutes:F0}m old): {cacheResult.DnsQueries} DNS, {cacheResult.SmtpProbes} SMTP, {cacheResult.RcptProbes} RCPT, {cacheResult.HttpRequests} HTTP, {cacheResult.PtrLookups} PTR, {cacheResult.PortProbes} port[/]");
    }

    // Periodic background flush (every 60s) + final save on dispose
    await using var cacheFlusher = cachePath != null
        ? new BackgroundCacheFlusher(cachePath, smtp, http, dns, TimeSpan.FromSeconds(60))
        : null;

    // Load previous domain results for --recheck
    Dictionary<string, DomainResultSummary>? previousResults2 = null;
    if (recheckSeverity != null && cachePath != null)
        previousResults2 = await DiskCacheService.LoadDomainResultsAsync(cachePath);

    for (int i = 0; i < domains.Count; i++)
    {
        var domain = domains[i];
        var validator = new DomainValidator(dns, smtp, http);

        // --recheck: clear stale cached probes for domains with previous issues
        if (recheckSeverity != null && previousResults2 != null &&
            previousResults2.TryGetValue(domain.ToLowerInvariant(), out var prevResult2))
        {
            var deps = RecheckHelper.GetDependenciesForIssues(prevResult2, recheckSeverity.Value);
            if (deps != RecheckHelper.CacheDep.None)
            {
                RecheckHelper.ClearImportedEntriesForDomain(domain, deps, dns, smtp, http);
                if (showProgress)
                    AnsiConsole.MarkupLine($"[dim]Recheck: cleared stale cache for {Markup.Escape(domain)} ({deps})[/]");
            }
        }

        if (showProgress)
        {
            if (i > 0)
            {
                AnsiConsole.WriteLine();
                if (verbose) AnsiConsole.WriteLine();
            }

            if (domains.Count > 1)
            {
                if (verbose)
                    AnsiConsole.Write(new Rule($"[bold cyan]Domain {i + 1} of {domains.Count}[/]").RuleStyle("cyan"));
                else
                    AnsiConsole.MarkupLine($"[bold cyan]Domain {i + 1} of {domains.Count}:[/] [bold]{Markup.Escape(domain)}[/]");
            }

            if (verbose)
            {
                AnsiConsole.Write(new Rule($"[bold blue]ednsv - Email DNS Validation[/]").RuleStyle("blue"));
                AnsiConsole.MarkupLine($"[bold]Domain:[/] {Markup.Escape(domain)}");
                AnsiConsole.MarkupLine($"[bold]Started:[/] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
                if (!options.EnableAxfr)
                    AnsiConsole.MarkupLine("[grey]AXFR testing disabled[/]");
                AnsiConsole.WriteLine();
            }
            else if (domains.Count <= 1)
            {
                AnsiConsole.MarkupLine($"[bold]Domain:[/] {Markup.Escape(domain)}");
            }

            var showingRunningLine = false;
            CheckCategory? currentCategory = null;
            var shownDescriptions = new HashSet<string>();
            var checkTimings = new Dictionary<string, TimeSpan>();
            var checkDnsHitsBefore = 0;
            var checkDnsMissesBefore = 0;

            validator.OnCheckTiming += (name, elapsed) =>
            {
                checkTimings[name] = elapsed;
            };

            validator.OnCheckStarted += name =>
            {
                checkDnsHitsBefore = dns.CacheHits;
                checkDnsMissesBefore = dns.CacheMisses;
                AnsiConsole.MarkupLine($"  [dim blue]● Running: {Markup.Escape(name)}…[/]");
                showingRunningLine = true;
            };

            validator.OnCheckCompleted += (name, check) =>
            {
                if (showingRunningLine)
                {
                    AnsiConsole.Write("\x1b[1A\x1b[2K");
                    showingRunningLine = false;
                }

                if (verbose)
                {
                    // Print category header when category changes
                    if (check.Category != currentCategory)
                    {
                        if (currentCategory != null)
                            AnsiConsole.WriteLine();

                        currentCategory = check.Category;
                        AnsiConsole.Write(new Rule($"[bold]{check.Category}[/]").RuleStyle("grey"));

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

                var timingSuffix = "";
                if (checkTimings.TryGetValue(name, out var elapsed))
                {
                    var hits = dns.CacheHits - checkDnsHitsBefore;
                    var misses = dns.CacheMisses - checkDnsMissesBefore;
                    timingSuffix = $" [dim]({elapsed.TotalSeconds:F1}s, dns:{hits}h/{misses}m)[/]";
                }

                AnsiConsole.MarkupLine($"  {icon} [bold]{Markup.Escape(check.CheckName)}[/]: {Markup.Escape(check.Summary)}{timingSuffix}");

                if (verbose)
                {
                    foreach (var detail in check.Details)
                        AnsiConsole.MarkupLine($"       [grey]{Markup.Escape(detail)}[/]");

                    foreach (var warning in check.Warnings)
                        AnsiConsole.MarkupLine($"       [yellow]⚠ {Markup.Escape(warning)}[/]");

                    foreach (var error in check.Errors)
                        AnsiConsole.MarkupLine($"       [red]✗ {Markup.Escape(error)}[/]");
                }
            };
        }

        var report = await validator.ValidateAsync(domain, options);
        reports.Add(report);

        // Save domain result + flush cache to disk (non-blocking)
        if (cachePath != null)
            _ = DiskCacheService.SaveDomainResultAsync(cachePath, domain, BuildDomainResultSummary(report));
        cacheFlusher?.RequestFlush();

        if (showProgress)
        {
            if (verbose)
            {
                // Full summary table matching interactive output
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
                summaryTable.AddRow("[dim]DNS cache[/]", $"{dns.CacheHits} hits / {dns.CacheMisses} misses");

                AnsiConsole.Write(summaryTable);
                AnsiConsole.WriteLine();

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
            else
            {
                var verdict = report.CriticalCount > 0 ? "[red bold]CRITICAL[/]" :
                              report.ErrorCount > 0 ? "[red]ERRORS[/]" :
                              report.WarningCount > 0 ? "[yellow]WARNINGS[/]" :
                              "[green]PASS[/]";
                AnsiConsole.MarkupLine($"  → {verdict} ({report.PassCount} pass, {report.WarningCount} warn, {report.ErrorCount} err, {report.CriticalCount} crit) in {report.Duration.TotalSeconds:F1}s");
                if (verbose)
                    AnsiConsole.MarkupLine($"     [dim]DNS cache: {dns.CacheHits} hits, {dns.CacheMisses} misses[/]");
            }
        }
    }

    if (showProgress && domains.Count > 1)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine($"[bold]{reports.Count}[/] domains validated.");
    }

    // Final cache save handled by cacheFlusher.DisposeAsync()
    return reports;
}

/// <summary>
/// Writes each domain report to a separate file in the output directory,
/// with progressive console output, then generates an index file with
/// the summary and links to each domain report.
/// </summary>
static async Task RunOutputDirAsync(List<string> domains, ValidationOptions options, string fmt, string outputDir, bool verbose, bool liveIndex = false, List<IPAddress>? dnsServers = null, Dictionary<string, DomainMeta>? domainMeta = null, List<string>? csvExtraColumns = null, string? csvVolumeColumn = null, string? cachePath = null, int cacheTtlHours = 24, bool retryErrors = false, CheckSeverity? recheckSeverity = null)
{
    var ext = fmt switch { "json" => "json", "html" => "html", "markdown" or "md" => "md", _ => fmt };
    var reports = new List<ValidationReport>();

    // Share services across domains so cached lookups are reused
    var dns = new DnsResolverService(dnsServers);
    var smtp = new SmtpProbeService();
    var http = new HttpProbeService();

    // Load disk cache if specified
    if (cachePath != null)
    {
        var cacheResult = await DiskCacheService.LoadAsync(cachePath, TimeSpan.FromHours(cacheTtlHours), smtp, http, dns, retryErrors);
        if (cacheResult != null)
            AnsiConsole.MarkupLine($"[dim]Loaded cache ({cacheResult.Total} entries, {cacheResult.Age.TotalMinutes:F0}m old): {cacheResult.DnsQueries} DNS, {cacheResult.SmtpProbes} SMTP, {cacheResult.RcptProbes} RCPT, {cacheResult.HttpRequests} HTTP, {cacheResult.PtrLookups} PTR, {cacheResult.PortProbes} port[/]");
    }

    // Load previous domain results for --recheck
    Dictionary<string, DomainResultSummary>? previousResults3 = null;
    if (recheckSeverity != null && cachePath != null)
        previousResults3 = await DiskCacheService.LoadDomainResultsAsync(cachePath);

    // Background cache flusher — periodically saves caches to disk and does a final save on dispose
    await using var cacheFlusher = cachePath != null
        ? new BackgroundCacheFlusher(cachePath, smtp, http, dns, TimeSpan.FromSeconds(30))
        : null;

    for (int i = 0; i < domains.Count; i++)
    {
        var domain = domains[i];
        var validator = new DomainValidator(dns, smtp, http);

        // --recheck: clear stale cached probes for domains with previous issues
        if (recheckSeverity != null && previousResults3 != null &&
            previousResults3.TryGetValue(domain.ToLowerInvariant(), out var prevResult3))
        {
            var deps = RecheckHelper.GetDependenciesForIssues(prevResult3, recheckSeverity.Value);
            if (deps != RecheckHelper.CacheDep.None)
            {
                RecheckHelper.ClearImportedEntriesForDomain(domain, deps, dns, smtp, http);
                AnsiConsole.MarkupLine($"[dim]Recheck: cleared stale cache for {Markup.Escape(domain)} ({deps})[/]");
            }
        }

        // Progressive console output
        if (i > 0)
        {
            AnsiConsole.WriteLine();
            if (verbose) AnsiConsole.WriteLine();
        }

        if (domains.Count > 1)
        {
            if (verbose)
                AnsiConsole.Write(new Rule($"[bold cyan]Domain {i + 1} of {domains.Count}[/]").RuleStyle("cyan"));
            else
                AnsiConsole.MarkupLine($"[bold cyan]Domain {i + 1} of {domains.Count}:[/] [bold]{Markup.Escape(domain)}[/]");
        }

        if (verbose)
        {
            AnsiConsole.Write(new Rule($"[bold blue]ednsv - Email DNS Validation[/]").RuleStyle("blue"));
            AnsiConsole.MarkupLine($"[bold]Domain:[/] {Markup.Escape(domain)}");
            AnsiConsole.MarkupLine($"[bold]Started:[/] {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            if (!options.EnableAxfr)
                AnsiConsole.MarkupLine("[grey]AXFR testing disabled[/]");
            AnsiConsole.WriteLine();
        }
        else if (domains.Count <= 1)
        {
            AnsiConsole.MarkupLine($"[bold]Domain:[/] {Markup.Escape(domain)}");
        }

        var showingRunningLine = false;
        CheckCategory? currentCategory = null;
        var shownDescriptions = new HashSet<string>();
        var checkTimings = new Dictionary<string, TimeSpan>();
        var checkDnsHitsBefore = 0;
        var checkDnsMissesBefore = 0;

        validator.OnCheckTiming += (name, elapsed) =>
        {
            checkTimings[name] = elapsed;
            if (name == "Prefetch")
                AnsiConsole.MarkupLine($"  [dim]Prefetch: {elapsed.TotalSeconds:F1}s (dns:{dns.CacheHits}h/{dns.CacheMisses}m)[/]");
        };

        validator.OnCheckStarted += name =>
        {
            checkDnsHitsBefore = dns.CacheHits;
            checkDnsMissesBefore = dns.CacheMisses;
            AnsiConsole.MarkupLine($"  [dim blue]● Running: {Markup.Escape(name)}…[/]");
            showingRunningLine = true;
        };

        validator.OnCheckCompleted += (name, check) =>
        {
            if (showingRunningLine) { AnsiConsole.Write("\x1b[1A\x1b[2K"); showingRunningLine = false; }

            if (verbose)
            {
                if (check.Category != currentCategory)
                {
                    if (currentCategory != null) AnsiConsole.WriteLine();
                    currentCategory = check.Category;
                    AnsiConsole.Write(new Rule($"[bold]{check.Category}[/]").RuleStyle("grey"));
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

            var timingSuffix = "";
            if (checkTimings.TryGetValue(name, out var elapsed))
            {
                var hits = dns.CacheHits - checkDnsHitsBefore;
                var misses = dns.CacheMisses - checkDnsMissesBefore;
                timingSuffix = $" [dim]({elapsed.TotalSeconds:F1}s, dns:{hits}h/{misses}m)[/]";
            }
            AnsiConsole.MarkupLine($"  {icon} [bold]{Markup.Escape(check.CheckName)}[/]: {Markup.Escape(check.Summary)}{timingSuffix}");

            if (verbose)
            {
                foreach (var detail in check.Details) AnsiConsole.MarkupLine($"       [grey]{Markup.Escape(detail)}[/]");
                foreach (var warning in check.Warnings) AnsiConsole.MarkupLine($"       [yellow]⚠ {Markup.Escape(warning)}[/]");
                foreach (var error in check.Errors) AnsiConsole.MarkupLine($"       [red]✗ {Markup.Escape(error)}[/]");
            }
        };

        var report = await validator.ValidateAsync(domain, options);
        reports.Add(report);

        // Save domain result + flush cache to disk (non-blocking)
        if (cachePath != null)
            _ = DiskCacheService.SaveDomainResultAsync(cachePath, domain, BuildDomainResultSummary(report));
        cacheFlusher?.RequestFlush();

        // Write individual domain file immediately
        var filename = $"{SanitizeFilename(domain)}.{ext}";
        var filepath = Path.Combine(outputDir, filename);
        await using (var fw = new StreamWriter(filepath, false, new UTF8Encoding(false)))
        {
            switch (fmt)
            {
                case "json":
                    await RunJsonAsync(new List<string> { domain }, options, fw, reports: new List<ValidationReport> { report });
                    break;
                case "html":
                    await RunHtmlAsync(new List<string> { domain }, options, fw, reports: new List<ValidationReport> { report });
                    break;
                case "markdown":
                case "md":
                    await RunMarkdownAsync(new List<string> { domain }, options, fw, reports: new List<ValidationReport> { report });
                    break;
            }
        }

        // Show per-domain verdict + file written
        if (verbose)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Rule("[bold]Summary[/]").RuleStyle("grey"));
            var summaryTable = new Table().Border(TableBorder.Rounded).AddColumn("Metric").AddColumn("Count");
            summaryTable.AddRow("[green]Pass[/]", report.PassCount.ToString());
            summaryTable.AddRow("[yellow]Warning[/]", report.WarningCount.ToString());
            summaryTable.AddRow("[red]Error[/]", report.ErrorCount.ToString());
            summaryTable.AddRow("[red bold]Critical[/]", report.CriticalCount.ToString());
            summaryTable.AddRow("[blue]Total Checks[/]", report.Results.Count.ToString());
            summaryTable.AddRow("[grey]Duration[/]", $"{report.Duration.TotalSeconds:F1}s");
            AnsiConsole.Write(summaryTable);
        }
        else
        {
            var verdict = report.CriticalCount > 0 ? "[red bold]CRITICAL[/]" :
                          report.ErrorCount > 0 ? "[red]ERRORS[/]" :
                          report.WarningCount > 0 ? "[yellow]WARNINGS[/]" :
                          "[green]PASS[/]";
            AnsiConsole.MarkupLine($"  → {verdict} ({report.PassCount} pass, {report.WarningCount} warn, {report.ErrorCount} err, {report.CriticalCount} crit) in {report.Duration.TotalSeconds:F1}s");
        }

        AnsiConsole.MarkupLine($"  [grey]Wrote {Markup.Escape(filepath)}[/]");

        // Rewrite the index and issues after each domain so they're always up to date
        if (liveIndex)
        {
            await WriteIndexFileAsync(reports, fmt, ext, outputDir, domainMeta, csvExtraColumns, csvVolumeColumn);
            await WriteIssuesFileAsync(reports, fmt, ext, outputDir, domainMeta, csvVolumeColumn);
            AnsiConsole.MarkupLine($"  [grey]Updated index + issues ({reports.Count}/{domains.Count} domains)[/]");
        }
    }

    // Write final index and issues (always — covers non-live-index mode and ensures
    // the final version includes all domains)
    await WriteIndexFileAsync(reports, fmt, ext, outputDir, domainMeta, csvExtraColumns, csvVolumeColumn);
    await WriteIssuesFileAsync(reports, fmt, ext, outputDir, domainMeta, csvVolumeColumn);

    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine($"[bold green]Index written to {Markup.Escape(Path.Combine(outputDir, $"index.{ext}"))}[/]");
    AnsiConsole.MarkupLine($"[bold green]Issues written to {Markup.Escape(Path.Combine(outputDir, $"issues.{ext}"))}[/]");
    Console.Error.WriteLine($"Reports written to {outputDir}/ ({reports.Count} domain files + index.{ext} + issues.{ext})");

    // Final disk cache save handled by cacheFlusher.DisposeAsync() at end of scope
}

static async Task WriteIndexFileAsync(List<ValidationReport> reports, string fmt, string ext, string outputDir, Dictionary<string, DomainMeta>? meta = null, List<string>? extraCols = null, string? volCol = null)
{
    var indexPath = Path.Combine(outputDir, $"index.{ext}");
    await using var fw = new StreamWriter(indexPath, false, new UTF8Encoding(false));
    switch (fmt)
    {
        case "json":
            await WriteJsonIndexAsync(reports, fw, meta, extraCols, volCol);
            break;
        case "html":
            WriteHtmlIndex(reports, ext, fw, meta, extraCols, volCol);
            break;
        case "markdown":
        case "md":
            WriteMdIndex(reports, ext, fw, meta, extraCols, volCol);
            break;
    }
}

/// <summary>
/// Extracts unique issues (Warning/Error/Critical) across all reports,
/// grouped by check name + severity + summary, with the list of affected domains.
/// </summary>
static List<(string CheckName, CheckCategory Category, CheckSeverity Severity, string Summary, List<string> Domains, long TotalVolume)> CollectCrossDomainIssues(List<ValidationReport> reports, Dictionary<string, DomainMeta>? meta = null)
{
    var issueMap = new Dictionary<(string, CheckCategory, CheckSeverity, string), List<string>>();

    foreach (var report in reports)
    {
        foreach (var result in report.Results)
        {
            if (result.Severity is CheckSeverity.Pass or CheckSeverity.Info)
                continue;

            var key = (result.CheckName, result.Category, result.Severity, result.Summary);
            if (!issueMap.TryGetValue(key, out var domains))
            {
                domains = new List<string>();
                issueMap[key] = domains;
            }
            domains.Add(report.Domain);
        }
    }

    bool hasVolume = meta?.Values.Any(m => m.Volume > 0) == true;

    return issueMap
        .Select(kv =>
        {
            long totalVol = 0;
            if (hasVolume && meta != null)
                totalVol = kv.Value.Where(d => meta.ContainsKey(d)).Sum(d => meta[d].Volume);
            return (kv.Key.Item1, kv.Key.Item2, kv.Key.Item3, kv.Key.Item4, kv.Value, totalVol);
        })
        .OrderByDescending(x => x.Item3) // Critical first
        .ThenByDescending(x => x.totalVol) // Highest message impact first
        .ThenByDescending(x => x.Item5.Count) // Most affected domains
        .ThenBy(x => x.Item1)
        .ToList();
}

static async Task WriteIssuesFileAsync(List<ValidationReport> reports, string fmt, string ext, string outputDir, Dictionary<string, DomainMeta>? meta = null, string? volCol = null)
{
    var issuesPath = Path.Combine(outputDir, $"issues.{ext}");
    await using var fw = new StreamWriter(issuesPath, false, new UTF8Encoding(false));
    var issues = CollectCrossDomainIssues(reports, meta);

    bool hasVolume = meta?.Values.Any(m => m.Volume > 0) == true;

    switch (fmt)
    {
        case "json":
            await WriteJsonIssuesAsync(issues, reports.Count, fw, hasVolume, volCol);
            break;
        case "html":
            WriteHtmlIssues(issues, reports.Count, ext, fw, hasVolume, volCol);
            break;
        case "markdown":
        case "md":
            WriteMdIssues(issues, reports.Count, ext, fw, hasVolume, volCol);
            break;
    }
}

static async Task WriteJsonIssuesAsync(List<(string CheckName, CheckCategory Category, CheckSeverity Severity, string Summary, List<string> Domains, long TotalVolume)> issues, int totalDomains, TextWriter writer, bool hasVolume = false, string? volCol = null)
{
    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    var issueEntries = issues.Select(i =>
    {
        var entry = new Dictionary<string, object>
        {
            ["checkName"] = i.CheckName,
            ["severity"] = i.Severity.ToString(),
            ["summary"] = i.Summary,
            ["affectedDomains"] = i.Domains.Count,
            ["domains"] = i.Domains
        };
        if (hasVolume)
            entry[jsonOptions.PropertyNamingPolicy?.ConvertName(volCol ?? "TotalMessages") ?? "totalMessages"] = i.TotalVolume;
        return entry;
    });

    var obj = new Dictionary<string, object>
    {
        ["totalIssues"] = issues.Count,
        ["totalDomains"] = totalDomains,
        ["timestamp"] = DateTime.UtcNow,
        ["issues"] = issueEntries
    };

    await writer.WriteLineAsync(JsonSerializer.Serialize(obj, jsonOptions));
}

static void WriteMdIssues(List<(string CheckName, CheckCategory Category, CheckSeverity Severity, string Summary, List<string> Domains, long TotalVolume)> issues, int totalDomains, string ext, TextWriter writer, bool hasVolume = false, string? volCol = null)
{
    var sb = new StringBuilder();
    sb.AppendLine("# ednsv — Cross-Domain Issues");
    sb.AppendLine();
    sb.AppendLine($"**Unique issues:** {issues.Count}");
    sb.AppendLine($"**Domains checked:** {totalDomains}");
    sb.AppendLine($"**Date:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
    sb.AppendLine();

    if (!issues.Any())
    {
        sb.AppendLine("No warnings, errors, or critical issues found across any domains.");
        sb.AppendLine();
    }
    else
    {
        // Summary table
        var volHeader = hasVolume ? $" {MdText(volCol ?? "Messages")} |" : "";
        var volSep = hasVolume ? " --------:|" : "";
        sb.AppendLine($"| Severity | Check | Summary | Domains |{volHeader}");
        sb.AppendLine($"|----------|-------|---------|--------:|{volSep}");

        foreach (var issue in issues)
        {
            var icon = issue.Severity switch
            {
                CheckSeverity.Warning => "\u26A0\uFE0F",
                CheckSeverity.Error => "\u274C",
                CheckSeverity.Critical => "\uD83D\uDED1",
                _ => "\u2753"
            };

            var volCell = hasVolume ? $" {issue.TotalVolume:N0} |" : "";
            sb.AppendLine($"| {icon} {SeverityLabel(issue.Severity)} | {MdText(issue.CheckName)} | {MdText(issue.Summary)} | {issue.Domains.Count}/{totalDomains} |{volCell}");
        }

        sb.AppendLine();
        sb.AppendLine("---");
        sb.AppendLine();

        // Detailed breakdown
        sb.AppendLine("## Details");
        sb.AppendLine();

        foreach (var issue in issues)
        {
            var icon = issue.Severity switch
            {
                CheckSeverity.Warning => "\u26A0\uFE0F",
                CheckSeverity.Error => "\u274C",
                CheckSeverity.Critical => "\uD83D\uDED1",
                _ => "\u2753"
            };

            sb.AppendLine($"### {icon} {MdText(issue.CheckName)} — {SeverityLabel(issue.Severity)}");
            sb.AppendLine();
            sb.AppendLine($"> {MdText(issue.Summary)}");
            sb.AppendLine();
            if (hasVolume && issue.TotalVolume > 0)
                sb.AppendLine($"**{MdText(volCol ?? "Messages")} impacted:** {issue.TotalVolume:N0}");
            sb.AppendLine($"**Affected domains ({issue.Domains.Count}/{totalDomains}):**");
            var mdCheckSlug = Slugify(issue.CheckName);
            foreach (var domain in issue.Domains)
                sb.AppendLine($"- [`{domain}`]({SanitizeFilename(domain)}.{ext}#check-{mdCheckSlug})");
            sb.AppendLine();
        }
    }

    sb.AppendLine("---");
    sb.AppendLine($"*Generated by [ednsv](https://github.com/pkinerd/ednsv) on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC*");

    writer.Write(sb.ToString());
}

static void WriteHtmlIssues(List<(string CheckName, CheckCategory Category, CheckSeverity Severity, string Summary, List<string> Domains, long TotalVolume)> issues, int totalDomains, string ext, TextWriter writer, bool hasVolume = false, string? volCol = null)
{
    var sb = new StringBuilder();
    var e = (string s) => HttpUtility.HtmlEncode(s);

    sb.AppendLine("<!DOCTYPE html>");
    sb.AppendLine("<html lang=\"en\">");
    sb.AppendLine("<head>");
    sb.AppendLine("<meta charset=\"UTF-8\">");
    sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
    sb.AppendLine($"<title>ednsv — Cross-Domain Issues</title>");
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
h2 { font-size: 1.2rem; margin-top: 2rem; margin-bottom: 0.75rem; }
.meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 1.5rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.75rem; margin-bottom: 2rem; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
.stat .value { font-size: 1.75rem; font-weight: 700; }
.stat .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
.stat.warn .value { color: var(--warn); }
.stat.error .value { color: var(--error); }
.stat.crit .value { color: var(--crit); }
.issue { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; border-left: 4px solid var(--border); }
.issue.sev-warning { border-left-color: var(--warn); }
.issue.sev-error { border-left-color: var(--error); }
.issue.sev-critical { border-left-color: var(--crit); }
.issue-header { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.badge { font-size: 0.7rem; font-weight: 600; padding: 0.15rem 0.5rem; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.05em; }
.badge-warning { background: var(--warn-bg); color: var(--warn); }
.badge-error { background: var(--error-bg); color: var(--error); }
.badge-critical { background: var(--crit-bg); color: var(--crit); }
.issue-name { font-weight: 600; }
.issue-count { color: var(--muted); font-size: 0.85rem; margin-left: auto; }
.issue-summary { color: var(--muted); font-size: 0.9rem; margin-top: 0.25rem; }
.domain-chips { display: flex; flex-wrap: wrap; gap: 0.375rem; margin-top: 0.5rem; }
.domain-chip { display: inline-block; font-size: 0.8rem; padding: 0.15rem 0.5rem; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--info); text-decoration: none; }
.domain-chip:hover { background: var(--info-bg); border-color: var(--info); }
a { color: var(--info); text-decoration: none; }
a:hover { text-decoration: underline; }
.empty { text-align: center; padding: 3rem; color: var(--pass); font-size: 1.1rem; }
footer { text-align: center; margin-top: 2rem; font-size: 0.75rem; color: var(--muted); }
");
    sb.AppendLine("</style>");
    sb.AppendLine("</head>");
    sb.AppendLine("<body>");

    sb.AppendLine("<h1>ednsv &mdash; Cross-Domain Issues</h1>");
    sb.AppendLine($"<div class=\"meta\">{totalDomains} domains checked &middot; {e(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"))} UTC &middot; <a href=\"index.{ext}\">Back to index</a></div>");

    // Stat cards
    int critCount = issues.Count(i => i.Severity == CheckSeverity.Critical);
    int errorCount = issues.Count(i => i.Severity == CheckSeverity.Error);
    int warnCount = issues.Count(i => i.Severity == CheckSeverity.Warning);

    sb.AppendLine("<div class=\"summary\">");
    sb.AppendLine($"  <div class=\"stat crit\"><div class=\"value\">{critCount}</div><div class=\"label\">Critical</div></div>");
    sb.AppendLine($"  <div class=\"stat error\"><div class=\"value\">{errorCount}</div><div class=\"label\">Error</div></div>");
    sb.AppendLine($"  <div class=\"stat warn\"><div class=\"value\">{warnCount}</div><div class=\"label\">Warning</div></div>");
    sb.AppendLine($"  <div class=\"stat\"><div class=\"value\">{issues.Count}</div><div class=\"label\">Unique Issues</div></div>");
    sb.AppendLine("</div>");

    if (!issues.Any())
    {
        sb.AppendLine("<div class=\"empty\">No warnings, errors, or critical issues found across any domains.</div>");
    }
    else
    {
        foreach (var issue in issues)
        {
            var sevClass = issue.Severity.ToString().ToLowerInvariant();
            var badgeLabel = issue.Severity switch
            {
                CheckSeverity.Warning => "WARN",
                CheckSeverity.Error => "FAIL",
                CheckSeverity.Critical => "CRIT",
                _ => "????"
            };

            sb.AppendLine($"<div class=\"issue sev-{sevClass}\">");
            sb.AppendLine($"  <div class=\"issue-header\">");
            sb.AppendLine($"    <span class=\"badge badge-{sevClass}\">{badgeLabel}</span>");
            sb.AppendLine($"    <span class=\"issue-name\">{e(issue.CheckName)}</span>");
            var volInfo = hasVolume && issue.TotalVolume > 0 ? $" &middot; {issue.TotalVolume:N0} {e(volCol ?? "messages")}" : "";
            sb.AppendLine($"    <span class=\"issue-count\">{issue.Domains.Count}/{totalDomains} domains{volInfo}</span>");
            sb.AppendLine($"  </div>");
            sb.AppendLine($"  <div class=\"issue-summary\">{e(issue.Summary)}</div>");
            sb.AppendLine($"  <div class=\"domain-chips\">");
            var checkSlug = Slugify(issue.CheckName);
            foreach (var domain in issue.Domains)
            {
                var file = $"{SanitizeFilename(domain)}.{ext}";
                sb.AppendLine($"    <a class=\"domain-chip\" href=\"{e(file)}#check-{checkSlug}\">{e(domain)}</a>");
            }
            sb.AppendLine($"  </div>");
            sb.AppendLine($"</div>");
        }
    }

    sb.AppendLine($"<footer>Generated by ednsv on {e(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</footer>");
    sb.AppendLine("</body>");
    sb.AppendLine("</html>");

    writer.Write(sb.ToString());
}

static DomainResultSummary BuildDomainResultSummary(ValidationReport report)
{
    return new DomainResultSummary
    {
        ValidatedAtUtc = DateTime.UtcNow,
        PassCount = report.PassCount,
        WarningCount = report.WarningCount,
        ErrorCount = report.ErrorCount,
        CriticalCount = report.CriticalCount,
        IssueChecks = report.Results
            .Where(r => r.Severity >= CheckSeverity.Warning)
            .Select(r => new IssueCheckEntry
            {
                Name = r.CheckName,
                Category = r.Category.ToString(),
                Severity = r.Severity.ToString()
            })
            .ToList()
    };
}

/// <summary>
/// Converts a check name or category into a URL-safe HTML anchor ID.
/// e.g. "SMTP TLS Certificate" → "smtp-tls-certificate"
/// </summary>
static string Slugify(string text)
{
    var sb = new StringBuilder(text.Length);
    foreach (var c in text.ToLowerInvariant())
    {
        if (char.IsLetterOrDigit(c))
            sb.Append(c);
        else if (c is ' ' or '_' or '/' or '(' or ')')
        {
            if (sb.Length > 0 && sb[^1] != '-')
                sb.Append('-');
        }
    }
    return sb.ToString().TrimEnd('-');
}

static string SanitizeFilename(string domain)
{
    // Replace characters that are invalid in filenames
    var invalid = Path.GetInvalidFileNameChars();
    var sb = new StringBuilder(domain.Length);
    foreach (var c in domain)
        sb.Append(invalid.Contains(c) ? '_' : c);
    return sb.ToString();
}

static async Task WriteJsonIndexAsync(List<ValidationReport> reports, TextWriter writer, Dictionary<string, DomainMeta>? meta = null, List<string>? extraCols = null, string? volCol = null)
{
    var jsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    bool hasVolume = meta?.Values.Any(m => m.Volume > 0) == true;
    var sorted = hasVolume
        ? reports.OrderByDescending(r => meta!.TryGetValue(r.Domain, out var m) ? m.Volume : 0).ToList()
        : reports;

    var displayCols = (extraCols ?? new List<string>()).Where(c => !string.Equals(c, volCol, StringComparison.OrdinalIgnoreCase)).ToList();

    var domains = sorted.Select(r =>
    {
        var entry = new Dictionary<string, object>
        {
            ["domain"] = r.Domain,
            ["file"] = $"{SanitizeFilename(r.Domain)}.json"
        };
        // Volume column right after domain
        if (hasVolume && meta != null && meta.TryGetValue(r.Domain, out var dmVol))
            entry[jsonOptions.PropertyNamingPolicy?.ConvertName(volCol ?? "TotalMessages") ?? "totalMessages"] = dmVol.Volume;
        // Tool-generated columns
        entry["passCount"] = r.PassCount;
        entry["warningCount"] = r.WarningCount;
        entry["errorCount"] = r.ErrorCount;
        entry["criticalCount"] = r.CriticalCount;
        entry["totalChecks"] = r.Results.Count;
        entry["durationSeconds"] = Math.Round(r.Duration.TotalSeconds, 1);
        entry["verdict"] = r.CriticalCount > 0 ? "CRITICAL" :
                      r.ErrorCount > 0 ? "ERRORS" :
                      r.WarningCount > 0 ? "WARNINGS" : "PASS";
        // Extra CSV columns at end
        if (meta != null && meta.TryGetValue(r.Domain, out var dm))
        {
            foreach (var col in displayCols)
            {
                if (dm.Columns.TryGetValue(col, out var val))
                    entry[jsonOptions.PropertyNamingPolicy?.ConvertName(col) ?? col] = val;
            }
        }
        return entry;
    });

    var obj = new Dictionary<string, object>
    {
        ["totalDomains"] = reports.Count,
        ["totalPass"] = reports.Sum(r => r.PassCount),
        ["totalWarning"] = reports.Sum(r => r.WarningCount),
        ["totalError"] = reports.Sum(r => r.ErrorCount),
        ["totalCritical"] = reports.Sum(r => r.CriticalCount),
        ["timestamp"] = DateTime.UtcNow,
        ["domains"] = domains
    };

    await writer.WriteLineAsync(JsonSerializer.Serialize(obj, jsonOptions));
}

static void WriteMdIndex(List<ValidationReport> reports, string ext, TextWriter writer, Dictionary<string, DomainMeta>? meta = null, List<string>? extraCols = null, string? volCol = null)
{
    var sb = new StringBuilder();
    sb.AppendLine("# ednsv — Email DNS Validation Summary");
    sb.AppendLine();
    sb.AppendLine($"**Domains checked:** {reports.Count}");
    sb.AppendLine($"**Date:** {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
    sb.AppendLine();

    bool hasVolume = meta?.Values.Any(m => m.Volume > 0) == true;
    var displayCols = (extraCols ?? new List<string>()).Where(c => !string.Equals(c, volCol, StringComparison.OrdinalIgnoreCase)).ToList();
    var sorted = hasVolume
        ? reports.OrderByDescending(r => meta!.TryGetValue(r.Domain, out var m) ? m.Volume : 0).ToList()
        : reports;

    sb.AppendLine("## Results");
    sb.AppendLine();

    // Build header: Domain | Volume | tool cols | extra CSV cols | Report
    var volHeader = hasVolume ? $" {MdText(volCol ?? "Messages")} |" : "";
    var extraHeaders = string.Join("", displayCols.Select(c => $" {MdText(c)} |"));
    sb.AppendLine($"| Domain |{volHeader} Pass | Warn | Error | Crit | Total | Duration | Verdict |{extraHeaders} Report |");
    var volSep = hasVolume ? " --------:|" : "";
    var extraSeps = string.Join("", displayCols.Select(_ => "--------|"));
    sb.AppendLine($"|--------|{volSep}-----:|-----:|------:|-----:|------:|---------:|---------|{extraSeps}--------|");

    foreach (var r in sorted)
    {
        var verdict = r.CriticalCount > 0 ? "\uD83D\uDED1 CRITICAL" :
                      r.ErrorCount > 0 ? "\u274C ERRORS" :
                      r.WarningCount > 0 ? "\u26A0\uFE0F WARNINGS" :
                      "\u2705 PASS";
        var file = $"{SanitizeFilename(r.Domain)}.{ext}";

        var volVal = "";
        var extraVals = "";
        if (meta != null && meta.TryGetValue(r.Domain, out var dm))
        {
            if (hasVolume) volVal = $" {dm.Volume:N0} |";
            extraVals = string.Join("", displayCols.Select(c => $" {MdText(dm.Columns.GetValueOrDefault(c, ""))} |"));
        }
        else
        {
            if (hasVolume) volVal = " |";
            extraVals = string.Join("", displayCols.Select(_ => " |"));
        }

        sb.AppendLine($"| `{r.Domain}` |{volVal} {r.PassCount} | {r.WarningCount} | {r.ErrorCount} | {r.CriticalCount} | {r.Results.Count} | {r.Duration.TotalSeconds:F1}s | {verdict} |{extraVals} [{file}]({file}) |");
    }

    var totalDuration = reports.Aggregate(TimeSpan.Zero, (acc, r) => acc + r.Duration);
    var volTotal = hasVolume ? $" **{meta!.Values.Sum(m => m.Volume):N0}** |" : "";
    var extraTotals = string.Join("", displayCols.Select(_ => " |"));
    sb.AppendLine($"| **Total** |{volTotal} **{reports.Sum(r => r.PassCount)}** | **{reports.Sum(r => r.WarningCount)}** | **{reports.Sum(r => r.ErrorCount)}** | **{reports.Sum(r => r.CriticalCount)}** | **{reports.Sum(r => r.Results.Count)}** | **{totalDuration.TotalSeconds:F1}s** | |{extraTotals} |");
    sb.AppendLine();
    sb.AppendLine($"[View cross-domain issues](issues.{ext})");
    sb.AppendLine();
    sb.AppendLine("---");
    sb.AppendLine($"*Generated by [ednsv](https://github.com/pkinerd/ednsv) on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC*");

    writer.Write(sb.ToString());
}

static void WriteHtmlIndex(List<ValidationReport> reports, string ext, TextWriter writer, Dictionary<string, DomainMeta>? meta = null, List<string>? extraCols = null, string? volCol = null)
{
    var sb = new StringBuilder();
    var e = (string s) => HttpUtility.HtmlEncode(s);

    bool hasVolume = meta?.Values.Any(m => m.Volume > 0) == true;
    var displayCols = (extraCols ?? new List<string>()).Where(c => !string.Equals(c, volCol, StringComparison.OrdinalIgnoreCase)).ToList();
    var sorted = hasVolume
        ? reports.OrderByDescending(r => meta!.TryGetValue(r.Domain, out var m) ? m.Volume : 0).ToList()
        : reports;

    sb.AppendLine("<!DOCTYPE html>");
    sb.AppendLine("<html lang=\"en\">");
    sb.AppendLine("<head>");
    sb.AppendLine("<meta charset=\"UTF-8\">");
    sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
    sb.AppendLine($"<title>ednsv — Summary ({reports.Count} Domains)</title>");
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
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; margin: 0; }
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
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }
th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; white-space: nowrap; }
th { background: var(--bg); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.03em; color: var(--muted); }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:last-child td { border-bottom: none; font-weight: 600; }
a { color: var(--info); text-decoration: none; }
a:hover { text-decoration: underline; }
.verdict-pass { color: var(--pass); }
.verdict-warn { color: var(--warn); }
.verdict-error { color: var(--error); }
.verdict-crit { color: var(--crit); font-weight: 700; }
footer { text-align: center; margin-top: 2rem; font-size: 0.75rem; color: var(--muted); }
");
    sb.AppendLine("</style>");
    sb.AppendLine("</head>");
    sb.AppendLine("<body>");

    sb.AppendLine("<h1>ednsv &mdash; Email DNS Validation Summary</h1>");
    sb.AppendLine($"<div class=\"meta\">{reports.Count} domains &middot; {e(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</div>");

    // Aggregate stat cards
    int totalPass = reports.Sum(r => r.PassCount), totalWarn = reports.Sum(r => r.WarningCount);
    int totalError = reports.Sum(r => r.ErrorCount), totalCrit = reports.Sum(r => r.CriticalCount);
    int totalChecks = reports.Sum(r => r.Results.Count);

    sb.AppendLine("<div class=\"summary\">");
    sb.AppendLine($"  <div class=\"stat pass\"><div class=\"value\">{totalPass}</div><div class=\"label\">Pass</div></div>");
    sb.AppendLine($"  <div class=\"stat warn\"><div class=\"value\">{totalWarn}</div><div class=\"label\">Warning</div></div>");
    sb.AppendLine($"  <div class=\"stat error\"><div class=\"value\">{totalError}</div><div class=\"label\">Error</div></div>");
    sb.AppendLine($"  <div class=\"stat crit\"><div class=\"value\">{totalCrit}</div><div class=\"label\">Critical</div></div>");
    sb.AppendLine($"  <div class=\"stat\"><div class=\"value\">{totalChecks}</div><div class=\"label\">Total</div></div>");
    sb.AppendLine("</div>");

    // Domain table: Domain | Volume | tool cols | extra CSV cols
    sb.AppendLine("<table>");
    sb.Append("<thead><tr><th>Domain</th>");
    if (hasVolume)
        sb.Append($"<th>{e(volCol ?? "Messages")}</th>");
    sb.Append("<th>Pass</th><th>Warn</th><th>Error</th><th>Crit</th><th>Total</th><th>Duration</th><th>Verdict</th>");
    foreach (var col in displayCols)
        sb.Append($"<th>{e(col)}</th>");
    sb.AppendLine("</tr></thead>");
    sb.AppendLine("<tbody>");

    var totalDuration = TimeSpan.Zero;
    foreach (var r in sorted)
    {
        string verdictClass, verdictLabel;
        if (r.CriticalCount > 0) { verdictClass = "verdict-crit"; verdictLabel = "CRITICAL"; }
        else if (r.ErrorCount > 0) { verdictClass = "verdict-error"; verdictLabel = "ERRORS"; }
        else if (r.WarningCount > 0) { verdictClass = "verdict-warn"; verdictLabel = "WARNINGS"; }
        else { verdictClass = "verdict-pass"; verdictLabel = "PASS"; }

        var file = $"{SanitizeFilename(r.Domain)}.{ext}";
        sb.Append($"<tr><td><a href=\"{e(file)}\">{e(r.Domain)}</a></td>");

        if (meta != null && meta.TryGetValue(r.Domain, out var dm))
        {
            if (hasVolume)
                sb.Append($"<td class=\"num\">{dm.Volume:N0}</td>");
            sb.Append($"<td class=\"num\">{r.PassCount}</td><td class=\"num\">{r.WarningCount}</td><td class=\"num\">{r.ErrorCount}</td><td class=\"num\">{r.CriticalCount}</td><td class=\"num\">{r.Results.Count}</td><td class=\"num\">{r.Duration.TotalSeconds:F1}s</td><td class=\"{verdictClass}\">{verdictLabel}</td>");
            foreach (var col in displayCols)
                sb.Append($"<td>{e(dm.Columns.GetValueOrDefault(col, ""))}</td>");
        }
        else
        {
            if (hasVolume)
                sb.Append("<td class=\"num\"></td>");
            sb.Append($"<td class=\"num\">{r.PassCount}</td><td class=\"num\">{r.WarningCount}</td><td class=\"num\">{r.ErrorCount}</td><td class=\"num\">{r.CriticalCount}</td><td class=\"num\">{r.Results.Count}</td><td class=\"num\">{r.Duration.TotalSeconds:F1}s</td><td class=\"{verdictClass}\">{verdictLabel}</td>");
            foreach (var _ in displayCols)
                sb.Append("<td></td>");
        }

        sb.AppendLine("</tr>");
        totalDuration += r.Duration;
    }

    sb.Append($"<tr><td><strong>Total</strong></td>");
    if (hasVolume)
        sb.Append($"<td class=\"num\">{meta!.Values.Sum(m => m.Volume):N0}</td>");
    sb.Append($"<td class=\"num\">{totalPass}</td><td class=\"num\">{totalWarn}</td><td class=\"num\">{totalError}</td><td class=\"num\">{totalCrit}</td><td class=\"num\">{totalChecks}</td><td class=\"num\">{totalDuration.TotalSeconds:F1}s</td><td></td>");
    foreach (var _ in displayCols)
        sb.Append("<td></td>");
    sb.AppendLine("</tr>");
    sb.AppendLine("</tbody></table>");

    sb.AppendLine($"<p style=\"margin-top:1rem;font-size:0.9rem;\"><a href=\"issues.{ext}\">View cross-domain issues &rarr;</a></p>");

    sb.AppendLine($"<footer>Generated by ednsv on {e(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"))} UTC</footer>");
    sb.AppendLine("</body>");
    sb.AppendLine("</html>");

    writer.Write(sb.ToString());
}

static async Task RunJsonAsync(List<string> domains, ValidationOptions options, TextWriter writer, bool showProgress = false, bool verbose = false, List<ValidationReport>? reports = null, List<IPAddress>? dnsServers = null, string? cachePath = null, int cacheTtlHours = 24, bool retryErrors = false, CheckSeverity? recheckSeverity = null)
{
    reports ??= await ValidateAllAsync(domains, options, showProgress, verbose, dnsServers, cachePath, cacheTtlHours, retryErrors, recheckSeverity);

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

static async Task RunMarkdownAsync(List<string> domains, ValidationOptions options, TextWriter writer, bool showProgress = false, bool verbose = false, List<ValidationReport>? reports = null, List<IPAddress>? dnsServers = null, string? cachePath = null, int cacheTtlHours = 24, bool retryErrors = false, CheckSeverity? recheckSeverity = null)
{
    reports ??= await ValidateAllAsync(domains, options, showProgress, verbose, dnsServers, cachePath, cacheTtlHours, retryErrors, recheckSeverity);

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

static async Task RunHtmlAsync(List<string> domains, ValidationOptions options, TextWriter writer, bool showProgress = false, bool verbose = false, List<ValidationReport>? reports = null, List<IPAddress>? dnsServers = null, string? cachePath = null, int cacheTtlHours = 24, bool retryErrors = false, CheckSeverity? recheckSeverity = null)
{
    reports ??= await ValidateAllAsync(domains, options, showProgress, verbose, dnsServers, cachePath, cacheTtlHours, retryErrors, recheckSeverity);

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
            var catSlug = Slugify(group.Key.ToString());
            sb.AppendLine($"<div class=\"category\" id=\"cat-{catSlug}\">");
            sb.AppendLine($"  <h2>{e(group.Key.ToString())}</h2>");

            foreach (var check in group)
            {
                var sevClass = check.Severity.ToString().ToLowerInvariant();
                var checkSlug = Slugify(check.CheckName);
                var badgeLabel = check.Severity switch
                {
                    CheckSeverity.Pass => "PASS",
                    CheckSeverity.Info => "INFO",
                    CheckSeverity.Warning => "WARN",
                    CheckSeverity.Error => "FAIL",
                    CheckSeverity.Critical => "CRIT",
                    _ => "????"
                };

                sb.AppendLine($"  <div class=\"check sev-{sevClass}\" id=\"check-{checkSlug}\">");
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

// ── Domain metadata from CSV ──────────────────────────────────────────
record DomainMeta(Dictionary<string, string> Columns, long Volume);
