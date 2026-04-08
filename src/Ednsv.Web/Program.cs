using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ednsv.Core;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

var builder = WebApplication.CreateBuilder(args);

// ── Configuration ────────────────────────────────────────────────────────
var cacheDir = builder.Configuration.GetValue<string>("CacheDir") ?? ".ednsv-cache";
var cacheTtlHours = builder.Configuration.GetValue<int>("CacheTtlHours", 24);
var flushIntervalSeconds = builder.Configuration.GetValue<int>("FlushIntervalSeconds", 120);
var dnsServerStr = builder.Configuration.GetValue<string>("DnsServer");
var dkimSelectorsStr = builder.Configuration.GetValue<string>("DkimSelectors");

// ── Shared services (singletons — thread-safe via ConcurrentDictionary) ──
// Use OS-configured resolvers by default; override with DnsServer env var.
DnsResolverService dns;
if (!string.IsNullOrEmpty(dnsServerStr))
{
    var dnsServers = new List<IPAddress>();
    foreach (var s in dnsServerStr.Split(',', StringSplitOptions.RemoveEmptyEntries))
        if (IPAddress.TryParse(s.Trim(), out var ip))
            dnsServers.Add(ip);
    dns = dnsServers.Count > 0 ? new DnsResolverService(dnsServers) : DnsResolverService.CreateWithSystemResolvers();
}
else
{
    dns = DnsResolverService.CreateWithSystemResolvers();
}
var smtp = new SmtpProbeService();
var http = new HttpProbeService();

builder.Services.AddSingleton(dns);
builder.Services.AddSingleton(smtp);
builder.Services.AddSingleton(http);

// ── Default validation options ────────────────────────────────────────────
var defaultOptions = new ValidationOptions();
if (!string.IsNullOrEmpty(dkimSelectorsStr))
    defaultOptions.AdditionalDkimSelectors = dkimSelectorsStr
        .Split(',', StringSplitOptions.RemoveEmptyEntries)
        .Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
builder.Services.AddSingleton(defaultOptions);

// ── Cache manager ────────────────────────────────────────────────────────
var cacheManager = new CacheManager(cacheDir, TimeSpan.FromHours(cacheTtlHours), dns, smtp, http);
builder.Services.AddSingleton(cacheManager);

// ── In-flight validation tracking ────────────────────────────────────────
var validationTracker = new ValidationTracker();
builder.Services.AddSingleton(validationTracker);

builder.Services.ConfigureHttpJsonOptions(opts =>
{
    opts.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    opts.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

var app = builder.Build();

// ── Load cache from disk at startup ──────────────────────────────────────
var cacheResult = await cacheManager.LoadAsync();
if (cacheResult != null)
    app.Logger.LogInformation("Loaded cache ({Total} entries, {Age:F0}m old): {Dns} DNS, {Smtp} SMTP, {Rcpt} RCPT, {Http} HTTP, {Ptr} PTR, {Port} port",
        cacheResult.Total, cacheResult.Age.TotalMinutes,
        cacheResult.DnsQueries, cacheResult.SmtpProbes, cacheResult.RcptProbes,
        cacheResult.HttpRequests, cacheResult.PtrLookups, cacheResult.PortProbes);

// Start periodic background flush
cacheManager.StartBackgroundFlusher(TimeSpan.FromSeconds(flushIntervalSeconds));

// ── Static files (wwwroot/index.html) ────────────────────────────────────
app.UseDefaultFiles();
app.UseStaticFiles();

// ── API endpoints ────────────────────────────────────────────────────────

// POST /api/validate  { "domain": "example.com" }
// Starts an async validation and returns a job ID.
app.MapPost("/api/validate", (ValidateRequest req, ValidationTracker tracker,
    DnsResolverService dnsSvc, SmtpProbeService smtpSvc, HttpProbeService httpSvc,
    CacheManager cache, ValidationOptions defaults, ILogger<Program> logger) =>
{
    var domain = req.Domain?.Trim().TrimEnd('.').ToLowerInvariant();
    if (string.IsNullOrEmpty(domain))
        return Results.BadRequest(new { error = "domain is required" });

    CheckSeverity? recheckSeverity = null;
    if (!string.IsNullOrEmpty(req.RecheckSeverity) &&
        Enum.TryParse<CheckSeverity>(req.RecheckSeverity, ignoreCase: true, out var parsed))
        recheckSeverity = parsed;

    // Merge request options with server defaults (request takes precedence)
    var options = req.Options ?? new ValidationOptions();
    if (!options.AdditionalDkimSelectors.Any() && defaults.AdditionalDkimSelectors.Any())
        options.AdditionalDkimSelectors = defaults.AdditionalDkimSelectors;

    var jobId = tracker.StartValidation(domain, dnsSvc, smtpSvc, httpSvc, options, cache, logger, recheckSeverity);
    return Results.Accepted($"/api/status/{jobId}", new { jobId, domain, status = "running" });
});

// GET /api/status/{jobId}
// Returns the current status and results (if complete) for a validation job.
app.MapGet("/api/status/{jobId}", (string jobId, ValidationTracker tracker) =>
{
    if (!tracker.TryGetJob(jobId, out var job))
        return Results.NotFound(new { error = "Job not found" });

    return Results.Ok(new
    {
        jobId,
        job!.Domain,
        status = job.Status.ToString().ToLowerInvariant(),
        currentCheck = job.CurrentCheck,
        completedChecks = job.CompletedChecks,
        report = job.Report,
        error = job.Error
    });
});

// GET /api/validate/{domain}
// Synchronous convenience endpoint — runs validation and returns the full report.
// Times out after 3 minutes.
app.MapGet("/api/validate/{domain}", async (string domain, string? recheck,
    DnsResolverService dnsSvc, SmtpProbeService smtpSvc, HttpProbeService httpSvc,
    CacheManager cache, ValidationOptions defaults, CancellationToken ct) =>
{
    domain = domain.Trim().TrimEnd('.').ToLowerInvariant();
    if (string.IsNullOrEmpty(domain))
        return Results.BadRequest(new { error = "domain is required" });

    if (!string.IsNullOrEmpty(recheck) &&
        Enum.TryParse<CheckSeverity>(recheck, ignoreCase: true, out var recheckSev))
        cache.ClearForRecheck(domain, recheckSev);

    var validator = new DomainValidator(dnsSvc, smtpSvc, httpSvc);

    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(3));

    try
    {
        var report = await validator.ValidateAsync(domain, defaults);
        _ = cache.SaveDomainResultAsync(domain, ValidationTracker.BuildSummary(report));
        cache.RequestFlush();
        return Results.Ok(report);
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(504);
    }
});

// GET /api/cache/stats
app.MapGet("/api/cache/stats", (DnsResolverService dnsSvc) =>
{
    return Results.Ok(new
    {
        dnsCacheSize = dnsSvc.CacheSize,
        dnsCacheHits = dnsSvc.CacheHits,
        dnsCacheMisses = dnsSvc.CacheMisses
    });
});

// POST /api/cache/flush
app.MapPost("/api/cache/flush", async (CacheManager cache) =>
{
    await cache.FlushAsync();
    return Results.Ok(new { flushed = true });
});

// GET /api/checks
app.MapGet("/api/checks", () => Results.Ok(CheckDescriptions.Categories));

app.Run();

// ── Supporting types ─────────────────────────────────────────────────────

record ValidateRequest(string? Domain, ValidationOptions? Options = null, string? RecheckSeverity = null);

enum JobStatus { Running, Completed, Failed }

class ValidationJob
{
    public string Domain { get; set; } = "";
    public JobStatus Status { get; set; } = JobStatus.Running;
    public string? CurrentCheck { get; set; }
    public int CompletedChecks { get; set; }
    public ValidationReport? Report { get; set; }
    public string? Error { get; set; }
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
}

class ValidationTracker
{
    private readonly ConcurrentDictionary<string, ValidationJob> _jobs = new();

    public string StartValidation(string domain, DnsResolverService dns,
        SmtpProbeService smtp, HttpProbeService http, ValidationOptions? options,
        CacheManager cache, ILogger logger, CheckSeverity? recheckSeverity = null)
    {
        var jobId = Guid.NewGuid().ToString("N")[..12];
        var job = new ValidationJob { Domain = domain };
        _jobs[jobId] = job;

        _ = Task.Run(async () =>
        {
            try
            {
                if (recheckSeverity != null)
                {
                    var cleared = cache.ClearForRecheck(domain, recheckSeverity.Value);
                    if (cleared)
                        logger.LogInformation("Recheck: cleared stale cache for {Domain} (>= {Severity})", domain, recheckSeverity);
                }

                var validator = new DomainValidator(dns, smtp, http);
                validator.OnCheckStarted += name => job.CurrentCheck = name;
                validator.OnCheckCompleted += (_, _) => job.CompletedChecks++;

                var report = await validator.ValidateAsync(domain, options);
                job.Report = report;
                job.CurrentCheck = null;
                job.Status = JobStatus.Completed;

                _ = cache.SaveDomainResultAsync(domain, ValidationTracker.BuildSummary(report));
                cache.RequestFlush();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Validation failed for {Domain}", domain);
                job.Error = ex.Message;
                job.Status = JobStatus.Failed;
            }
        });

        return jobId;
    }

    public bool TryGetJob(string jobId, out ValidationJob? job) => _jobs.TryGetValue(jobId, out job);

    public static DomainResultSummary BuildSummary(ValidationReport report)
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
}

// Make Program accessible for logging DI
public partial class Program { }
