using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using Ednsv.Core;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

var builder = WebApplication.CreateBuilder(args);

// ── Console log timestamps with fractional seconds ───────────────────────
builder.Logging.AddSimpleConsole(options =>
{
    options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ";
});

// ── Configuration ────────────────────────────────────────────────────────
var cacheDir = builder.Configuration.GetValue<string>("CacheDir") ?? ".ednsv-cache";
var cacheTtlHours = builder.Configuration.GetValue<int>("CacheTtlHours", 24);
var flushIntervalSeconds = builder.Configuration.GetValue<int>("FlushIntervalSeconds", 120);
var dnsServerStr = builder.Configuration.GetValue<string>("DnsServer");
var dkimSelectorsStr = builder.Configuration.GetValue<string>("DkimSelectors");
var enableTrace = builder.Configuration.GetValue<bool>("Trace", false);
var maskTrace = builder.Configuration.GetValue<bool>("MaskTrace", true); // default ON for privacy
var maskSalt = builder.Configuration.GetValue<string>("MaskSalt");

// ── Shared services (singletons — thread-safe via ConcurrentDictionary) ──
// Use OS-configured resolvers by default; override with DnsServer env var.
// CacheTtlHours controls per-entry in-memory cache expiry.
var inMemoryTtl = cacheTtlHours > 0 ? TimeSpan.FromHours(cacheTtlHours) : (TimeSpan?)null;

DnsResolverService dns;
if (!string.IsNullOrEmpty(dnsServerStr))
{
    var dnsServers = new List<IPAddress>();
    foreach (var s in dnsServerStr.Split(',', StringSplitOptions.RemoveEmptyEntries))
        if (IPAddress.TryParse(s.Trim(), out var ip))
            dnsServers.Add(ip);
    dns = dnsServers.Count > 0
        ? new DnsResolverService(dnsServers, cacheTtl: inMemoryTtl)
        : DnsResolverService.CreateWithSystemResolvers(cacheTtl: inMemoryTtl);
}
else
{
    dns = DnsResolverService.CreateWithSystemResolvers(cacheTtl: inMemoryTtl);
}
var smtp = new SmtpProbeService(cacheTtl: inMemoryTtl);
var http = new HttpProbeService(cacheTtl: inMemoryTtl);

builder.Services.AddSingleton(dns);
builder.Services.AddSingleton(smtp);
builder.Services.AddSingleton(http);

// ── Trace masker (singleton — same salt for session, consistent hashes) ───
var traceMasker = maskTrace
    ? (!string.IsNullOrEmpty(maskSalt) ? new TraceMasker(maskSalt) : new TraceMasker())
    : null;

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

    var jobId = tracker.StartValidation(domain, dnsSvc, smtpSvc, httpSvc, options, cache, logger, recheckSeverity, enableTrace, traceMasker);
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
        results = new
        {
            pass = job.PassCount,
            info = job.InfoCount,
            warning = job.WarningCount,
            error = job.ErrorCount,
            critical = job.CriticalCount
        },
        dns = job.Dns != null ? new
        {
            queries = (job.Dns.CacheHits - job.DnsHitsBaseline) + (job.Dns.CacheMisses - job.DnsMissesBaseline),
            cacheHits = job.Dns.CacheHits - job.DnsHitsBaseline,
            sent = job.Dns.CacheMisses - job.DnsMissesBaseline,
            received = job.Dns.ResponsesReceived - job.DnsResponsesBaseline
        } : null,
        smtp = job.Smtp != null ? new
        {
            probesStarted = job.Smtp.ProbesStarted - job.SmtpProbesStartedBaseline,
            probesDone = job.Smtp.ProbesCompleted - job.SmtpProbesCompletedBaseline,
            portsStarted = job.Smtp.PortsStarted - job.PortsStartedBaseline,
            portsDone = job.Smtp.PortsCompleted - job.PortsCompletedBaseline
        } : null,
        elapsed = (DateTime.UtcNow - job.StartedAt).TotalSeconds,
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

    var validator = new DomainValidator(dnsSvc, smtpSvc, httpSvc);
    if (traceMasker != null) validator.TraceMask = traceMasker;
    if (enableTrace) validator.Trace = msg => app.Logger.LogDebug("{Trace}", msg);

    if (!string.IsNullOrEmpty(recheck) &&
        Enum.TryParse<CheckSeverity>(recheck, ignoreCase: true, out var recheckSev))
        validator.RecheckDeps = cache.GetRecheckDeps(domain, recheckSev);

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
    // Fields read by status endpoint, written by background task.
    // volatile ensures cross-thread visibility without locks.
    private volatile string? _currentCheck;
    private volatile int _status = (int)JobStatus.Running;
    private volatile ValidationReport? _report;
    private volatile string? _error;
    public string? CurrentCheck { get => _currentCheck; set => _currentCheck = value; }
    public JobStatus Status { get => (JobStatus)_status; set => _status = (int)value; }
    public ValidationReport? Report { get => _report; set => _report = value; }
    public string? Error { get => _error; set => _error = value; }
    public int CompletedChecks;
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    // References to services for live stats (read-only, shared singletons)
    public DnsResolverService? Dns { get; set; }
    public SmtpProbeService? Smtp { get; set; }
    // Baseline snapshots taken at job start — deltas computed at read time
    public int DnsHitsBaseline;
    public int DnsMissesBaseline;
    public int DnsResponsesBaseline;
    public int SmtpProbesStartedBaseline;
    public int SmtpProbesCompletedBaseline;
    public int PortsStartedBaseline;
    public int PortsCompletedBaseline;
    // Live severity counts — updated as each check result arrives
    public int PassCount;
    public int InfoCount;
    public int WarningCount;
    public int ErrorCount;
    public int CriticalCount;

    public void SnapshotBaselines()
    {
        if (Dns != null)
        {
            DnsHitsBaseline = Dns.CacheHits;
            DnsMissesBaseline = Dns.CacheMisses;
            DnsResponsesBaseline = Dns.ResponsesReceived;
        }
        if (Smtp != null)
        {
            SmtpProbesStartedBaseline = Smtp.ProbesStarted;
            SmtpProbesCompletedBaseline = Smtp.ProbesCompleted;
            PortsStartedBaseline = Smtp.PortsStarted;
            PortsCompletedBaseline = Smtp.PortsCompleted;
        }
    }
}

class ValidationTracker
{
    private readonly ConcurrentDictionary<string, ValidationJob> _jobs = new();

    public string StartValidation(string domain, DnsResolverService dns,
        SmtpProbeService smtp, HttpProbeService http, ValidationOptions? options,
        CacheManager cache, ILogger logger, CheckSeverity? recheckSeverity = null,
        bool trace = false, TraceMasker? traceMasker = null)
    {
        var jobId = Guid.NewGuid().ToString("N")[..12];
        var job = new ValidationJob { Domain = domain, Dns = dns, Smtp = smtp };
        _jobs[jobId] = job;

        _ = Task.Run(async () =>
        {
            try
            {
                var validator = new DomainValidator(dns, smtp, http);
                if (traceMasker != null) validator.TraceMask = traceMasker;
                if (trace) validator.Trace = msg => logger.LogDebug("{Trace}", msg);

                // Determine recheck deps (bypass MemoryCache without clearing shared entries)
                if (recheckSeverity != null)
                {
                    var deps = cache.GetRecheckDeps(domain, recheckSeverity.Value);
                    if (deps != RecheckHelper.CacheDep.None)
                    {
                        validator.RecheckDeps = deps;
                        var logDomain = traceMasker != null ? traceMasker.Hash(domain) : domain;
                        logger.LogInformation("Recheck: bypassing cache for {Domain} ({Deps})", logDomain, deps);
                    }
                }

                // Snapshot baselines AFTER validator is created but BEFORE ValidateAsync
                // runs (which calls ResetErrors and starts incrementing counters).
                job.SnapshotBaselines();

                validator.OnCheckStarted += name => job.CurrentCheck = name;
                validator.OnCheckCompleted += (_, result) =>
                {
                    Interlocked.Increment(ref job.CompletedChecks);
                    switch (result.Severity)
                    {
                        case CheckSeverity.Pass: Interlocked.Increment(ref job.PassCount); break;
                        case CheckSeverity.Info: Interlocked.Increment(ref job.InfoCount); break;
                        case CheckSeverity.Warning: Interlocked.Increment(ref job.WarningCount); break;
                        case CheckSeverity.Error: Interlocked.Increment(ref job.ErrorCount); break;
                        case CheckSeverity.Critical: Interlocked.Increment(ref job.CriticalCount); break;
                    }
                };

                var report = await validator.ValidateAsync(domain, options);
                job.Report = report;
                job.CurrentCheck = null;
                job.Status = JobStatus.Completed;

                _ = cache.SaveDomainResultAsync(domain, ValidationTracker.BuildSummary(report));
                cache.RequestFlush();
            }
            catch (Exception ex)
            {
                var errDomain = traceMasker != null ? traceMasker.Hash(domain) : domain;
                logger.LogError(ex, "Validation failed for {Domain}", errDomain);
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
