using System.Collections.Concurrent;
using System.Diagnostics;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core;

public class DomainValidator
{
    // Foundation checks run sequentially — they populate shared CheckContext state
    // (MxHosts, NsHosts, SpfRecord, DmarcRecord, etc.) that all other checks read.
    private readonly List<ICheck> _foundationChecks;

    // Concurrent checks run in parallel — they only read from CheckContext shared
    // state and are independent of each other.
    private readonly List<ICheck> _concurrentChecks;

    private readonly DnsResolverService _dns;
    private readonly SmtpProbeService _smtp;
    private readonly HttpProbeService _http;
    private Stopwatch? _validationSw;

    /// <summary>Optional trace callback for detailed timing diagnostics.</summary>
    public Action<string>? Trace
    {
        get => _dns.Trace;
        set
        {
            _dns.Trace = value;
            _smtp.Trace = value;
        }
    }

    /// <summary>
    /// Creates a new validator with fresh (non-shared) services.
    /// </summary>
    public DomainValidator() : this(new DnsResolverService(), new SmtpProbeService(), new HttpProbeService()) { }

    /// <summary>
    /// Creates a new validator using shared services whose caches persist
    /// across multiple <see cref="ValidateAsync"/> calls. This avoids
    /// repeating expensive DNS, SMTP, and HTTP lookups when checking
    /// multiple domains that share infrastructure.
    /// </summary>
    public DomainValidator(DnsResolverService dns, SmtpProbeService smtp, HttpProbeService http)
    {
        _dns = dns;
        _smtp = smtp;
        _http = http;

        // ── Foundation checks: run sequentially, populate shared state ────
        // Order matters here — later checks depend on state set by earlier ones.
        // Only checks that WRITE to CheckContext shared state belong here.
        // Everything else runs concurrently.
        _foundationChecks = new List<ICheck>
        {
            // AuthoritativeNsCheck → ctx.NsHosts, ctx.NsHostIps
            new AuthoritativeNsCheck(),

            // A/AAAA → ctx.DomainARecords, ctx.DomainAAAARecords
            new ARecordCheck(),
            new AAAARecordCheck(),

            // MX → ctx.MxHosts, ctx.MxHostIps
            new MxRecordsCheck(),

            // SPF → ctx.SpfRecord
            new SpfRecordCheck(),

            // DMARC → ctx.DmarcRecord
            new DmarcRecordCheck(),
        };

        // ── Concurrent checks: run in parallel, read-only on shared state ──
        _concurrentChecks = new List<ICheck>
        {
            // Delegation (reads NsHosts)
            new DelegationChainCheck(),
            new DelegationConsistencyCheck(),

            // SOA (reads NsHosts)
            new SoaRecordCheck(),
            new SoaSerialConsistencyCheck(),

            // Glue records
            new NsGlueRecordCheck(),

            // NS
            new NsRecordsCheck(),
            new NsMinimumCountCheck(),
            new NsLameDelegationCheck(),
            new NsNetworkDiversityCheck(),
            new DuplicateNsIpCheck(),
            new OpenRecursiveResolverCheck(),

            // CNAME
            new CnameChainCheck(),

            // MX (remaining — MxRecordsCheck is foundation)
            new MxIpDetectionCheck(),
            new MxPrivateIpCheck(),
            new MxCnameCheck(),
            new NullMxCheck(),
            new MxPriorityDistributionCheck(),
            new MxBackupSecurityCheck(),
            new MailSubdomainSurveyCheck(),

            // SPF (remaining — SpfRecordCheck is foundation)
            new SpfExpansionCheck(),
            new SpfLookupCountCheck(),
            new SpfIncludeDepthCheck(),
            new SpfRecordSizeCheck(),
            new SpfMacrosCheck(),
            new SpfIncludesAllCheck(),
            new SpfOverlapCheck(),
            new MxCoveredBySpfCheck(),
            new SubdomainSpfGapCheck(),

            // DMARC (remaining — DmarcRecordCheck is foundation)
            new DmarcPctAnalysisCheck(),
            new DmarcInheritanceCheck(),
            new DmarcExternalReportAuthCheck(),
            new DmarcReportTargetMxCheck(),
            new SpfDmarcCombinedCheck(),
            new SubdomainDmarcOverrideCheck(),
            new DmarcSubdomainPolicyCheck(),
            new DmarcReportUriValidationCheck(),

            // DKIM + ARC
            new DkimSelectorsCheck(),
            new ArcCheck(),

            // PTR
            new ReverseDnsCheck(),
            new MxReverseDnsCheck(),

            // FCrDNS
            new ForwardConfirmedRdnsCheck(),

            // Blocklists
            new IpBlocklistCheck(),
            new ExtendedDnsblCheck(),
            new DomainBlocklistCheck(),
            new MxHostnameBlocklistCheck(),

            // DNSSEC
            new DnssecCheck(),
            new NsecZoneWalkCheck(),

            // MTA-STS
            new MtaStsCheck(),

            // TLS-RPT
            new TlsRptCheck(),

            // BIMI
            new BimiCheck(),

            // DANE
            new DaneCheck(),
            new DaneTlsaCertMatchCheck(),

            // SMTP
            new SmtpTlsCertCheck(),
            new SmtpTlsVersionCheck(),
            new SmtpBannerCheck(),
            new EhloCapabilitiesCheck(),
            new SmtpSizeCheck(),
            new SmtpRequireTlsCheck(),
            new SmtpStarttlsEnforcementCheck(),
            new SmtpBannerRdnsMatchCheck(),
            new SmtpTransactionTimingCheck(),
            new SubmissionPortsCheck(),

            // SRV
            new SrvRecordsCheck(),

            // Autodiscover
            new AutodiscoverCheck(),

            // CAA
            new CaaRecordCheck(),

            // IPv6
            new Ipv6ReadinessCheck(),
            new SmtpIpv6ConnectivityCheck(),

            // Postmaster
            new PostmasterAddressCheck(),

            // Abuse
            new AbuseAddressCheck(),

            // DNS propagation
            new DnsPropagationCheck(),

            // Open relay detection
            new OpenRelayCheck(),

            // Catch-all detection
            new CatchAllDetectionCheck(),

            // Wildcard
            new WildcardDnsCheck(),

            // TTL
            new TtlSanityCheck(),

            // Zone Transfer
            new ZoneTransferCheck(),

            // security.txt
            new SecurityTxtCheck(),

            // Provider verification
            new ProviderVerificationTxtCheck(),

            // Certificate Transparency
            new CertificateTransparencyCheck(),

            // Duplicate/conflicting records
            new DuplicateTxtRecordCheck(),

            // TXT dump
            new AllTxtRecordsCheck(),
        };
    }

    public event Action<string>? OnCheckStarted;
    public event Action<string, CheckResult>? OnCheckCompleted;
    public event Action<string, TimeSpan>? OnCheckTiming;

    public async Task<ValidationReport> ValidateAsync(string domain, ValidationOptions? options = null)
    {
        var report = new ValidationReport { Domain = domain };
        _validationSw = Stopwatch.StartNew();

        // Reset per-validation state while keeping shared caches
        _dns.ResetErrors();

        var context = new CheckContext
        {
            Dns = _dns,
            Smtp = _smtp,
            Http = _http,
            Options = options ?? new ValidationOptions()
        };

        // ── Prefetch phase: fire DNS queries and SMTP probes in parallel ──
        TraceLog($"[PHASE] PREFETCH START for {domain}");
        var prefetchSw = Stopwatch.StartNew();
        await PrefetchAsync(domain, context);
        prefetchSw.Stop();
        TraceLog($"[PHASE] PREFETCH DONE: {prefetchSw.ElapsedMilliseconds}ms (dns:{_dns.CacheHits}h/{_dns.CacheMisses}m smtp:{_smtp.ProbesCompleted}p/{_smtp.PortsCompleted}ports)");
        OnCheckTiming?.Invoke("Prefetch", prefetchSw.Elapsed);

        // ── Foundation checks: sequential, populate shared state ──────────
        TraceLog($"[PHASE] FOUNDATION START ({_foundationChecks.Count} checks)");
        var foundationSw = Stopwatch.StartNew();
        var timedOutChecks = new List<ICheck>();

        foreach (var check in _foundationChecks)
            await RunCheckAsync(check, domain, context, report, timedOutChecks);

        foundationSw.Stop();
        TraceLog($"[PHASE] FOUNDATION DONE: {foundationSw.ElapsedMilliseconds}ms (mx:{context.MxHosts.Count} ns:{context.NsHosts.Count} spf:{(context.SpfRecord != null ? "yes" : "no")} dmarc:{(context.DmarcRecord != null ? "yes" : "no")})");

        // ── Concurrent checks: parallel, read-only on shared state ────────
        TraceLog($"[PHASE] CONCURRENT START ({_concurrentChecks.Count} checks, max 12 parallel)");
        var concurrentResults = new ConcurrentBag<(ICheck Check, List<CheckResult>? Results, CheckResult? Error, TimeSpan Elapsed, bool TimedOut)>();

        await Parallel.ForEachAsync(_concurrentChecks,
            new ParallelOptions { MaxDegreeOfParallelism = 12 },
            async (check, _) =>
            {
                var checkSw = Stopwatch.StartNew();
                try
                {
                    OnCheckStarted?.Invoke(check.Name);
                    var checkTask = check.RunAsync(domain, context);
                    var completedTask = await Task.WhenAny(checkTask, Task.Delay(TimeSpan.FromSeconds(45)));
                    checkSw.Stop();
                    OnCheckTiming?.Invoke(check.Name, checkSw.Elapsed);

                    if (completedTask == checkTask)
                    {
                        var results = await checkTask;
                        concurrentResults.Add((check, results, null, checkSw.Elapsed, false));
                    }
                    else
                    {
                        concurrentResults.Add((check, null, null, checkSw.Elapsed, true));
                    }
                }
                catch (Exception ex)
                {
                    checkSw.Stop();
                    OnCheckTiming?.Invoke(check.Name, checkSw.Elapsed);
                    var errorResult = new CheckResult
                    {
                        CheckName = check.Name,
                        Category = check.Category,
                        Severity = CheckSeverity.Error,
                        Summary = $"Check failed: {ex.Message}",
                        Errors = { ex.Message }
                    };
                    concurrentResults.Add((check, null, errorResult, checkSw.Elapsed, false));
                }
            });

        TraceLog($"[PHASE] CONCURRENT DONE: all {_concurrentChecks.Count} checks finished");

        // Collect results, preserving original check order for consistent output
        var concurrentMap = concurrentResults.ToDictionary(r => r.Check.Name);
        foreach (var check in _concurrentChecks)
        {
            if (!concurrentMap.TryGetValue(check.Name, out var entry)) continue;

            if (entry.TimedOut)
            {
                timedOutChecks.Add(check);
            }
            else if (entry.Results != null)
            {
                foreach (var r in entry.Results)
                {
                    report.Results.Add(r);
                    OnCheckCompleted?.Invoke(check.Name, r);
                }
            }
            else if (entry.Error != null)
            {
                report.Results.Add(entry.Error);
                OnCheckCompleted?.Invoke(check.Name, entry.Error);
            }
        }

        // ── Deferred retry: timed-out checks get a second attempt ─────────
        foreach (var check in timedOutChecks)
        {
            try
            {
                OnCheckStarted?.Invoke(check.Name);
                var checkTask = check.RunAsync(domain, context);
                var completedTask = await Task.WhenAny(checkTask, Task.Delay(TimeSpan.FromSeconds(30)));
                List<CheckResult> results;
                if (completedTask == checkTask)
                {
                    results = await checkTask;
                }
                else
                {
                    results = new List<CheckResult>
                    {
                        new CheckResult
                        {
                            CheckName = check.Name,
                            Category = check.Category,
                            Severity = CheckSeverity.Warning,
                            Summary = "Check timed out",
                            Warnings = { "Check did not complete within timeout — retried once" }
                        }
                    };
                }
                foreach (var r in results)
                {
                    report.Results.Add(r);
                    OnCheckCompleted?.Invoke(check.Name, r);
                }
            }
            catch (Exception ex)
            {
                var errorResult = new CheckResult
                {
                    CheckName = check.Name,
                    Category = check.Category,
                    Severity = CheckSeverity.Error,
                    Summary = $"Check failed: {ex.Message}",
                    Errors = { ex.Message }
                };
                report.Results.Add(errorResult);
                OnCheckCompleted?.Invoke(check.Name, errorResult);
            }
        }

        // Surface any DNS query errors so users know results may be incomplete
        var dnsErrors = _dns.QueryErrors.ToList();
        if (dnsErrors.Any())
        {
            report.Results.Add(new CheckResult
            {
                CheckName = "DNS Query Errors",
                Category = CheckCategory.NS,
                Severity = CheckSeverity.Warning,
                Summary = $"{dnsErrors.Count} DNS query error(s) — some results may be incomplete",
                Warnings = dnsErrors.Take(20).ToList(),
                Details = dnsErrors.Count > 20
                    ? new List<string> { $"...and {dnsErrors.Count - 20} more" }
                    : new List<string>()
            });
        }

        _validationSw.Stop();
        report.Duration = _validationSw.Elapsed;
        TraceLog($"[PHASE] VALIDATION COMPLETE: {_validationSw.ElapsedMilliseconds}ms total, {report.Results.Count} results (pass:{report.PassCount} warn:{report.WarningCount} err:{report.ErrorCount} crit:{report.CriticalCount})");
        return report;
    }

    private void TraceLog(string message)
    {
        if (Trace == null) return;
        var elapsed = _validationSw?.ElapsedMilliseconds ?? 0;
        Trace($"[{elapsed,7}ms] {message}");
    }

    private async Task RunCheckAsync(ICheck check, string domain, CheckContext context,
        ValidationReport report, List<ICheck> timedOutChecks)
    {
        try
        {
            OnCheckStarted?.Invoke(check.Name);
            TraceLog($"[CHECK] START {check.Name}");
            var checkSw = Stopwatch.StartNew();
            var checkTask = check.RunAsync(domain, context);
            var completedTask = await Task.WhenAny(checkTask, Task.Delay(TimeSpan.FromSeconds(45)));
            List<CheckResult> results;
            if (completedTask == checkTask)
            {
                results = await checkTask;
            }
            else
            {
                timedOutChecks.Add(check);
                checkSw.Stop();
                TraceLog($"[CHECK] TIMEOUT {check.Name}: {checkSw.ElapsedMilliseconds}ms");
                OnCheckTiming?.Invoke(check.Name, checkSw.Elapsed);
                return;
            }
            checkSw.Stop();
            var severities = string.Join(",", results.Select(r => r.Severity));
            TraceLog($"[CHECK] DONE {check.Name}: {checkSw.ElapsedMilliseconds}ms [{severities}]");
            OnCheckTiming?.Invoke(check.Name, checkSw.Elapsed);
            foreach (var r in results)
            {
                report.Results.Add(r);
                OnCheckCompleted?.Invoke(check.Name, r);
            }
        }
        catch (Exception ex)
        {
            var errorResult = new CheckResult
            {
                CheckName = check.Name,
                Category = check.Category,
                Severity = CheckSeverity.Error,
                Summary = $"Check failed: {ex.Message}",
                Errors = { ex.Message }
            };
            report.Results.Add(errorResult);
            OnCheckCompleted?.Invoke(check.Name, errorResult);
        }
    }

    /// <summary>
    /// Prefetches DNS records and SMTP probes to prime service caches.
    /// Phase 1 resolves core records. Phase 2 runs MX/NS host resolution,
    /// policy records, DKIM selectors, PTR lookups, and SMTP probes all
    /// concurrently — SMTP probes start as soon as MX IPs are available
    /// without waiting for unrelated DNS queries to complete.
    /// </summary>
    private async Task PrefetchAsync(string domain, CheckContext ctx)
    {
        try
        {
            // Phase 1: Core DNS records
            var mxTask = _dns.GetMxRecordsAsync(domain);
            var nsTask = _dns.GetNsRecordsAsync(domain);
            var aTask = _dns.ResolveAAsync(domain);
            var aaaaTask = _dns.ResolveAAAAAsync(domain);
            var txtTask = _dns.QueryAsync(domain, DnsClient.QueryType.TXT);
            var soaTask = _dns.QueryAsync(domain, DnsClient.QueryType.SOA);

            await Task.WhenAll(mxTask, nsTask, aTask, aaaaTask, txtTask, soaTask);

            var mxRecords = await mxTask;
            var nsRecords = await nsTask;

            // Phase 2: Everything else in parallel — DNS, PTR, and SMTP probes
            // all start at the same time. Rate limiting is in DnsResolverService.
            var mxHosts = mxRecords.Select(m => m.Exchange.Value.TrimEnd('.')).Where(h => !string.IsNullOrEmpty(h)).Distinct().ToList();
            var nsHosts = nsRecords.Select(n => n.NSDName.Value.TrimEnd('.')).Where(h => !string.IsNullOrEmpty(h)).Distinct().ToList();

            var allTasks = new List<Task>();

            // MX/NS host IP resolution
            foreach (var host in mxHosts.Concat(nsHosts).Distinct())
            {
                allTasks.Add(_dns.ResolveAAsync(host));
                allTasks.Add(_dns.ResolveAAAAAsync(host));
            }

            // Policy/security records
            allTasks.Add(_dns.QueryAsync($"_dmarc.{domain}", DnsClient.QueryType.TXT));
            allTasks.Add(_dns.QueryAsync($"_mta-sts.{domain}", DnsClient.QueryType.TXT));
            allTasks.Add(_dns.QueryAsync($"_smtp._tls.{domain}", DnsClient.QueryType.TXT));
            allTasks.Add(_dns.QueryAsync($"_bimi.{domain}", DnsClient.QueryType.TXT));
            allTasks.Add(_dns.QueryAsync(domain, DnsClient.QueryType.CAA));
            allTasks.Add(_dns.QueryAsync(domain, DnsClient.QueryType.CNAME));
            allTasks.Add(_dns.QueryAsync(domain, DnsClient.QueryType.DS));
            allTasks.Add(_dns.QueryAsync(domain, DnsClient.QueryType.DNSKEY));

            // DKIM selectors — trimmed to common providers
            var selectors = new[] { "default", "google", "selector1", "selector2" };
            foreach (var sel in selectors.Concat(ctx.Options.AdditionalDkimSelectors).Distinct())
                allTasks.Add(_dns.QueryAsync($"{sel}._domainkey.{domain}", DnsClient.QueryType.TXT));

            // PTR lookups for domain IPs
            var domainIps = await aTask;
            foreach (var ip in domainIps)
                allTasks.Add(_dns.ResolvePtrAsync(ip));

            // SMTP probes + PTR for MX hosts — start immediately, don't wait for DNS phase
            var smtpSemaphore = new SemaphoreSlim(3);
            foreach (var host in mxHosts)
            {
                // Resolve MX host IPs then probe — chained but non-blocking to other tasks
                var h = host;
                allTasks.Add(Task.Run(async () =>
                {
                    var ips = await _dns.ResolveAAsync(h);
                    // PTR lookups for MX IPs
                    var ptrTasks = ips.Select(ip => _dns.ResolvePtrAsync(ip));

                    // SMTP probe on port 25
                    await smtpSemaphore.WaitAsync();
                    try { await _smtp.ProbeSmtpAsync(h, 25); }
                    finally { smtpSemaphore.Release(); }

                    await Task.WhenAll(ptrTasks);
                }));

                // Submission port probes (independent of IP resolution)
                allTasks.Add(Task.Run(() => _smtp.ProbePortAsync(h, 587)));
                allTasks.Add(Task.Run(() => _smtp.ProbePortAsync(h, 465)));
            }

            await Task.WhenAll(allTasks);
        }
        catch
        {
            // Prefetch is best-effort — any failures will be retried by the checks themselves
        }
    }
}
