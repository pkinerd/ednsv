using System.Diagnostics;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core;

public class DomainValidator
{
    private readonly List<ICheck> _checks;
    private readonly DnsResolverService _dns;
    private readonly SmtpProbeService _smtp;
    private readonly HttpProbeService _http;

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

        _checks = new List<ICheck>
        {
            // Delegation (1-3)
            new DelegationChainCheck(),
            new AuthoritativeNsCheck(),
            new DelegationConsistencyCheck(),

            // SOA (4)
            new SoaRecordCheck(),
            new SoaSerialConsistencyCheck(),

            // Glue records
            new NsGlueRecordCheck(),

            // NS (5-8)
            new NsRecordsCheck(),
            new NsMinimumCountCheck(),
            new NsLameDelegationCheck(),
            new NsNetworkDiversityCheck(),
            new DuplicateNsIpCheck(),
            new OpenRecursiveResolverCheck(),

            // CNAME (9)
            new CnameChainCheck(),

            // A/AAAA (10-11)
            new ARecordCheck(),
            new AAAARecordCheck(),

            // MX (12-16, 51, 43)
            new MxRecordsCheck(),
            new MxIpDetectionCheck(),
            new MxPrivateIpCheck(),
            new MxCnameCheck(),
            new NullMxCheck(),
            new MxPriorityDistributionCheck(),
            new MxBackupSecurityCheck(),
            new MailSubdomainSurveyCheck(),

            // SPF (16-21)
            new SpfRecordCheck(),
            new SpfExpansionCheck(),
            new SpfLookupCountCheck(),
            new SpfIncludeDepthCheck(),
            new SpfRecordSizeCheck(),
            new SpfMacrosCheck(),
            new SpfIncludesAllCheck(),
            new SpfOverlapCheck(),
            new MxCoveredBySpfCheck(),
            new SubdomainSpfGapCheck(),

            // DMARC (22-27)
            new DmarcRecordCheck(),
            new DmarcPctAnalysisCheck(),
            new DmarcInheritanceCheck(),
            new DmarcExternalReportAuthCheck(),
            new DmarcReportTargetMxCheck(),
            new SpfDmarcCombinedCheck(),
            new SubdomainDmarcOverrideCheck(),
            new DmarcSubdomainPolicyCheck(),
            new DmarcReportUriValidationCheck(),

            // DKIM (28) + ARC
            new DkimSelectorsCheck(),
            new ArcCheck(),

            // PTR (29)
            new ReverseDnsCheck(),
            new MxReverseDnsCheck(),

            // FCrDNS (30)
            new ForwardConfirmedRdnsCheck(),

            // Blocklists (31-32)
            new IpBlocklistCheck(),
            new ExtendedDnsblCheck(),
            new DomainBlocklistCheck(),
            new MxHostnameBlocklistCheck(),

            // DNSSEC (33)
            new DnssecCheck(),
            new NsecZoneWalkCheck(),

            // MTA-STS (34)
            new MtaStsCheck(),

            // TLS-RPT (35)
            new TlsRptCheck(),

            // BIMI (36)
            new BimiCheck(),

            // DANE (37, 39)
            new DaneCheck(),
            new DaneTlsaCertMatchCheck(),

            // SMTP (38, 40-42)
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

            // SRV (44)
            new SrvRecordsCheck(),

            // Autodiscover (45)
            new AutodiscoverCheck(),

            // CAA (46)
            new CaaRecordCheck(),

            // IPv6 (47)
            new Ipv6ReadinessCheck(),
            new SmtpIpv6ConnectivityCheck(),

            // Postmaster (48)
            new PostmasterAddressCheck(),

            // Abuse (49)
            new AbuseAddressCheck(),

            // DNS propagation
            new DnsPropagationCheck(),

            // Open relay detection
            new OpenRelayCheck(),

            // Catch-all detection
            new CatchAllDetectionCheck(),

            // Wildcard (50)
            new WildcardDnsCheck(),

            // TTL (52)
            new TtlSanityCheck(),

            // Zone Transfer (53)
            new ZoneTransferCheck(),

            // security.txt (54)
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
        var sw = Stopwatch.StartNew();

        // Reset per-validation state while keeping shared caches
        _dns.ResetErrors();

        var context = new CheckContext
        {
            Dns = _dns,
            Smtp = _smtp,
            Http = _http,
            Options = options ?? new ValidationOptions()
        };

        // ── Prefetch phase: fire common DNS queries and SMTP probes in parallel ──
        // This primes the service caches so sequential checks hit cache instead of
        // waiting on network I/O one-by-one.
        await PrefetchAsync(domain, context);

        var timedOutChecks = new List<ICheck>();

        foreach (var check in _checks)
        {
            try
            {
                OnCheckStarted?.Invoke(check.Name);
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
                    // Track for deferred retry instead of immediately reporting timeout
                    timedOutChecks.Add(check);
                    checkSw.Stop();
                    OnCheckTiming?.Invoke(check.Name, checkSw.Elapsed);
                    continue;
                }
                checkSw.Stop();
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

        // Deferred retry: timed-out checks get a second attempt.
        // By now, slow DNS responses may have resolved and been cached.
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
        var dnsErrors = _dns.QueryErrors.ToList(); // snapshot for consistent reads
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

        sw.Stop();
        report.Duration = sw.Elapsed;
        return report;
    }

    /// <summary>
    /// Prefetches common DNS records and SMTP probes in batches to prime the
    /// service caches. Concurrency is capped to avoid looking abusive — DNS
    /// queries go through the configured resolver (not hammering authoritative
    /// servers directly) and SMTP probes are limited to 3 at a time.
    /// </summary>
    private async Task PrefetchAsync(string domain, CheckContext ctx)
    {
        try
        {
            // Phase 1: Core DNS records — small batch, all go through our configured
            // resolver (Google/Cloudflare) which handles its own rate limiting.
            var mxTask = _dns.GetMxRecordsAsync(domain);
            var nsTask = _dns.GetNsRecordsAsync(domain);
            var aTask = _dns.ResolveAAsync(domain);
            var aaaaTask = _dns.ResolveAAAAAsync(domain);
            var txtTask = _dns.QueryAsync(domain, DnsClient.QueryType.TXT);
            var soaTask = _dns.QueryAsync(domain, DnsClient.QueryType.SOA);

            await Task.WhenAll(mxTask, nsTask, aTask, aaaaTask, txtTask, soaTask);

            var mxRecords = await mxTask;
            var nsRecords = await nsTask;

            // Phase 2: Resolve MX/NS host IPs + policy records (throttled to 8 concurrent)
            var mxHosts = mxRecords.Select(m => m.Exchange.Value.TrimEnd('.')).Where(h => !string.IsNullOrEmpty(h)).Distinct().ToList();
            var nsHosts = nsRecords.Select(n => n.NSDName.Value.TrimEnd('.')).Where(h => !string.IsNullOrEmpty(h)).Distinct().ToList();

            var dnsSemaphore = new SemaphoreSlim(8);
            var phase2Tasks = new List<Task>();

            Task ThrottledDns(Func<Task> query)
            {
                return Task.Run(async () =>
                {
                    await dnsSemaphore.WaitAsync();
                    try { await query(); }
                    finally { dnsSemaphore.Release(); }
                });
            }

            foreach (var host in mxHosts.Concat(nsHosts).Distinct())
            {
                phase2Tasks.Add(ThrottledDns(() => _dns.ResolveAAsync(host)));
                phase2Tasks.Add(ThrottledDns(() => _dns.ResolveAAAAAsync(host)));
            }

            // Policy/security records
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync($"_dmarc.{domain}", DnsClient.QueryType.TXT)));
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync($"_mta-sts.{domain}", DnsClient.QueryType.TXT)));
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync($"_smtp._tls.{domain}", DnsClient.QueryType.TXT)));
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync($"_bimi.{domain}", DnsClient.QueryType.TXT)));
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync(domain, DnsClient.QueryType.CAA)));
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync(domain, DnsClient.QueryType.CNAME)));
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync(domain, DnsClient.QueryType.DS)));
            phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync(domain, DnsClient.QueryType.DNSKEY)));

            // DKIM selectors
            var selectors = new[] { "default", "google", "selector1", "selector2", "k1", "s1", "s2", "dkim" };
            foreach (var sel in selectors.Concat(ctx.Options.AdditionalDkimSelectors).Distinct())
                phase2Tasks.Add(ThrottledDns(() => _dns.QueryAsync($"{sel}._domainkey.{domain}", DnsClient.QueryType.TXT)));

            await Task.WhenAll(phase2Tasks);

            // Phase 3: PTR lookups + SMTP probes — SMTP limited to 3 concurrent
            // to be respectful of mail servers (each probe opens a TCP connection).
            var smtpSemaphore = new SemaphoreSlim(3);
            var phase3Tasks = new List<Task>();

            foreach (var host in mxHosts)
            {
                var ips = await _dns.ResolveAAsync(host);
                foreach (var ip in ips)
                    phase3Tasks.Add(ThrottledDns(() => _dns.ResolvePtrAsync(ip)));

                phase3Tasks.Add(Task.Run(async () =>
                {
                    await smtpSemaphore.WaitAsync();
                    try { await _smtp.ProbeSmtpAsync(host, 25); }
                    finally { smtpSemaphore.Release(); }
                }));
            }

            var domainIps = await aTask;
            foreach (var ip in domainIps)
                phase3Tasks.Add(ThrottledDns(() => _dns.ResolvePtrAsync(ip)));

            if (phase3Tasks.Count > 0)
                await Task.WhenAll(phase3Tasks);
        }
        catch
        {
            // Prefetch is best-effort — any failures will be retried by the checks themselves
        }
    }
}
