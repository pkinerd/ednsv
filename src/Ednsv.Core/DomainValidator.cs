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

    public DomainValidator()
    {
        _dns = new DnsResolverService();
        _smtp = new SmtpProbeService();
        _http = new HttpProbeService();

        _checks = new List<ICheck>
        {
            // Delegation (1-3)
            new DelegationChainCheck(),
            new AuthoritativeNsCheck(),
            new DelegationConsistencyCheck(),

            // SOA (4)
            new SoaRecordCheck(),

            // Glue records
            new NsGlueRecordCheck(),

            // NS (5-8)
            new NsRecordsCheck(),
            new NsMinimumCountCheck(),
            new NsLameDelegationCheck(),
            new NsNetworkDiversityCheck(),
            new DuplicateNsIpCheck(),

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

    public async Task<ValidationReport> ValidateAsync(string domain, ValidationOptions? options = null)
    {
        var report = new ValidationReport { Domain = domain };
        var sw = Stopwatch.StartNew();

        var context = new CheckContext
        {
            Dns = _dns,
            Smtp = _smtp,
            Http = _http,
            Options = options ?? new ValidationOptions()
        };

        foreach (var check in _checks)
        {
            try
            {
                OnCheckStarted?.Invoke(check.Name);
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
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
                            Summary = "Check timed out (30s limit)",
                            Warnings = { "Check did not complete within timeout" }
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
        if (_dns.QueryErrors.Any())
        {
            report.Results.Add(new CheckResult
            {
                CheckName = "DNS Query Errors",
                Category = CheckCategory.NS,
                Severity = CheckSeverity.Warning,
                Summary = $"{_dns.QueryErrors.Count} DNS query error(s) — some results may be incomplete",
                Warnings = _dns.QueryErrors.Take(20).ToList(),
                Details = _dns.QueryErrors.Count > 20
                    ? new List<string> { $"...and {_dns.QueryErrors.Count - 20} more" }
                    : new List<string>()
            });
        }

        sw.Stop();
        report.Duration = sw.Elapsed;
        return report;
    }
}
