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

            // NS (5-8)
            new NsRecordsCheck(),
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
            new MxCnameCheck(),
            new NullMxCheck(),
            new MxPriorityDistributionCheck(),
            new MxBackupSecurityCheck(),

            // SPF (16-21)
            new SpfRecordCheck(),
            new SpfExpansionCheck(),
            new SpfLookupCountCheck(),
            new SpfIncludeDepthCheck(),
            new SpfRecordSizeCheck(),
            new SpfMacrosCheck(),

            // DMARC (22-27)
            new DmarcRecordCheck(),
            new DmarcInheritanceCheck(),
            new DmarcExternalReportAuthCheck(),
            new DmarcReportTargetMxCheck(),
            new SpfDmarcCombinedCheck(),
            new SubdomainDmarcOverrideCheck(),

            // DKIM (28)
            new DkimSelectorsCheck(),

            // PTR (29)
            new ReverseDnsCheck(),

            // FCrDNS (30)
            new ForwardConfirmedRdnsCheck(),

            // Blocklists (31-32)
            new IpBlocklistCheck(),
            new DomainBlocklistCheck(),

            // DNSSEC (33)
            new DnssecCheck(),

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
            new SmtpBannerCheck(),
            new EhloCapabilitiesCheck(),
            new SubmissionPortsCheck(),

            // SRV (44)
            new SrvRecordsCheck(),

            // Autodiscover (45)
            new AutodiscoverCheck(),

            // CAA (46)
            new CaaRecordCheck(),

            // IPv6 (47)
            new Ipv6ReadinessCheck(),

            // Postmaster (48)
            new PostmasterAddressCheck(),

            // Abuse (49)
            new AbuseAddressCheck(),

            // Wildcard (50)
            new WildcardDnsCheck(),

            // TTL (52)
            new TtlSanityCheck(),

            // Zone Transfer (53)
            new ZoneTransferCheck(),

            // security.txt (54)
            new SecurityTxtCheck(),

            // TXT dump (55)
            new AllTxtRecordsCheck(),
        };
    }

    public event Action<string>? OnCheckStarted;
    public event Action<string, CheckResult>? OnCheckCompleted;

    public async Task<ValidationReport> ValidateAsync(string domain)
    {
        var report = new ValidationReport { Domain = domain };
        var sw = Stopwatch.StartNew();

        var context = new CheckContext
        {
            Dns = _dns,
            Smtp = _smtp,
            Http = _http
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

        sw.Stop();
        report.Duration = sw.Elapsed;
        return report;
    }
}
