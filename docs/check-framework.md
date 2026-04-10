# Check Framework & Categories

This document describes the check system — how individual checks are structured, how they share state, and how they are organized into categories.

## Core Types

```mermaid
classDiagram
    class ICheck {
        <<interface>>
        +string Name
        +CheckCategory Category
        +RunAsync(domain, context) Task~List~CheckResult~~
    }

    class CheckContext {
        +DnsResolverService Dns
        +SmtpProbeService Smtp
        +HttpProbeService Http
        +ValidationOptions Options
        +List~string~ MxHosts
        +ConcurrentDictionary MxHostIps
        +List~string~ NsHosts
        +ConcurrentDictionary NsHostIps
        +string? SpfRecord
        +string? DmarcRecord
        +List~string~ DomainARecords
        +List~string~ DomainAAAARecords
        +bool MxLookupFailed
        +bool NsLookupFailed
        +bool SpfLookupFailed
        +bool DmarcLookupFailed
        +ConcurrentDictionary SmtpProbeCache
        +ConcurrentBag~string~ QueryErrors
        +SeverityForMissing(lookupFailed) CheckSeverity
        +GetOrProbeSmtpAsync(host, port) SmtpProbeResult
    }

    class CheckResult {
        +string CheckName
        +CheckCategory Category
        +CheckSeverity Severity
        +string Summary
        +List~string~ Details
        +List~string~ Warnings
        +List~string~ Errors
        +AdjustForUnreachableHosts(total, unreachable)
    }

    class ValidationReport {
        +string Domain
        +DateTime Timestamp
        +TimeSpan Duration
        +List~CheckResult~ Results
        +int PassCount
        +int WarningCount
        +int ErrorCount
        +int CriticalCount
    }

    class ValidationOptions {
        +bool EnableAxfr
        +bool EnableCatchAll
        +bool EnableOpenRelay
        +bool EnableOpenResolver
        +string OpenResolverTestDomain
        +List~string~ AdditionalDkimSelectors
        +bool EnablePrivateDnsbl
    }

    class CheckSeverity {
        <<enumeration>>
        Info
        Pass
        Warning
        Error
        Critical
    }

    class CheckCategory {
        <<enumeration>>
        Delegation
        SOA
        NS
        CNAME
        A / AAAA
        MX
        SPF / DMARC / DKIM
        PTR / FCrDNS
        DNSBL / DomainBL
        DNSSEC
        MTASTS / TLSRPT / BIMI / DANE
        SMTP / SRV / Autodiscover
        CAA / IPv6
        Postmaster / Abuse
        Wildcard / TTL / ZoneTransfer
        SecurityTxt / TXT
    }

    ICheck --> CheckContext : receives
    ICheck --> CheckResult : returns
    CheckResult --> CheckSeverity : uses
    CheckResult --> CheckCategory : uses
    CheckContext --> ValidationOptions : holds
    ValidationReport --> CheckResult : contains
```

## The ICheck Interface

Every check implements `ICheck` (defined in `src/Ednsv.Core/Checks/ICheck.cs`):

```csharp
public interface ICheck
{
    string Name { get; }
    CheckCategory Category { get; }
    Task<List<CheckResult>> RunAsync(string domain, CheckContext context);
}
```

A single check can return **multiple** CheckResult objects (e.g., a check might report both findings and warnings).

## CheckContext: Shared State

`CheckContext` is the shared data container passed to every check. It provides:

**Service References** — access to DNS, SMTP, and HTTP services for making queries.

**Shared State** (populated by foundation checks, read by concurrent checks):
- `MxHosts` / `MxHostIps` — MX hostnames and their resolved IPs
- `NsHosts` / `NsHostIps` — NS hostnames and their resolved IPs
- `SpfRecord` / `DmarcRecord` — Raw SPF and DMARC record strings
- `DomainARecords` / `DomainAAAARecords` — Domain's A and AAAA records

**Lookup Failure Flags** — indicate whether a foundation lookup had a transient failure (SERVFAIL/timeout) vs simply returning no records:
- `MxLookupFailed`, `NsLookupFailed`, `SpfLookupFailed`, `DmarcLookupFailed`
- Used by `SeverityForMissing(lookupFailed)`: returns `Warning` if the lookup failed (uncertain), `Info` if the record is definitively absent
- NXDOMAIN is treated as definitive absence, NOT as a lookup failure

**Per-Validation SMTP Cache** — `SmtpProbeCache` (ConcurrentDictionary) stores SMTP probe results from the prefetch phase. Checks should use `GetOrProbeSmtpAsync()` to read from this cache rather than calling the service directly.

**Diagnostics** — `QueryErrors` (ConcurrentBag) collects per-validation DNS errors that are surfaced in the final report.

## Severity Levels

| Level | Meaning |
|-------|---------|
| **Info** | Informational — record absent or advisory finding |
| **Pass** | Check passed successfully |
| **Warning** | Potential issue or uncertain result (transient failure) |
| **Error** | Definite misconfiguration or failure |
| **Critical** | Severe issue that likely causes mail delivery failure |

The `AdjustForUnreachableHosts()` method downgrades a `Pass` to `Warning` when some or all MX hosts were unreachable during SMTP probing.

## Check Categories

30 categories organized into functional groups:

```mermaid
graph LR
    subgraph DNS["DNS Infrastructure"]
        Delegation
        SOA
        NS
        CNAME
        A_AAAA["A / AAAA"]
        DNSSEC
        Wildcard
        TTL
        ZoneTransfer
        CAA
        TXT
    end

    subgraph Email["Email Authentication"]
        MX
        SPF
        DMARC
        DKIM
    end

    subgraph MailServer["Mail Server Security"]
        PTR
        FCrDNS
        DNSBL
        DomainBL
        SMTP
    end

    subgraph Transport["Transport Security"]
        MTASTS["MTA-STS"]
        TLSRPT["TLS-RPT"]
        DANE
    end

    subgraph Brand["Brand Protection"]
        BIMI
    end

    subgraph Ops["Operational"]
        Postmaster
        Abuse
        SecurityTxt
        IPv6
        SRV
        Autodiscover
    end

    style DNS fill:#e8f4fd,stroke:#1a73e8
    style Email fill:#fef7e0,stroke:#f9ab00
    style MailServer fill:#fce8e6,stroke:#ea4335
    style Transport fill:#e6f4ea,stroke:#34a853
    style Brand fill:#f3e8fd,stroke:#9334e6
    style Ops fill:#fef0e1,stroke:#e8710a
```

## Check Module Map

Each check file in `src/Ednsv.Core/Checks/` contains multiple related checks:

| File | Categories | Key Checks |
|------|-----------|------------|
| `BasicRecordChecks.cs` | A, AAAA, CNAME | ARecordCheck, AAAARecordCheck, CnameChainCheck |
| `DelegationChecks.cs` | Delegation | AuthoritativeNsCheck, DelegationChainCheck, DelegationConsistencyCheck |
| `DkimChecks.cs` | DKIM | DkimSelectorsCheck, ArcCheck |
| `DmarcChecks.cs` | DMARC | DmarcRecordCheck, DmarcPctAnalysisCheck, DmarcInheritanceCheck, DmarcReportUriValidationCheck, and more |
| `ExtendedChecks.cs` | CAA, DANE, SecurityTxt | CaaRecordCheck, DaneCheck, DaneTlsaCertMatchCheck, SecurityTxtCheck, ProviderVerificationTxtCheck, CertificateTransparencyCheck |
| `HighValueChecks.cs` | MTA-STS, TLS-RPT, BIMI, DNSSEC, ZoneTransfer | MtaStsCheck, TlsRptCheck, BimiCheck, DnssecCheck, NsecZoneWalkCheck, ZoneTransferCheck |
| `MiscChecks.cs` | Wildcard, TTL, TXT, SRV, Autodiscover | WildcardDnsCheck, TtlSanityCheck, DuplicateTxtRecordCheck, AllTxtRecordsCheck, SrvRecordsCheck, AutodiscoverCheck |
| `MxChecks.cs` | MX | MxRecordsCheck, MxIpDetectionCheck, MxPrivateIpCheck, MxCnameCheck, NullMxCheck, MxPriorityDistributionCheck, MxBackupSecurityCheck |
| `NsChecks.cs` | NS | NsRecordsCheck, NsMinimumCountCheck, NsLameDelegationCheck, NsNetworkDiversityCheck, DuplicateNsIpCheck, OpenRecursiveResolverCheck |
| `PtrAndBlacklistChecks.cs` | PTR, FCrDNS, DNSBL, DomainBL | ReverseDnsCheck, MxReverseDnsCheck, ForwardConfirmedRdnsCheck, IpBlocklistCheck, ExtendedDnsblCheck, DomainBlocklistCheck |
| `SecurityChecks.cs` | DNSSEC, SMTP | SmtpTlsCertCheck, SmtpTlsVersionCheck, DnsPropagationCheck |
| `SmtpChecks.cs` | SMTP, IPv6, Postmaster, Abuse | SmtpBannerCheck, EhloCapabilitiesCheck, SmtpStarttlsEnforcementCheck, SubmissionPortsCheck, SmtpIpv6ConnectivityCheck, PostmasterAddressCheck, AbuseAddressCheck, and more |
| `SpfChecks.cs` | SPF | SpfRecordCheck, SpfExpansionCheck, SpfLookupCountCheck, SpfIncludeDepthCheck, SpfMacrosCheck, MxCoveredBySpfCheck, SubdomainSpfGapCheck, and more |

## Foundation vs. Concurrent Checks

### Foundation Checks (6, sequential)

These **write** to CheckContext shared state. They run in a fixed order because later checks depend on earlier ones:

1. **AuthoritativeNsCheck** — resolves authoritative nameservers, populates `NsHosts`/`NsHostIps`
2. **ARecordCheck** — resolves domain A records, populates `DomainARecords`
3. **AAAARecordCheck** — resolves domain AAAA records, populates `DomainAAAARecords`
4. **MxRecordsCheck** — resolves MX records, populates `MxHosts`/`MxHostIps`
5. **SpfRecordCheck** — parses SPF TXT record, populates `SpfRecord`
6. **DmarcRecordCheck** — parses DMARC record, populates `DmarcRecord`

### Concurrent Checks (~50, parallel)

These **read** from CheckContext shared state. They are independent of each other and run with `MaxDegreeOfParallelism = 12`. Examples:

- **DelegationChainCheck** reads `NsHosts` to validate the delegation chain
- **SpfExpansionCheck** reads `SpfRecord` to expand and analyze SPF mechanisms
- **SmtpTlsCertCheck** reads `MxHosts` and uses `GetOrProbeSmtpAsync()` to check certificates
- **IpBlocklistCheck** reads `MxHostIps` to query DNS blocklists

## ValidationOptions

Optional features controlled per-validation:

| Option | Default | Description |
|--------|---------|-------------|
| `EnableAxfr` | false | Attempt zone transfer (AXFR) to discover DKIM selectors |
| `EnableCatchAll` | false | Test if domain accepts mail to random addresses |
| `EnableOpenRelay` | false | Test if MX hosts relay mail for external domains |
| `EnableOpenResolver` | false | Test if NS hosts answer recursive queries |
| `AdditionalDkimSelectors` | empty | Extra DKIM selectors to probe beyond defaults |
| `EnablePrivateDnsbl` | false | Query blocklists requiring registered resolvers (Spamhaus, etc.) |
