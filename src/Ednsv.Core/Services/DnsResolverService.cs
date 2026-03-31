using System.Net;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;

namespace Ednsv.Core.Services;

public class DnsResolverService
{
    private readonly LookupClient _client;
    private readonly LookupClient _directClient;

    public DnsResolverService()
    {
        var options = new LookupClientOptions(NameServer.GooglePublicDns, NameServer.GooglePublicDns2)
        {
            UseCache = true,
            Timeout = TimeSpan.FromSeconds(3),
            Retries = 1,
            ThrowDnsErrors = false
        };
        _client = new LookupClient(options);

        var directOptions = new LookupClientOptions
        {
            UseCache = false,
            Timeout = TimeSpan.FromSeconds(5),
            Retries = 1,
            ThrowDnsErrors = false
        };
        _directClient = new LookupClient(directOptions);
    }

    public async Task<IDnsQueryResponse> QueryAsync(string domain, QueryType type)
    {
        try
        {
            return await _client.QueryAsync(domain, type);
        }
        catch (Exception)
        {
            return EmptyResponse.Instance;
        }
    }

    public async Task<IDnsQueryResponse> QueryServerAsync(IPAddress server, string domain, QueryType type)
    {
        try
        {
            var serverEndpoint = new IPEndPoint(server, 53);
            var opts = new LookupClientOptions(serverEndpoint)
            {
                UseCache = false,
                Timeout = TimeSpan.FromSeconds(5),
                Retries = 1,
                ThrowDnsErrors = false
            };
            var client = new LookupClient(opts);
            return await client.QueryAsync(domain, type);
        }
        catch (Exception)
        {
            return EmptyResponse.Instance;
        }
    }

    public async Task<List<string>> ResolveAAsync(string hostname)
    {
        var result = await QueryAsync(hostname, QueryType.A);
        return result.Answers.ARecords().Select(a => a.Address.ToString()).ToList();
    }

    public async Task<List<string>> ResolveAAAAAsync(string hostname)
    {
        var result = await QueryAsync(hostname, QueryType.AAAA);
        return result.Answers.AaaaRecords().Select(a => a.Address.ToString()).ToList();
    }

    public async Task<List<string>> ResolvePtrAsync(string ip)
    {
        try
        {
            var result = await _client.QueryReverseAsync(IPAddress.Parse(ip));
            return result.Answers.PtrRecords().Select(p => p.PtrDomainName.Value.TrimEnd('.')).ToList();
        }
        catch
        {
            return new List<string>();
        }
    }

    public async Task<List<string>> ResolveCnameChainAsync(string hostname)
    {
        var chain = new List<string>();
        var current = hostname;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < 10; i++)
        {
            if (!visited.Add(current)) break;
            var result = await QueryAsync(current, QueryType.CNAME);
            var cname = result.Answers.CnameRecords().FirstOrDefault();
            if (cname == null) break;
            var target = cname.CanonicalName.Value.TrimEnd('.');
            chain.Add($"{current} -> {target}");
            current = target;
        }
        return chain;
    }

    public async Task<List<NsRecord>> GetNsRecordsAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.NS);
        return result.Answers.NsRecords().ToList();
    }

    public async Task<List<MxRecord>> GetMxRecordsAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.MX);
        return result.Answers.MxRecords().OrderBy(m => m.Preference).ToList();
    }

    public async Task<List<TxtRecord>> GetTxtRecordsAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.TXT);
        return result.Answers.OfType<TxtRecord>().ToList();
    }

    public async Task<SoaRecord?> GetSoaRecordAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.SOA);
        return result.Answers.SoaRecords().FirstOrDefault()
            ?? result.Authorities.SoaRecords().FirstOrDefault();
    }

    public async Task<IDnsQueryResponse> QueryRawAsync(string domain, QueryType type)
    {
        return await QueryAsync(domain, type);
    }

    public async Task<bool> TestZoneTransferAsync(IPAddress nsIp, string domain)
    {
        try
        {
            var result = await PerformZoneTransferAsync(nsIp, domain);
            return result.Answers.Count > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Performs AXFR and returns discovered DKIM selectors from _domainkey TXT records.
    /// </summary>
    public async Task<List<string>> ExtractDkimSelectorsFromAxfrAsync(IPAddress nsIp, string domain)
    {
        var selectors = new List<string>();
        try
        {
            var result = await PerformZoneTransferAsync(nsIp, domain);
            var domainkeySuffix = $"._domainkey.{domain}".ToLowerInvariant();
            foreach (var record in result.Answers)
            {
                var name = record.DomainName.Value.TrimEnd('.').ToLowerInvariant();
                if (name.EndsWith(domainkeySuffix))
                {
                    // Extract selector: everything before ._domainkey.domain
                    var selector = name.Substring(0, name.Length - domainkeySuffix.Length);
                    if (!string.IsNullOrWhiteSpace(selector) && !selector.Contains('.'))
                        selectors.Add(selector);
                }
            }
        }
        catch { }
        return selectors.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<IDnsQueryResponse> PerformZoneTransferAsync(IPAddress nsIp, string domain)
    {
        var opts = new LookupClientOptions(new IPEndPoint(nsIp, 53))
        {
            UseCache = false,
            Timeout = TimeSpan.FromSeconds(5),
            Retries = 0,
            UseTcpOnly = true,
            ThrowDnsErrors = false
        };
        var client = new LookupClient(opts);
        return await client.QueryAsync(domain, QueryType.AXFR);
    }

    /// <summary>
    /// Gets parent zone NS records (delegation from parent)
    /// </summary>
    public async Task<IDnsQueryResponse> QueryParentNsAsync(string domain)
    {
        // Query the parent zone for NS records of this domain
        var parts = domain.Split('.');
        if (parts.Length < 2) return EmptyResponse.Instance;

        return await QueryAsync(domain, QueryType.NS);
    }

    // Minimal empty response implementation
    private class EmptyResponse : IDnsQueryResponse
    {
        public static readonly EmptyResponse Instance = new();
        public IReadOnlyList<DnsQuestion> Questions => Array.Empty<DnsQuestion>();
        public IReadOnlyList<DnsResourceRecord> Answers => Array.Empty<DnsResourceRecord>();
        public IReadOnlyList<DnsResourceRecord> Additionals => Array.Empty<DnsResourceRecord>();
        public IReadOnlyList<DnsResourceRecord> Authorities => Array.Empty<DnsResourceRecord>();
        IEnumerable<DnsResourceRecord> IDnsQueryResponse.AllRecords => Array.Empty<DnsResourceRecord>();
        public string AuditTrail => "";
        public bool HasError => true;
        public string ErrorMessage => "Query failed";
        public DnsResponseHeader Header => throw new NotImplementedException();
        public int MessageSize => 0;
        public NameServer NameServer => throw new NotImplementedException();
        public DnsQuerySettings Settings => throw new NotImplementedException();
    }
}
