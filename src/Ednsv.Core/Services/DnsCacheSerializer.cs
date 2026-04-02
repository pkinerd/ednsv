using System.Net;
using DnsClient;
using DnsClient.Protocol;

namespace Ednsv.Core.Services;

/// <summary>
/// Serializable DTO for a cached DNS query response.
/// </summary>
public class DnsCacheEntry
{
    public bool HasError { get; set; }
    public string? ErrorMessage { get; set; }
    public List<DnsCacheRecord> Answers { get; set; } = new();
    public List<DnsCacheRecord> Authorities { get; set; } = new();
    public List<DnsCacheRecord> Additionals { get; set; } = new();
}

/// <summary>
/// Serializable DTO for a single DNS resource record.
/// Type-specific data stored in a flat dictionary for simplicity.
/// </summary>
public class DnsCacheRecord
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public int Ttl { get; set; }
    public Dictionary<string, string> Data { get; set; } = new();
}

/// <summary>
/// Converts between DnsClient record objects and serializable DTOs.
/// </summary>
public static class DnsCacheSerializer
{
    public static DnsCacheEntry? SerializeResponse(IDnsQueryResponse response)
    {
        var entry = new DnsCacheEntry
        {
            HasError = response.HasError,
            ErrorMessage = response.HasError ? response.ErrorMessage : null
        };

        foreach (var record in response.Answers)
        {
            var dto = SerializeRecord(record);
            if (dto != null) entry.Answers.Add(dto);
            else return null; // can't fully serialize — skip this response
        }
        foreach (var record in response.Authorities)
        {
            var dto = SerializeRecord(record);
            if (dto != null) entry.Authorities.Add(dto);
            else return null;
        }
        foreach (var record in response.Additionals)
        {
            var dto = SerializeRecord(record);
            if (dto != null) entry.Additionals.Add(dto);
            else return null;
        }

        return entry;
    }

    public static CachedDnsResponse DeserializeResponse(DnsCacheEntry entry)
    {
        var answers = new List<DnsResourceRecord>();
        var authorities = new List<DnsResourceRecord>();
        var additionals = new List<DnsResourceRecord>();

        foreach (var dto in entry.Answers)
        {
            var record = DeserializeRecord(dto);
            if (record != null) answers.Add(record);
        }
        foreach (var dto in entry.Authorities)
        {
            var record = DeserializeRecord(dto);
            if (record != null) authorities.Add(record);
        }
        foreach (var dto in entry.Additionals)
        {
            var record = DeserializeRecord(dto);
            if (record != null) additionals.Add(record);
        }

        return new CachedDnsResponse(answers, authorities, additionals, entry.HasError, entry.ErrorMessage);
    }

    private static DnsCacheRecord? SerializeRecord(DnsResourceRecord record)
    {
        var dto = new DnsCacheRecord
        {
            Name = record.DomainName.Value.TrimEnd('.'),
            Ttl = record.InitialTimeToLive
        };

        switch (record)
        {
            case ARecord a:
                dto.Type = "A";
                dto.Data["Address"] = a.Address.ToString();
                break;
            case AaaaRecord aaaa:
                dto.Type = "AAAA";
                dto.Data["Address"] = aaaa.Address.ToString();
                break;
            case MxRecord mx:
                dto.Type = "MX";
                dto.Data["Preference"] = mx.Preference.ToString();
                dto.Data["Exchange"] = mx.Exchange.Value.TrimEnd('.');
                break;
            case NsRecord ns:
                dto.Type = "NS";
                dto.Data["NsDName"] = ns.NSDName.Value.TrimEnd('.');
                break;
            case CNameRecord cname:
                dto.Type = "CNAME";
                dto.Data["CanonicalName"] = cname.CanonicalName.Value.TrimEnd('.');
                break;
            case PtrRecord ptr:
                dto.Type = "PTR";
                dto.Data["PtrDomainName"] = ptr.PtrDomainName.Value.TrimEnd('.');
                break;
            case TxtRecord txt:
                dto.Type = "TXT";
                // Join with record separator — TXT records can have multiple strings
                dto.Data["Values"] = string.Join("\x1E", txt.Text);
                break;
            case SoaRecord soa:
                dto.Type = "SOA";
                dto.Data["MName"] = soa.MName.Value.TrimEnd('.');
                dto.Data["RName"] = soa.RName.Value.TrimEnd('.');
                dto.Data["Serial"] = soa.Serial.ToString();
                dto.Data["Refresh"] = soa.Refresh.ToString();
                dto.Data["Retry"] = soa.Retry.ToString();
                dto.Data["Expire"] = soa.Expire.ToString();
                dto.Data["Minimum"] = soa.Minimum.ToString();
                break;
            case CaaRecord caa:
                dto.Type = "CAA";
                dto.Data["Flags"] = caa.Flags.ToString();
                dto.Data["Tag"] = caa.Tag;
                dto.Data["Value"] = caa.Value;
                break;
            case SrvRecord srv:
                dto.Type = "SRV";
                dto.Data["Priority"] = srv.Priority.ToString();
                dto.Data["Weight"] = srv.Weight.ToString();
                dto.Data["Port"] = srv.Port.ToString();
                dto.Data["Target"] = srv.Target.Value.TrimEnd('.');
                break;
            default:
                // Unsupported record type — can't serialize
                return null;
        }

        return dto;
    }

    private static DnsResourceRecord? DeserializeRecord(DnsCacheRecord dto)
    {
        var info = new ResourceRecordInfo(dto.Name, ParseRecordType(dto.Type), QueryClass.IN, dto.Ttl, 0);

        try
        {
            return dto.Type switch
            {
                "A" => new ARecord(info, IPAddress.Parse(dto.Data["Address"])),
                "AAAA" => new AaaaRecord(info, IPAddress.Parse(dto.Data["Address"])),
                "MX" => new MxRecord(info, ushort.Parse(dto.Data["Preference"]),
                    DnsString.Parse(dto.Data["Exchange"])),
                "NS" => new NsRecord(info, DnsString.Parse(dto.Data["NsDName"])),
                "CNAME" => new CNameRecord(info, DnsString.Parse(dto.Data["CanonicalName"])),
                "PTR" => new PtrRecord(info, DnsString.Parse(dto.Data["PtrDomainName"])),
                "TXT" => new TxtRecord(info,
                    dto.Data["Values"].Split('\x1E'),
                    dto.Data["Values"].Split('\x1E')),
                "SOA" => new SoaRecord(info,
                    DnsString.Parse(dto.Data["MName"]),
                    DnsString.Parse(dto.Data["RName"]),
                    uint.Parse(dto.Data["Serial"]),
                    uint.Parse(dto.Data["Refresh"]),
                    uint.Parse(dto.Data["Retry"]),
                    uint.Parse(dto.Data["Expire"]),
                    uint.Parse(dto.Data["Minimum"])),
                "CAA" => new CaaRecord(info,
                    byte.Parse(dto.Data["Flags"]),
                    dto.Data["Tag"],
                    dto.Data["Value"]),
                "SRV" => new SrvRecord(info,
                    ushort.Parse(dto.Data["Priority"]),
                    ushort.Parse(dto.Data["Weight"]),
                    ushort.Parse(dto.Data["Port"]),
                    DnsString.Parse(dto.Data["Target"])),
                _ => null
            };
        }
        catch
        {
            return null;
        }
    }

    private static ResourceRecordType ParseRecordType(string type) => type switch
    {
        "A" => ResourceRecordType.A,
        "AAAA" => ResourceRecordType.AAAA,
        "MX" => ResourceRecordType.MX,
        "NS" => ResourceRecordType.NS,
        "CNAME" => ResourceRecordType.CNAME,
        "PTR" => ResourceRecordType.PTR,
        "TXT" => ResourceRecordType.TXT,
        "SOA" => ResourceRecordType.SOA,
        "CAA" => ResourceRecordType.CAA,
        "SRV" => ResourceRecordType.SRV,
        _ => ResourceRecordType.A // fallback, shouldn't happen
    };
}

/// <summary>
/// A cached DNS response reconstructed from serialized data.
/// Implements IDnsQueryResponse so it can be used in place of live responses.
/// </summary>
public class CachedDnsResponse : IDnsQueryResponse
{
    private readonly IReadOnlyList<DnsResourceRecord> _answers;
    private readonly IReadOnlyList<DnsResourceRecord> _authorities;
    private readonly IReadOnlyList<DnsResourceRecord> _additionals;

    public CachedDnsResponse(
        List<DnsResourceRecord> answers,
        List<DnsResourceRecord> authorities,
        List<DnsResourceRecord> additionals,
        bool hasError,
        string? errorMessage)
    {
        _answers = answers;
        _authorities = authorities;
        _additionals = additionals;
        HasError = hasError;
        ErrorMessage = errorMessage ?? "";
    }

    public IReadOnlyList<DnsQuestion> Questions => Array.Empty<DnsQuestion>();
    public IReadOnlyList<DnsResourceRecord> Answers => _answers;
    public IReadOnlyList<DnsResourceRecord> Authorities => _authorities;
    public IReadOnlyList<DnsResourceRecord> Additionals => _additionals;
    IEnumerable<DnsResourceRecord> IDnsQueryResponse.AllRecords =>
        _answers.Concat(_authorities).Concat(_additionals);
    public string AuditTrail => "";
    public bool HasError { get; }
    public string ErrorMessage { get; }
    public DnsResponseHeader Header => throw new NotImplementedException();
    public int MessageSize => 0;
    public NameServer NameServer => throw new NotImplementedException();
    public DnsQuerySettings Settings => throw new NotImplementedException();
}
