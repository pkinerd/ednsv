using Ednsv.Core.Models;

namespace Ednsv.Core.Checks;

public interface ICheck
{
    string Name { get; }
    CheckCategory Category { get; }
    Task<List<CheckResult>> RunAsync(string domain, CheckContext context);
}

public class CheckContext
{
    public Services.DnsResolverService Dns { get; set; } = null!;
    public Services.SmtpProbeService Smtp { get; set; } = null!;
    public Services.HttpProbeService Http { get; set; } = null!;

    // Shared state between checks
    public List<string> MxHosts { get; set; } = new();
    public Dictionary<string, List<string>> MxHostIps { get; set; } = new();
    public List<string> NsHosts { get; set; } = new();
    public Dictionary<string, List<string>> NsHostIps { get; set; } = new();
    public string? SpfRecord { get; set; }
    public string? DmarcRecord { get; set; }
    public List<string> DomainARecords { get; set; } = new();
    public List<string> DomainAAAARecords { get; set; } = new();
}
