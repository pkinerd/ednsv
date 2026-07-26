namespace Ednsv.Core.Services;

/// <summary>
/// Type tags used in cache files. One file holds every type, so each record says
/// which cache it belongs to. These strings are a persisted format — changing one
/// orphans the entries already written under the old tag until they expire.
/// </summary>
public static class CacheTypes
{
    public const string Dns = "dns";
    public const string DnsServer = "dns-srv";
    public const string Ptr = "ptr";
    public const string Smtp = "smtp";
    public const string Port = "port";
    public const string Rcpt = "rcpt";
    public const string Relay = "relay";
    public const string HttpGet = "http-get";
    public const string HttpGetHeaders = "http-get-headers";
    public const string Axfr = "axfr";
    public const string Unreachable = "unreachable";
    public const string DomainResults = "domain-results";
}
