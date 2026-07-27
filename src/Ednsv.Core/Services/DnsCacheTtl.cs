using DnsClient.Protocol;

namespace Ednsv.Core.Services;

/// <summary>
/// How long a DNS answer may be cached, given what the zone published.
///
/// <para>Separate from <see cref="DnsResolverService"/> because it is policy rather
/// than resolution: a pure clamp over three numbers, with one genuinely awkward case
/// (an empty answer section) and one invariant that is easy to break by accident (the
/// cache TTL must remain the ceiling).</para>
/// </summary>
public static class DnsCacheTtl
{
    /// <summary>
    /// <c>clamp(minRecordTtl, floor, cap)</c>, or null when the gating is off.
    ///
    /// <para>A null <paramref name="minRecordTtl"/> means the answer section was empty
    /// and there is no published TTL to read. That is not an edge case to shrug at:
    /// NXDOMAIN and NODATA are real responses, they are cached, and their answer
    /// sections are always empty, so this branch is taken routinely. It resolves to
    /// the floor — treating it as "no TTL, cache forever" or "zero, never cache"
    /// would both be wrong.</para>
    ///
    /// <para><paramref name="cap"/> is the ceiling and must stay so. The sweep deletes
    /// a record file at <c>fileTime + CacheTtlHours</c>, so an entry allowed to live
    /// longer than the cap could be swept while still considered live.</para>
    /// </summary>
    public static TimeSpan? For(TimeSpan? minRecordTtl, TimeSpan floor, TimeSpan? cap)
    {
        // Off by default: every entry gets the cache-wide TTL, as before this existed.
        if (floor <= TimeSpan.Zero) return null;

        var ttl = minRecordTtl ?? floor;
        if (ttl < floor) ttl = floor;
        if (cap.HasValue && ttl > cap.Value) ttl = cap.Value;
        return ttl;
    }

    /// <summary>
    /// The shortest TTL published across an answer section, or null when it is empty.
    ///
    /// <para><c>InitialTimeToLive</c> rather than <c>TimeToLive</c>: the latter counts
    /// down while DnsClient holds the record, so using it would shorten every entry by
    /// however long the response happened to sit around before being cached.</para>
    /// </summary>
    public static TimeSpan? MinRecordTtl(IEnumerable<DnsResourceRecord> answers)
    {
        var min = int.MaxValue;
        foreach (var record in answers)
            if (record.InitialTimeToLive < min) min = record.InitialTimeToLive;

        return min == int.MaxValue ? null : TimeSpan.FromSeconds(Math.Max(0, min));
    }
}
