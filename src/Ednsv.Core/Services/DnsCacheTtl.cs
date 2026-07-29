using DnsClient.Protocol;

namespace Ednsv.Core.Services;

/// <summary>
/// How long a DNS answer may be cached, given what the zone published.
///
/// <para>Separate from <see cref="DnsResolverService"/> because it is policy rather
/// than resolution: a clamp over three numbers, plus the question of which number the
/// response actually published, and one invariant that is easy to break by accident
/// (the cache TTL must remain the ceiling).</para>
/// </summary>
public static class DnsCacheTtl
{
    /// <summary>
    /// <c>clamp(receivedTtl, floor, cap)</c>, or null when there is no per-entry TTL
    /// to apply and the cache-wide one should govern.
    ///
    /// <para><b>The floor bounds TTLs we received; it is not a default for responses
    /// that carried none.</b> A null <paramref name="receivedTtl"/> means the response
    /// published nothing to read — no answer records and no SOA to derive a negative
    /// TTL from — so there is nothing for the floor to raise. Returning null hands the
    /// entry to <c>CacheTtlHours</c>, exactly as if gating were off.</para>
    ///
    /// <para>It used to resolve to the floor instead, and that was the dominant path
    /// rather than a corner: every "not listed" blocklist answer, every absent DKIM
    /// selector and every probed subdomain that does not exist arrives with an empty
    /// answer section. A validation of a clean domain issues hundreds of them, so a
    /// 60-second floor became a 60-second lifetime for most of the cache — the floor
    /// setting silently deciding the TTL for entries no zone had spoken about.</para>
    ///
    /// <para><paramref name="cap"/> is the ceiling and must stay so. The sweep deletes
    /// a record file at <c>fileTime + CacheTtlHours</c>, so an entry allowed to live
    /// longer than the cap could be swept while still considered live.</para>
    /// </summary>
    public static TimeSpan? For(TimeSpan? receivedTtl, TimeSpan floor, TimeSpan? cap)
    {
        // Off by default: every entry gets the cache-wide TTL, as before this existed.
        if (floor <= TimeSpan.Zero) return null;

        // Nothing came back from the wire — the cache-wide TTL governs, not the floor.
        if (receivedTtl is not { } ttl) return null;

        if (ttl < floor) ttl = floor;
        if (cap.HasValue && ttl > cap.Value) ttl = cap.Value;
        return ttl;
    }

    /// <summary>
    /// <c>clamp(negativeTtl, floor, min(cap, negativeCap))</c> — the same clamp as
    /// <see cref="For"/> under a second, tighter ceiling that applies to negative
    /// answers alone.
    ///
    /// <para><b>The asymmetry is the point.</b> A stale "this exists" goes out of date;
    /// a stale "this does not exist" produces a false finding — "No PTR record, Gmail
    /// will reject mail" against an IP that has perfectly good reverse DNS. Resolvers
    /// routinely cap negative caching well below positive for exactly this reason, and
    /// RFC 2308 §5 recommends the same. Honouring an SOA MINIMUM of a day for an answer
    /// a stressed resolver may simply have got wrong means one bad reply becomes a
    /// long-lived, disk-persisted, fleet-shared error.</para>
    ///
    /// <para><b>Independent of the floor.</b> Unlike <see cref="For"/>, this applies
    /// even with record-TTL gating switched off: it is a ceiling, and the damage it
    /// bounds does not depend on whether the gating is on. With gating off nothing reads
    /// a published TTL at all, so the ceiling alone governs.</para>
    ///
    /// <para>A negative answer that published no SOA takes the ceiling rather than
    /// inheriting the cache-wide TTL. It is still a negative answer — the caller only
    /// reaches here once the response has been confirmed an answer with an empty
    /// answer section — so the cap is the safer of the two readings.</para>
    /// </summary>
    public static TimeSpan? ForNegative(TimeSpan? negativeTtl, TimeSpan floor, TimeSpan? cap,
        TimeSpan? negativeCap)
    {
        // The tighter of the two ceilings.
        var ceiling = cap;
        if (negativeCap is { } n && n > TimeSpan.Zero && (ceiling is not { } c || n < c))
            ceiling = n;

        // Gating off: no published TTL is consulted, so the ceiling is the whole policy.
        // Null when there is no negative cap either, which leaves the cache-wide TTL
        // governing exactly as before this existed.
        if (floor <= TimeSpan.Zero)
            return negativeCap is { } set && set > TimeSpan.Zero ? ceiling : null;

        if (negativeTtl is not { } ttl) return ceiling;

        if (ttl < floor) ttl = floor;
        if (ceiling is { } max && ttl > max) ttl = max;
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

    /// <summary>
    /// How long a negative answer may be cached, read from the SOA the zone returns in
    /// the authority section, or null when there is no SOA to read.
    ///
    /// <para>RFC 2308 §5: the lifetime of a negative answer is
    /// <c>min(SOA.MINIMUM, TTL of the SOA record)</c>. This is the number the zone
    /// publishes precisely so resolvers know how long "it does not exist" holds, and
    /// without reading it every NXDOMAIN and NODATA looks TTL-less — which is most of
    /// what a validation asks for. The data was already being captured and persisted by
    /// <see cref="DnsCacheSerializer"/>; only the TTL policy ignored it.</para>
    ///
    /// <para>The minimum across SOAs, on the same reasoning as
    /// <see cref="MinRecordTtl"/>: more than one is irregular, and the shortest is the
    /// safe reading. <c>InitialTimeToLive</c> for the same reason too — the countdown
    /// copy would shorten the entry by however long the response sat around.</para>
    /// </summary>
    public static TimeSpan? NegativeTtl(IEnumerable<DnsResourceRecord> authorities)
    {
        long? min = null;
        foreach (var record in authorities)
        {
            if (record is not SoaRecord soa) continue;

            var ttl = Math.Min(Math.Max(0L, soa.InitialTimeToLive), soa.Minimum);
            if (min is null || ttl < min) min = ttl;
        }

        return min is { } seconds ? TimeSpan.FromSeconds(seconds) : null;
    }
}
