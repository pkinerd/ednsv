using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// How long a failure to obtain an answer may be remembered, and how it is told apart
/// from an answer.
///
/// <para>The bug these pin reached users as fact. A reverse lookup that timed out
/// returned an empty list — indistinguishable from "this IP has no PTR record" — and
/// was held for the whole <c>CacheTtlHours</c>, so one unlucky query pinned "No PTR
/// record — many receivers reject mail from IPs without reverse DNS" against a
/// perfectly well-configured IP for hours. Record-TTL gating did not cause it but made
/// it far likelier to be hit: an answer bounded to sixty seconds refetches 120 times as
/// often, and every refetch is another chance to acquire a two-hour falsehood.</para>
/// </summary>
public sealed class TransientFailureCachingTests
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(2);   // CacheTtlHours=2
    private static readonly TimeSpan Brief = TimeSpan.FromMilliseconds(250);

    // ── What a rejected value's lifetime is ──────────────────────────────

    [Fact]
    public async Task ARejectedValueExpiresOnTheTransientWindowNotTheCacheTtl()
    {
        // The whole bug in one assertion: with a two-hour cache TTL, a failure must be
        // gone in the transient window. Before, it stayed for the two hours.
        var cache = new ProbeCache<List<string>>(CacheTtl, persist: false, transientLifetime: Brief);

        await cache.GetOrCreateAsync("ptr:1.2.3.4", () => Task.FromResult(new List<string>()),
            shouldPersist: _ => false);

        Assert.True(cache.TryGet("ptr:1.2.3.4", out _), "still needed for dedup within the validation");

        await Task.Delay(Brief + TimeSpan.FromMilliseconds(350));

        Assert.False(cache.TryGet("ptr:1.2.3.4", out _),
            "the failure was held for the cache-wide TTL — one timeout poisons the key for hours");
    }

    [Fact]
    public async Task AnAcceptedValueStillTakesTheCacheTtl()
    {
        // The other side of it: the short window applies to failures only. An answer
        // must not be shortened to the transient window.
        var cache = new ProbeCache<List<string>>(CacheTtl, persist: false, transientLifetime: Brief);

        await cache.GetOrCreateAsync("ptr:5.6.7.8",
            () => Task.FromResult(new List<string> { "mail.example" }),
            shouldPersist: _ => true);

        await Task.Delay(Brief + TimeSpan.FromMilliseconds(350));

        Assert.True(cache.TryGet("ptr:5.6.7.8", out var kept));
        Assert.Equal(new[] { "mail.example" }, kept);
    }

    [Fact]
    public async Task ACacheShorterThanTheWindowIsNotLengthenedByAFailure()
    {
        // The window is a ceiling on failures, never a floor.
        var cache = new ProbeCache<List<string>>(TimeSpan.FromMilliseconds(200), persist: false,
            transientLifetime: TimeSpan.FromMinutes(5));

        await cache.GetOrCreateAsync("k", () => Task.FromResult(new List<string>()),
            shouldPersist: _ => false);
        await Task.Delay(500);

        Assert.False(cache.TryGet("k", out _), "the failure outlived the cache's own TTL");
    }

    [Fact]
    public async Task TheValueTypeCacheFollowsTheSameRule()
    {
        // _portCache is a ProbeCacheValue, and a timed-out connect cached as "port shut"
        // for the cache TTL is the same falsehood in a different type.
        var cache = new ProbeCacheValue<bool>(CacheTtl, persist: false, transientLifetime: Brief);

        await cache.GetOrCreateAsync("port:host:25", () => Task.FromResult(false),
            shouldPersist: _ => false);
        Assert.True(cache.TryGet("port:host:25", out _));

        await Task.Delay(Brief + TimeSpan.FromMilliseconds(350));

        Assert.False(cache.TryGet("port:host:25", out _));
    }

    [Fact]
    public void TheShippedWindowIsShorterThanAValidation()
    {
        // It only has to span one validation — the in-flight map already collapses the
        // concurrent case. Anything longer starts surviving into the next run, which is
        // the failure mode this exists to end.
        Assert.InRange(ProbeCachePolicy.TransientLifetime,
            TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(2));
    }

    // ── A failure told apart from an absence ─────────────────────────────

    [Fact]
    public void AnOrdinaryEmptyResultIsNotAFailure()
    {
        // Both are empty lists; only one is a finding. Conflating them is how a timeout
        // reached users as a mail-delivery warning.
        Assert.False(DnsResolverService.PtrLookupDidFail(new List<string>()));
        Assert.False(DnsResolverService.PtrLookupDidFail(new List<string> { "mail.example." }));
    }

    [Fact]
    public async Task AFailedLookupIsReportedAsAFailureAndNotCached()
    {
        // No resolver on TEST-NET-1, so the query cannot succeed: a short timeout makes
        // this deterministic without depending on outbound DNS.
        var dns = new DnsResolverService(
            new[] { System.Net.IPAddress.Parse("192.0.2.1") }, cacheTtl: CacheTtl,
            tuning: new DnsTuning { QueryTimeoutSeconds = 1, QueryRetries = 0 });

        var ptrs = await dns.ResolvePtrAsync("198.51.100.7");

        Assert.True(DnsResolverService.PtrLookupDidFail(ptrs),
            "an unreachable resolver produced an ordinary empty result — indistinguishable from 'no PTR'");
        Assert.Empty(ptrs); // still an empty list to callers that do not ask

        // ...and a failure never reaches disk.
        foreach (var pending in dns.CollectPendingWrites())
            Assert.DoesNotContain(pending.Records, r => r.Type == CacheTypes.Ptr);
    }
}
