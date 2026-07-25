using System.Runtime.CompilerServices;

namespace Ednsv.Core.Services;

/// <summary>
/// A cache value waiting to be written to disk. Each <see cref="ProbeCache{T}"/>
/// holds a bag of these — only results this process fetched fresh from the network,
/// never values imported from disk or read out of the shared Redis L2, which are
/// already persisted elsewhere. A flush writes the bag out and removes exactly the
/// entries it wrote, leaving anything that arrived meanwhile for the next round.
///
/// <para><b>Equality is reference identity, and is stated explicitly rather than
/// left to the default on purpose.</b> The flush removes written entries with
/// <c>ConcurrentDictionary.TryRemove(KeyValuePair)</c>, which compares values using
/// <c>EqualityComparer&lt;T&gt;.Default</c> — so any value-based equality here would
/// let a flush delete a <i>newer</i> entry that replaced the one it persisted. A
/// record, or an added <c>Equals</c> override, would do exactly that and the loss
/// would be silent. Do not add one.</para>
/// </summary>
public sealed class BagEntry<TValue>
{
    /// <summary>The cached value itself.</summary>
    public TValue Value { get; }

    /// <summary>When this value was fetched. Orders entries across instances when
    /// their files are merged on load — a later fetch wins.</summary>
    public DateTime WrittenUtc { get; }

    /// <summary>When this value stops being usable. Held per entry rather than
    /// derived from a single global TTL, so DNS results can later be bounded by
    /// their own record TTLs without the rest of the cache changing.</summary>
    public DateTime ExpiresUtc { get; }

    public BagEntry(TValue value, DateTime writtenUtc, DateTime expiresUtc)
    {
        Value = value;
        WrittenUtc = writtenUtc;
        ExpiresUtc = expiresUtc;
    }

    public override bool Equals(object? obj) => ReferenceEquals(this, obj);

    public override int GetHashCode() => RuntimeHelpers.GetHashCode(this);
}
