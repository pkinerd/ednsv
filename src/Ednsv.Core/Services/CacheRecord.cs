using System.Text.Json.Serialization;

namespace Ednsv.Core.Services;

/// <summary>
/// One line of a cache file. Self-describing so every cache type shares a single
/// file rather than one file each: the type tag says which cache it belongs to,
/// and the value stays as raw JSON until a reader decides it needs it.
///
/// Both timestamps are needed. <see cref="WrittenUtc"/> orders entries when files
/// from several instances are merged — the later fetch wins. <see cref="ExpiresUtc"/>
/// decides whether an entry is still usable. They cannot be collapsed into one:
/// once DNS entries are bounded by their own record TTLs, an entry fetched later
/// can expire sooner than one fetched earlier.
/// </summary>
public sealed class CacheRecord
{
    [JsonPropertyName("t")] public string Type { get; set; } = "";
    [JsonPropertyName("k")] public string Key { get; set; } = "";
    [JsonPropertyName("w")] public DateTime WrittenUtc { get; set; }
    [JsonPropertyName("e")] public DateTime ExpiresUtc { get; set; }

    /// <summary>The cached value, already serialised. Kept as raw JSON so the load
    /// path can read the envelope and skip the payload entirely for entries that
    /// are expired or beaten by a newer copy.</summary>
    [JsonPropertyName("v")] public System.Text.Json.Nodes.JsonNode? Value { get; set; }
}

/// <summary>
/// Records a cache is ready to hand to a flush, together with how to mark them
/// written once they are safely on disk.
///
/// The two halves are separate on purpose: nothing is removed from a bag until the
/// file it went into has landed, so a failed write simply leaves everything queued
/// for the next attempt. <see cref="Commit"/> removes exactly the entries that were
/// snapshotted — matched by reference — so a fresher value that arrived for the same
/// key while the write was in flight survives.
/// </summary>
public sealed class PendingWrites
{
    private readonly Action _commit;

    public IReadOnlyList<CacheRecord> Records { get; }

    public PendingWrites(IReadOnlyList<CacheRecord> records, Action commit)
    {
        Records = records;
        _commit = commit;
    }

    public void Commit() => _commit();

    public static PendingWrites None { get; } = new(Array.Empty<CacheRecord>(), () => { });
}
