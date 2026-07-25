namespace Ednsv.Core.Services;

/// <summary>
/// Write-to-temp-then-rename helpers for the JSON files EDNSV persists
/// (config, users, revision bodies, disk cache).
///
/// The rename itself is atomic — <see cref="File.Move(string, string, bool)"/>
/// maps to <c>rename(2)</c> on Unix and <c>MoveFileEx(MOVEFILE_REPLACE_EXISTING)</c>
/// on Windows — so a reader never observes a half-written file. The scratch path,
/// however, must be unique per write: a fixed <c>"&lt;target&gt;.tmp"</c> is shared
/// state, and two writers (two replicas on one mount, or a CLI run alongside the
/// web service) truncate and interleave into it, after which one rename publishes
/// the resulting garbage and the other throws because the temp file has already
/// been moved away.
///
/// Concurrent writers still race to publish, and the last rename wins — that is
/// the intended semantic for these files and is what the callers already assume.
/// What is guaranteed here is that whatever ends up at the target path is exactly
/// one writer's complete payload.
/// </summary>
public static class AtomicFile
{
    private const string TempExtension = ".tmp";

    /// <summary>Files left behind by a crashed or killed writer are only swept
    /// once they are older than this, so a temp file belonging to a live
    /// concurrent write is never deleted out from under it.</summary>
    public static readonly TimeSpan DefaultStaleTempAge = TimeSpan.FromHours(1);

    // Kept in the target's own directory so the rename stays within one
    // filesystem; a temp in a different directory could cross a mount boundary,
    // where File.Move silently degrades to a non-atomic copy-then-delete.
    private static string NewTempPath(string path)
        => path + "." + Guid.NewGuid().ToString("N")[..8] + TempExtension;

    /// <summary>Serialises <paramref name="contents"/> to a unique temp file and
    /// renames it over <paramref name="path"/>.</summary>
    public static void WriteAllText(string path, string contents)
    {
        var tmp = NewTempPath(path);
        try
        {
            File.WriteAllText(tmp, contents);
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            TryDelete(tmp); // don't leak the scratch file when the write fails
            throw;
        }
    }

    /// <inheritdoc cref="WriteAllText"/>
    public static async Task WriteAllTextAsync(string path, string contents)
    {
        var tmp = NewTempPath(path);
        try
        {
            await File.WriteAllTextAsync(tmp, contents);
            File.Move(tmp, path, overwrite: true);
        }
        catch
        {
            TryDelete(tmp);
            throw;
        }
    }

    /// <summary>Removes temp files for <paramref name="path"/> that are older than
    /// <paramref name="maxAge"/>, plus the legacy fixed-name temp written by
    /// earlier versions. Best-effort; never throws.</summary>
    public static void SweepStaleTemps(string path, TimeSpan? maxAge = null)
    {
        var cutoff = DateTime.UtcNow - (maxAge ?? DefaultStaleTempAge);
        foreach (var tmp in EnumerateTemps(path))
        {
            try
            {
                if (File.GetLastWriteTimeUtc(tmp) < cutoff) File.Delete(tmp);
            }
            catch { /* best effort */ }
        }
    }

    /// <summary>Removes every temp file for <paramref name="path"/> regardless of
    /// age. Only safe where the caller holds the lock that excludes writers —
    /// otherwise use <see cref="SweepStaleTemps"/>. Best-effort; never throws.</summary>
    public static void DeleteAllTemps(string path)
    {
        foreach (var tmp in EnumerateTemps(path))
            TryDelete(tmp);
    }

    private static IEnumerable<string> EnumerateTemps(string path)
    {
        // The legacy fixed name, written before temp paths were made unique.
        var legacy = path + TempExtension;
        if (File.Exists(legacy)) yield return legacy;

        var dir = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) yield break;

        string[] matches;
        try
        {
            matches = Directory.GetFiles(dir, Path.GetFileName(path) + ".*" + TempExtension);
        }
        catch
        {
            yield break;
        }
        foreach (var m in matches) yield return m;
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* best effort */ }
    }
}
