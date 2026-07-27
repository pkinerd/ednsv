using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

public sealed class AtomicFileTests : IDisposable
{
    private readonly string _dir;

    public AtomicFileTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"ednsv-atomicfile-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private string Path_(string name) => Path.Combine(_dir, name);

    [Fact]
    public void WriteAllText_WritesContentAndLeavesNoTemp()
    {
        var path = Path_("f.json");
        AtomicFile.WriteAllText(path, "hello");

        Assert.Equal("hello", File.ReadAllText(path));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    [Fact]
    public async Task WriteAllTextAsync_OverwritesExisting()
    {
        var path = Path_("f.json");
        await AtomicFile.WriteAllTextAsync(path, "first");
        await AtomicFile.WriteAllTextAsync(path, "second");

        Assert.Equal("second", File.ReadAllText(path));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    /// <summary>
    /// The regression this whole change exists for: with a shared "&lt;target&gt;.tmp"
    /// scratch path, concurrent writers interleave into the same file and one of
    /// them publishes the resulting mixture. Payloads are large and single-character
    /// so any interleaving is unmistakable.
    /// </summary>
    [Fact]
    public async Task ConcurrentWriters_TargetIsAlwaysOneCompletePayload()
    {
        var path = Path_("contended.json");
        const int writers = 8;
        var payloads = Enumerable.Range(0, writers)
            .Select(i => new string((char)('a' + i), 400_000))
            .ToArray();

        for (var round = 0; round < 5; round++)
        {
            await Task.WhenAll(payloads.Select(p => Task.Run(() => AtomicFile.WriteAllText(path, p))));

            var actual = File.ReadAllText(path);
            Assert.Contains(actual, payloads);
        }
    }

    [Fact]
    public async Task ConcurrentAsyncWriters_TargetIsAlwaysOneCompletePayload()
    {
        var path = Path_("contended-async.json");
        var payloads = Enumerable.Range(0, 8)
            .Select(i => new string((char)('a' + i), 400_000))
            .ToArray();

        await Task.WhenAll(payloads.Select(p => AtomicFile.WriteAllTextAsync(path, p)));

        Assert.Contains(File.ReadAllText(path), payloads);
    }

    [Fact]
    public void WriteAllText_FailureDoesNotLeakTempFile()
    {
        // A directory where the target should be makes File.Move fail after the
        // temp has been written — the path that would otherwise strand scratch files.
        var path = Path_("blocked");
        Directory.CreateDirectory(path);

        Assert.ThrowsAny<Exception>(() => AtomicFile.WriteAllText(path, "payload"));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    [Fact]
    public void SweepStaleTemps_RemovesOldTempsAndLegacyName()
    {
        var path = Path_("f.json");
        File.WriteAllText(path, "{}");

        var legacy = path + ".tmp";
        var stale = path + ".deadbeef.tmp";
        File.WriteAllText(legacy, "x");
        File.WriteAllText(stale, "x");
        var old = DateTime.UtcNow.AddHours(-2);
        File.SetLastWriteTimeUtc(legacy, old);
        File.SetLastWriteTimeUtc(stale, old);

        AtomicFile.SweepStaleTemps(path);

        Assert.False(File.Exists(legacy));
        Assert.False(File.Exists(stale));
        Assert.True(File.Exists(path)); // the real file is untouched
    }

    [Fact]
    public void SweepStaleTemps_LeavesTempsFromAnInFlightWrite()
    {
        var path = Path_("f.json");
        var fresh = path + ".cafebabe.tmp";
        File.WriteAllText(fresh, "in flight");

        AtomicFile.SweepStaleTemps(path);

        Assert.True(File.Exists(fresh));
    }

    [Fact]
    public void SweepStaleTemps_IgnoresTempsBelongingToOtherFiles()
    {
        var path = Path_("f.json");
        var other = Path_("g.json.deadbeef.tmp");
        File.WriteAllText(other, "x");
        File.SetLastWriteTimeUtc(other, DateTime.UtcNow.AddHours(-2));

        AtomicFile.SweepStaleTemps(path);

        Assert.True(File.Exists(other));
    }

    [Fact]
    public void DeleteAllTemps_RemovesRegardlessOfAge()
    {
        var path = Path_("f.json");
        File.WriteAllText(path + ".tmp", "x");
        File.WriteAllText(path + ".0badf00d.tmp", "x");

        AtomicFile.DeleteAllTemps(path);

        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    [Fact]
    public void SweepStaleTemps_MissingDirectoryIsNoOp()
        => AtomicFile.SweepStaleTemps(Path.Combine(_dir, "nope", "f.json")); // must not throw
}
