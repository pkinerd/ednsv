using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

public sealed class DiskCacheClearTests
{
    [Fact]
    public void Clear_DeletesKnownCacheFilesButLeavesOthers()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"ednsv-cacheclear-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "dns-queries.json"), "{}");
            File.WriteAllText(Path.Combine(dir, "domain-results.json"), "{}");
            File.WriteAllText(Path.Combine(dir, "http-get.json.tmp"), "{}"); // legacy fixed-name temp
            File.WriteAllText(Path.Combine(dir, "http-get.json.a1b2c3d4.tmp"), "{}"); // unique-name temp
            File.WriteAllText(Path.Combine(dir, "unrelated.txt"), "keep me");
            File.WriteAllText(Path.Combine(dir, "unrelated.json.deadbeef.tmp"), "keep me too");

            DiskCacheService.Clear(dir);

            Assert.False(File.Exists(Path.Combine(dir, "dns-queries.json")));
            Assert.False(File.Exists(Path.Combine(dir, "domain-results.json")));
            Assert.False(File.Exists(Path.Combine(dir, "http-get.json.tmp")));
            Assert.False(File.Exists(Path.Combine(dir, "http-get.json.a1b2c3d4.tmp")));
            Assert.True(File.Exists(Path.Combine(dir, "unrelated.txt"))); // only cache files removed
            Assert.True(File.Exists(Path.Combine(dir, "unrelated.json.deadbeef.tmp")));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Clear_MissingDirectoryIsNoOp()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"ednsv-cacheclear-missing-{Guid.NewGuid():N}");
        DiskCacheService.Clear(dir); // must not throw
        Assert.False(Directory.Exists(dir));
    }
}
