using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// A guard, not a behaviour test: it asserts that the environment the Redis-backed
/// tests need is actually present when it is supposed to be.
///
/// <para>Six test classes reach a real Redis — the shared L2, the emptied-cache
/// re-warm, L2 lifetimes, the config and auth beacons, and write leases — and every
/// one of them self-skips when nothing is listening. That is right for a dev box: a
/// contributor without a Redis should still get a green run. It is wrong for CI, and
/// it failed silently there for exactly as long as nobody looked. A run on <c>main</c>
/// reported 315 of 315 passed while logging <c>SKIPPED: no Redis</c> 43 times, which
/// meant no shared-cache behaviour was verified by the thing that gates merges.</para>
///
/// <para>Adding a service container to the workflow fixes it once. This makes it stay
/// fixed: with <c>EDNSV_REQUIRE_REDIS=1</c> set, a missing Redis is a failure that
/// names the consequence, so removing or breaking the container cannot quietly return
/// dozens of tests to skipping. Everywhere else the variable is unset and this test
/// does nothing.</para>
/// </summary>
public sealed class RedisTestPrerequisiteTests
{
    private const string ConnString =
        "127.0.0.1:6380,abortConnect=false,connectTimeout=2000,syncTimeout=2000";

    [Fact]
    public async Task RedisIsReachableWhereTheEnvironmentSaysItMustBe()
    {
        if (Environment.GetEnvironmentVariable("EDNSV_REQUIRE_REDIS") != "1")
        {
            Console.WriteLine("SKIPPED: EDNSV_REQUIRE_REDIS not set — Redis is optional here");
            return;
        }

        using var redis = new RedisConnection(ConnString);
        Assert.True(redis.Enabled, "the connection string did not configure a Redis at all");

        // A few attempts: a service container can pass its health check a moment
        // before it is accepting our connections.
        var healthy = false;
        for (var i = 0; i < 10 && !healthy; i++)
        {
            healthy = await redis.IsHealthyAsync();
            if (!healthy) await Task.Delay(500);
        }

        Assert.True(healthy,
            "EDNSV_REQUIRE_REDIS=1 but nothing answered on 127.0.0.1:6380. Every Redis-backed "
            + "test self-skips in this state, so the run would report green while verifying "
            + "none of the shared-cache behaviour. Check the redis service container in "
            + ".github/workflows/ci.yml.");
    }
}
