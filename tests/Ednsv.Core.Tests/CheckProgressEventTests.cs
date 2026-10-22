using System.Collections.Concurrent;
using System.Net;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// <c>OnCheckFinished</c> is what lets the web UI show a result while slower checks are
/// still running. Its predecessor for that job, <c>OnCheckCompleted</c>, holds every
/// concurrent result back until the whole phase is done, so a page fed from it sat empty
/// for as long as the slowest check took. The proof here is causal rather than timed:
/// the slow check is released only by the fast check's finish event, so the run cannot
/// complete unless that event fires while the slow check is still waiting.
/// </summary>
public sealed class CheckProgressEventTests
{
    private sealed class GatedCheck(string name, Func<Task> gate) : ICheck
    {
        public string Name => name;
        public CheckCategory Category => CheckCategory.MX;

        public async Task<List<CheckResult>> RunAsync(string domain, CheckContext context, CancellationToken cancellationToken = default)
        {
            await gate();
            return new List<CheckResult>
            {
                new() { CheckName = name, Category = Category, Severity = CheckSeverity.Info, Summary = "first" },
                new() { CheckName = name, Category = Category, Severity = CheckSeverity.Info, Summary = "second" },
            };
        }
    }

    private static DomainValidator Validator(params ICheck[] concurrent)
    {
        // Nothing listens on loopback:53 here or in CI, so the prefetch fails fast
        // rather than reaching a real resolver; RFC 6761 keeps .invalid off the internet.
        var dns = new DnsResolverService(new[] { IPAddress.Loopback },
            tuning: new DnsTuning { QueryTimeoutSeconds = 0.5, QueryRetries = 0 });
        return new DomainValidator(dns, new SmtpProbeService(), new HttpProbeService(),
            Array.Empty<ICheck>(), concurrent);
    }

    private static readonly ValidationOptions Offline = new()
    {
        EnableSmtpProbes = false, EnableHttpProbes = false, EnableDnsbl = false, EnableDirectDns = false,
        CrtShBaseUrl = "http://127.0.0.1:9/",
    };

    [Fact]
    public async Task FinishedChecksAreReportedWhileOthersAreStillRunning()
    {
        var fastFinished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releasedByEvent = false;
        var slow = new GatedCheck("slow", async () =>
        {
            releasedByEvent = await Task.WhenAny(fastFinished.Task, Task.Delay(TimeSpan.FromSeconds(20))) == fastFinished.Task;
        });
        var fast = new GatedCheck("fast", () => Task.CompletedTask);

        var validator = Validator(slow, fast);
        var finished = new ConcurrentQueue<string>();
        var completed = new ConcurrentQueue<string>();
        validator.OnCheckFinished += (name, results, _) =>
        {
            finished.Enqueue(name);
            if (name == "fast") fastFinished.TrySetResult();
        };
        validator.OnCheckCompleted += (name, _) => completed.Enqueue(name);

        var report = await validator.ValidateAsync("example.invalid", Offline);

        Assert.True(releasedByEvent, "fast's OnCheckFinished did not fire until the concurrent phase ended");
        Assert.Equal(new[] { "fast", "slow" }, finished);
        // The CLI's ordered, per-result stream is unchanged: check-list order.
        Assert.Equal(new[] { "slow", "slow", "fast", "fast" }, completed);

        var ours = report.Results.Where(r => r.CheckName is "slow" or "fast").ToList();
        Assert.Equal(4, ours.Count);
        Assert.All(ours, r => Assert.NotNull(r.DurationMs));
        // Every result of a check carries that check's one duration.
        Assert.Single(ours.Where(r => r.CheckName == "slow").Select(r => r.DurationMs).Distinct());
    }

    [Fact]
    public async Task AFailedCheckIsFinishedWithItsErrorAndDuration()
    {
        var boom = new GatedCheck("boom", () => throw new InvalidOperationException("kaput"));
        var validator = Validator(boom);
        IReadOnlyList<CheckResult>? got = null;
        validator.OnCheckFinished += (name, results, _) => { if (name == "boom") got = results; };

        await validator.ValidateAsync("example.invalid", Offline);

        var r = Assert.Single(got!);
        Assert.Equal(CheckSeverity.Error, r.Severity);
        Assert.NotNull(r.DurationMs);
    }

    [Fact]
    public void CheckCountCoversBothPhases()
    {
        Assert.Equal(88, new DomainValidator().CheckCount);
    }
}
