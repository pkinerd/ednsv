namespace Ednsv.Core.Services;

/// <summary>
/// Per-request trace plumbing that flows through async calls via AsyncLocal.
/// Replaces the previous pattern of setting Action&lt;string&gt; on singleton
/// services, which leaked traces between concurrent validations because the
/// callback slot was a single shared field.
///
/// The AsyncLocal contract: setting Sink/Phase/Check inside a request's task
/// chain is visible only to tasks descended from that chain. Two concurrent
/// validations in the same process see independent values.
/// </summary>
public static class TraceContext
{
    private static readonly AsyncLocal<Action<string>?> _sink = new();
    private static readonly AsyncLocal<string?> _phase = new();
    private static readonly AsyncLocal<string?> _check = new();

    /// <summary>The trace sink for the current async-flow context, or null when tracing is off.</summary>
    public static Action<string>? Sink
    {
        get => _sink.Value;
        set => _sink.Value = value;
    }

    /// <summary>Current validation phase label (e.g. PREFETCH / FOUNDATION / CONCURRENT).</summary>
    public static string? Phase
    {
        get => _phase.Value;
        set => _phase.Value = value;
    }

    /// <summary>Current check name when inside a check's RunAsync, or null otherwise.</summary>
    public static string? Check
    {
        get => _check.Value;
        set => _check.Value = value;
    }
}
