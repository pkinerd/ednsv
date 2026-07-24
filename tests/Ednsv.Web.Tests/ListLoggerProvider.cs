using Microsoft.Extensions.Logging;

namespace Ednsv.Web.Tests;

public sealed record CapturedLog(string Category, LogLevel Level, string Message);

/// <summary>Thread-safe in-memory logger provider that captures formatted messages for assertions.</summary>
public sealed class ListLoggerProvider : ILoggerProvider
{
    private readonly List<CapturedLog> _sink;
    public ListLoggerProvider(List<CapturedLog> sink) => _sink = sink;

    public ILogger CreateLogger(string categoryName) => new ListLogger(categoryName, _sink);
    public void Dispose() { }

    private sealed class ListLogger : ILogger
    {
        private readonly string _category;
        private readonly List<CapturedLog> _sink;
        public ListLogger(string category, List<CapturedLog> sink) { _category = category; _sink = sink; }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            var msg = formatter(state, exception);
            lock (_sink) _sink.Add(new CapturedLog(_category, logLevel, msg));
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }
}
