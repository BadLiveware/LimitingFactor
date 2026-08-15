namespace LimitingFactor.LowLevel;

/// <summary>Explicit low-level process and mount configuration for a sandbox launch.</summary>
public sealed record SandboxLaunchOptions
{
    public required string FileName { get; init; }
    public required string WorkingDirectory { get; init; }
    public IReadOnlyList<string> Arguments { get; init; } = [];
    public IReadOnlyDictionary<string, string?> Environment { get; init; } =
        new Dictionary<string, string?>();
    public IReadOnlyList<SandboxMount> Mounts { get; init; } = [];
    public bool RedirectStandardInput { get; init; }
    public bool RedirectStandardOutput { get; init; }
    public bool RedirectStandardError { get; init; }
}
