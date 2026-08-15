namespace LimitingFactor.LowLevel;

/// <summary>One mount operation applied by the native sandbox helper.</summary>
public abstract record SandboxMount
{
    private SandboxMount() { }

    public sealed record ReadWrite(string Path) : SandboxMount;

    public sealed record Gateway(string MountPath, string DestinationPath) : SandboxMount;

    public sealed record Overlay(
        string SourcePath,
        string LowerPath,
        string UpperPath,
        string WorkPath) : SandboxMount;
}
