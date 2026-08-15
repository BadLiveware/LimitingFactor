namespace LimitingFactor.LowLevel;

public enum SandboxChangeKind
{
    Created,
    Modified,
    Deleted,
}

/// <summary>Describes one host-visible change staged by a copy-on-write overlay.</summary>
public sealed record SandboxChange(
    SandboxChangeKind Kind,
    string Path);
