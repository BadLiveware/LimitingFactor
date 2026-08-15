namespace LimitingFactor;

public enum SandboxChangeKind
{
    Created,
    Modified,
    Deleted,
}

/// <summary>Describes one host-visible change staged by a copy-on-write grant.</summary>
public sealed record SandboxChange(
    SandboxChangeKind Kind,
    string Path);
