namespace LimitingFactor;

/// <summary>Controls how a sandbox may mutate a granted filesystem tree.</summary>
public enum SandboxAccessMode
{
    ReadOnly,
    ReadWrite,
    CopyOnWrite,
}
