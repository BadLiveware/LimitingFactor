namespace LimitingFactor;

/// <summary>A trusted host decision for a held filesystem mutation.</summary>
public sealed record SandboxAccessDecision
{
    private SandboxAccessDecision(bool isAllowed, SandboxAccessMode mode, string? path)
    {
        IsAllowed = isAllowed;
        Mode = mode;
        Path = path;
    }

    public bool IsAllowed { get; }

    public SandboxAccessMode Mode { get; }

    /// <summary>The file or directory prefix granted by this decision, or null when denied.</summary>
    public string? Path { get; }

    public static SandboxAccessDecision Deny { get; } = new(false, SandboxAccessMode.ReadOnly, null);

    public static SandboxAccessDecision AllowReadWrite(string path) =>
        new(true, SandboxAccessMode.ReadWrite, SandboxPath.Normalize(path));
}
