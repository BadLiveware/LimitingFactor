namespace LimitingFactor;

/// <summary>Grants one normalized host path to the sandbox.</summary>
public sealed record SandboxGrant
{
    public SandboxGrant(string path, SandboxAccessMode mode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode), mode, "Sandbox access mode is not defined.");
        }
        Path = SandboxPath.Normalize(path);
        Mode = mode;
    }

    public string Path { get; }

    public SandboxAccessMode Mode { get; }
}
