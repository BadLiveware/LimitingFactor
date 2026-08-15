namespace LimitingFactor.LowLevel;

/// <summary>Describes a filesystem mutation held by a low-level approval mount.</summary>
public sealed record SandboxMutationRequest(
    SandboxMutationOperation Operation,
    string Path,
    string SourceRoot,
    string? DestinationPath = null,
    int? ProcessId = null);
