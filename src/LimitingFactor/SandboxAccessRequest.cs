namespace LimitingFactor;

/// <summary>Describes a held filesystem mutation awaiting a trusted host decision.</summary>
public sealed record SandboxAccessRequest(
    SandboxFileOperation Operation,
    string Path,
    string ApprovalRoot,
    string? DestinationPath = null,
    int? ProcessId = null);
