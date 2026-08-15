namespace LimitingFactor.LowLevel;

/// <summary>Decides whether a mutation held by a low-level approval filesystem may proceed.</summary>
public interface ISandboxMutationApprover
{
    ValueTask<SandboxMutationDecision> ApproveAsync(
        SandboxMutationRequest request,
        CancellationToken cancellationToken);
}

/// <summary>A low-level decision granting a writable prefix or denying a held mutation.</summary>
public sealed record SandboxMutationDecision
{
    private SandboxMutationDecision(bool isAllowed, string? writablePrefix)
    {
        IsAllowed = isAllowed;
        WritablePrefix = writablePrefix;
    }

    public bool IsAllowed { get; }
    public string? WritablePrefix { get; }

    public static SandboxMutationDecision Deny { get; } = new(false, null);

    public static SandboxMutationDecision Allow(string writablePrefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(writablePrefix);
        return new(true, SandboxPath.Normalize(writablePrefix));
    }
}
