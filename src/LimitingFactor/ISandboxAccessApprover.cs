namespace LimitingFactor;

/// <summary>Implemented by a trusted host application to decide held filesystem mutations.</summary>
public interface ISandboxAccessApprover
{
    ValueTask<SandboxAccessDecision> ApproveAsync(
        SandboxAccessRequest request,
        CancellationToken cancellationToken);
}
