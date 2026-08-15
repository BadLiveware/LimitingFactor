using LimitingFactor.LowLevel;

namespace LimitingFactor;

/// <summary>Reports whether the local Linux dependencies for the sandbox are available.</summary>
public sealed record SandboxSupport(bool IsAvailable, string Reason)
{
    public static SandboxSupport Get(
        bool requireFuse = true,
        bool requireOverlay = true)
    {
        var support = SandboxRuntimeSupport.Get(requireFuse, requireOverlay);
        return new(support.IsAvailable, support.Reason);
    }
}
