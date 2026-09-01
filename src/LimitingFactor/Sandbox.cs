using LimitingFactor.LowLevel;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace LimitingFactor;

/// <summary>Starts process trees under a validated Linux sandbox policy.</summary>
[SupportedOSPlatform("linux")]
public static class Sandbox
{
    public static async Task<SandboxSession> StartAsync(
        SandboxPolicy policy,
        ProcessStartInfo processStartInfo,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(processStartInfo);

        var support = SandboxSupport.Get(
            requireFuse: policy.ApprovalRoots.Length > 0,
            requireOverlay: policy.Grants.Any(static grant => grant.Mode == SandboxAccessMode.CopyOnWrite));
        if (!support.IsAvailable)
        {
            throw new PlatformNotSupportedException(support.Reason);
        }

        if (string.IsNullOrWhiteSpace(processStartInfo.FileName))
        {
            throw new ArgumentException("A sandbox command is required.", nameof(processStartInfo));
        }

        if (!string.IsNullOrEmpty(processStartInfo.Arguments))
        {
            throw new ArgumentException(
                "Use ProcessStartInfo.ArgumentList so sandbox arguments remain unambiguous.",
                nameof(processStartInfo));
        }

        var copyOnWrite = policy.Grants
            .Where(static grant => grant.Mode == SandboxAccessMode.CopyOnWrite)
            .Select(static grant => new CopyOnWriteOverlay(grant.Path))
            .ToArray();
        try
        {
            var overlays = copyOnWrite.ToDictionary(
                static state => state.SourceRoot,
                StringComparer.Ordinal);
            var mounts = policy.Grants
                .OrderBy(static grant => PathDepth(grant.Path))
                .ThenBy(static grant => grant.Path, StringComparer.Ordinal)
                .Select(grant => CreateMount(grant, overlays))
                .ToArray();

            var options = new SandboxLaunchOptions
            {
                FileName = processStartInfo.FileName,
                Arguments = processStartInfo.ArgumentList.ToArray(),
                WorkingDirectory = policy.WorkingDirectory,
                Environment = processStartInfo.Environment.ToDictionary(),
                Mounts = mounts,
                RedirectStandardInput = processStartInfo.RedirectStandardInput,
                RedirectStandardOutput = processStartInfo.RedirectStandardOutput,
                RedirectStandardError = processStartInfo.RedirectStandardError,
            };
            var approvers = policy.ApprovalRoots.ToImmutableDictionary(
                static root => root,
                root => (ISandboxMutationApprover)new ApproverAdapter(policy.Approver!, root),
                StringComparer.Ordinal);
            var process = await SandboxProcess.StartAsync(options, approvers, cancellationToken)
                .ConfigureAwait(false);
            return new SandboxSession(process, copyOnWrite);
        }
        catch
        {
            foreach (var state in copyOnWrite)
            {
                state.Dispose();
            }
            throw;
        }
    }

    private static SandboxMount CreateMount(
        SandboxGrant grant,
        IReadOnlyDictionary<string, CopyOnWriteOverlay> overlays)
    {
        if (grant.Mode == SandboxAccessMode.ReadWrite)
        {
            return new SandboxMount.ReadWrite(grant.Path);
        }
        if (grant.Mode == SandboxAccessMode.ReadOnly)
        {
            return new SandboxMount.ReadOnly(grant.Path);
        }

        var overlay = overlays[grant.Path];
        return new SandboxMount.Overlay(
            overlay.SourceRoot,
            overlay.LowerRoot,
            overlay.UpperRoot,
            overlay.WorkRoot);
    }

    private static int PathDepth(string path) =>
        path.Count(static character => character == Path.DirectorySeparatorChar);

    private sealed class ApproverAdapter(
        ISandboxAccessApprover approver,
        string approvalRoot) : ISandboxMutationApprover
    {
        public async ValueTask<SandboxMutationDecision> ApproveAsync(
            SandboxMutationRequest request,
            CancellationToken cancellationToken)
        {
            var operation = (SandboxFileOperation)(int)request.Operation;
            var decision = await approver.ApproveAsync(
                new SandboxAccessRequest(
                    operation,
                    request.Path,
                    approvalRoot,
                    request.DestinationPath,
                    request.ProcessId),
                cancellationToken).ConfigureAwait(false);
            return decision.IsAllowed && decision.Mode == SandboxAccessMode.ReadWrite && decision.Path is not null
                ? SandboxMutationDecision.Allow(decision.Path)
                : SandboxMutationDecision.Deny;
        }
    }
}

/// <summary>Owns a running sandboxed process and its supervisor-side resources.</summary>
[SupportedOSPlatform("linux")]
public sealed class SandboxSession : IAsyncDisposable, IDisposable
{
    private readonly SandboxProcess _process;
    private readonly IReadOnlyList<CopyOnWriteOverlay> _copyOnWrite;
    private bool _disposed;

    internal SandboxSession(
        SandboxProcess process,
        IReadOnlyList<CopyOnWriteOverlay> copyOnWrite)
    {
        _process = process;
        _copyOnWrite = copyOnWrite;
    }

    public Process Process => _process.Process;

    public IReadOnlyList<SandboxChange> GetChanges() =>
        _copyOnWrite.Where(static state => !state.IsDisposed)
            .SelectMany(static state => state.GetChanges())
            .Select(static change => new SandboxChange(
                (SandboxChangeKind)(int)change.Kind,
                change.Path))
            .ToArray();

    public void ApplyChanges()
    {
        EnsureExited();
        foreach (var state in _copyOnWrite)
        {
            state.Apply();
        }
    }

    public void DiscardChanges()
    {
        EnsureExited();
        foreach (var state in _copyOnWrite)
        {
            state.Discard();
        }
    }

    private void EnsureExited()
    {
        if (!Process.HasExited)
        {
            throw new InvalidOperationException("COW changes can be applied or discarded only after the sandbox process exits.");
        }
    }

    public Task WaitForExitAsync(CancellationToken cancellationToken = default) =>
        _process.WaitForExitAsync(cancellationToken);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _process.Dispose();
        foreach (var state in _copyOnWrite)
        {
            state.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        await _process.DisposeAsync().ConfigureAwait(false);
        foreach (var state in _copyOnWrite)
        {
            state.Dispose();
        }
    }
}
