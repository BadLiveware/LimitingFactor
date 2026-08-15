using FuseDotNet;
using FuseDotNet.Logging;
using System.Runtime.Versioning;

namespace LimitingFactor.LowLevel;

/// <summary>Runs an approval filesystem against a FUSE descriptor mounted by the native helper.</summary>
[SupportedOSPlatform("linux")]
public sealed partial class ApprovalMount : IDisposable
{
    private readonly ApprovalFileSystem _fileSystem;
    private readonly Task _mountTask;
    private readonly int _fuseFileDescriptor;
    private bool _disposed;

    private ApprovalMount(
        ApprovalFileSystem fileSystem,
        Task mountTask,
        int fuseFileDescriptor)
    {
        _fileSystem = fileSystem;
        _mountTask = mountTask;
        _fuseFileDescriptor = fuseFileDescriptor;
    }

    internal static ApprovalMount Start(
        string sourceRoot,
        int fuseFileDescriptor,
        ISandboxMutationApprover approver,
        CancellationToken cancellationToken)
    {
        var fileSystem = new ApprovalFileSystem(sourceRoot, approver, cancellationToken);
        var descriptorPath = $"/dev/fd/{fuseFileDescriptor}";
        var mountTask = Task.Factory.StartNew(
            () => fileSystem.Mount(
                ["LimitingFactor", "-f", descriptorPath],
                new NullLogger()),
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default);
        return new ApprovalMount(fileSystem, mountTask, fuseFileDescriptor);
    }

    internal void ThrowIfFaulted()
    {
        if (_mountTask.IsCompleted)
        {
            _mountTask.GetAwaiter().GetResult();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        close(_fuseFileDescriptor);
        _fileSystem.Dispose();
        try
        {
            _mountTask.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // The process namespace owns the mount and may already have torn it down.
        }
    }

    [System.Runtime.InteropServices.LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fileDescriptor);
}
