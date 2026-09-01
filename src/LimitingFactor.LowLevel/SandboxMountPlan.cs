using System.Runtime.Versioning;

namespace LimitingFactor.LowLevel;

[SupportedOSPlatform("linux")]
internal sealed class SandboxMountPlan : IDisposable
{
    private readonly string _stateRoot;
    private bool _disposed;

    public SandboxMountPlan(IReadOnlyList<SandboxMount> mounts)
    {
        var overlappingPaths = mounts
            .Where(static mount => mount is not SandboxMount.Gateway)
            .Select(MountPath)
            .Distinct(StringComparer.Ordinal)
            .Where(path => mounts.Any(mount =>
                mount is not SandboxMount.Gateway
                && !string.Equals(MountPath(mount), path, StringComparison.Ordinal)
                && SandboxPath.Contains(MountPath(mount), path)))
            .ToArray();
        if (overlappingPaths.Length == 0)
        {
            Mounts = mounts;
            _stateRoot = string.Empty;
            return;
        }

        _stateRoot = Path.Combine(
            Path.GetTempPath(),
            $"limiting-factor-mounts-{Environment.ProcessId}-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(
                _stateRoot,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var backingPaths = overlappingPaths.ToDictionary(
                static path => path,
                CreateBackingPath,
                StringComparer.Ordinal);
            Mounts = mounts
                .Select(mount => Capture(mount, backingPaths.GetValueOrDefault(MountPath(mount))))
                .ToArray();
        }
        catch
        {
            DeleteStateRoot(_stateRoot);
            throw;
        }
    }

    public IReadOnlyList<SandboxMount> Mounts { get; }
    public string? StateRoot => string.IsNullOrEmpty(_stateRoot) ? null : _stateRoot;

    private string CreateBackingPath(string path)
    {
        var backingPath = Path.Combine(_stateRoot, Guid.NewGuid().ToString("N"));
        if (Directory.Exists(path))
        {
            Directory.CreateDirectory(backingPath);
        }
        else
        {
            using var _ = File.Create(backingPath);
        }
        return backingPath;
    }

    private static string MountPath(SandboxMount mount) => mount switch
    {
        SandboxMount.ReadWrite readWrite => readWrite.Path,
        SandboxMount.ReadOnly readOnly => readOnly.Path,
        SandboxMount.Gateway gateway => gateway.DestinationPath,
        SandboxMount.Overlay overlay => overlay.SourcePath,
        SandboxMount.CapturedReadWrite readWrite => readWrite.Path,
        SandboxMount.CapturedReadOnly readOnly => readOnly.Path,
        SandboxMount.CapturedOverlay overlay => overlay.SourcePath,
        _ => throw new InvalidOperationException($"Unknown sandbox mount type: {mount.GetType().Name}"),
    };

    private static SandboxMount Capture(SandboxMount mount, string? backingPath)
    {
        if (backingPath is null)
        {
            return mount;
        }

        return mount switch
        {
            SandboxMount.ReadWrite readWrite => new SandboxMount.CapturedReadWrite(readWrite.Path, backingPath),
            SandboxMount.ReadOnly readOnly => new SandboxMount.CapturedReadOnly(readOnly.Path, backingPath),
            SandboxMount.Overlay overlay => new SandboxMount.CapturedOverlay(
                overlay.SourcePath,
                backingPath,
                overlay.LowerPath,
                overlay.UpperPath,
                overlay.WorkPath),
            _ => mount,
        };
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        DeleteStateRoot(_stateRoot);
    }

    private static void DeleteStateRoot(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }
}
