using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace LimitingFactor.LowLevel;

[SupportedOSPlatform("linux")]
public sealed partial class CopyOnWriteOverlay : IDisposable
{
    private const uint FileTypeMask = 0xF000;
    private const uint RegularFile = 0x8000;
    private const uint DirectoryFile = 0x4000;
    private const uint SymbolicLink = 0xA000;
    private const uint CharacterDevice = 0x2000;

    private readonly string _sourceRoot;
    private readonly string _stateRoot;
    private readonly string _upperRoot;
    private readonly BaselineEntry _sourceBaseline;
    private readonly Dictionary<string, BaselineEntry> _baseline;
    private bool _disposed;

    public CopyOnWriteOverlay(string sourceRoot)
    {
        _sourceRoot = SandboxPath.Normalize(sourceRoot);
        if (MountTable.HasDescendantMount(_sourceRoot, File.ReadLines("/proc/self/mountinfo")))
        {
            throw new NotSupportedException(
                $"Copy-on-write source '{_sourceRoot}' contains a mounted subtree. Nested mount reconstruction is not supported.");
        }
        _stateRoot = Path.Combine(
            Path.GetTempPath(),
            $"limiting-factor-cow-{Environment.ProcessId}-{Guid.NewGuid():N}");
        LowerRoot = Path.Combine(_stateRoot, "lower");
        UpperRoot = Path.Combine(_stateRoot, "upper");
        WorkRoot = Path.Combine(_stateRoot, "work");
        var privateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(_stateRoot, privateMode);
        Directory.CreateDirectory(LowerRoot, privateMode);
        Directory.CreateDirectory(UpperRoot, privateMode);
        Directory.CreateDirectory(WorkRoot, privateMode);
        _upperRoot = UpperRoot;
        _sourceBaseline = BaselineEntry.Capture(_sourceRoot);
        _baseline = CaptureBaseline(_sourceRoot);
    }

    public string SourceRoot => _sourceRoot;
    public string LowerRoot { get; }
    public string UpperRoot { get; }
    public string WorkRoot { get; }
    public bool IsDisposed => _disposed;

    public IReadOnlyList<SandboxChange> GetChanges()
    {
        ThrowIfDisposed();
        return EnumerateUpperEntries()
            .Select(entry => entry.IsWhiteout
                ? new SandboxChange(SandboxChangeKind.Deleted, Path.Combine(_sourceRoot, entry.RelativePath))
                : new SandboxChange(
                    _baseline.ContainsKey(entry.RelativePath)
                        ? SandboxChangeKind.Modified
                        : SandboxChangeKind.Created,
                    Path.Combine(_sourceRoot, entry.RelativePath)))
            .OrderBy(static change => change.Path, StringComparer.Ordinal)
            .ToArray();
    }

    public void Apply()
    {
        ThrowIfDisposed();
        var entries = EnumerateUpperEntries().ToArray();
        if (!_sourceBaseline.Matches(_sourceRoot))
        {
            throw HostChanged(_sourceRoot);
        }
        var unsupported = entries.FirstOrDefault(static entry => entry.Kind == UpperEntryKind.Unsupported);
        if (unsupported is not null)
        {
            throw new NotSupportedException(
                $"COW apply does not support the staged filesystem entry '{unsupported.UpperPath}'.");
        }
        foreach (var entry in entries)
        {
            ValidateDestination(entry.RelativePath);
            if (entry.IsOpaque)
            {
                ValidateOpaqueDirectory(entry.RelativePath);
            }
        }

        foreach (var entry in entries
                     .Where(static entry => entry.IsWhiteout || entry.IsOpaque)
                     .OrderByDescending(static entry => PathDepth(entry.RelativePath)))
        {
            var destination = Path.Combine(_sourceRoot, entry.RelativePath);
            if (PathExists(destination))
            {
                DeleteWithoutFollowingLinks(destination);
            }
        }

        foreach (var entry in entries.Where(static entry => !entry.IsWhiteout)
                     .OrderBy(static entry => PathDepth(entry.RelativePath)))
        {
            EnsureAncestorsSafeForApply(entry.RelativePath, entries);
            var destination = Path.Combine(_sourceRoot, entry.RelativePath);
            if (entry.Kind == UpperEntryKind.Directory)
            {
                Directory.CreateDirectory(destination);
            }
            else if (entry.Kind == UpperEntryKind.RegularFile)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(entry.UpperPath, destination, overwrite: true);
            }
            else
            {
                throw new NotSupportedException(
                    $"COW apply does not support the staged filesystem entry '{entry.UpperPath}'.");
            }
        }

        Dispose();
    }

    public void Discard() => Dispose();

    private void ValidateDestination(string relativePath)
    {
        EnsureAncestorsUnchanged(relativePath);
        var destination = Path.Combine(_sourceRoot, relativePath);
        if (_baseline.TryGetValue(relativePath, out var baseline))
        {
            if (!baseline.Matches(destination))
            {
                throw HostChanged(destination);
            }
        }
        else if (PathExists(destination))
        {
            throw new InvalidOperationException(
                $"Cannot apply COW change to '{destination}' because the host created that path after the sandbox started.");
        }
    }

    private void EnsureAncestorsUnchanged(string relativePath)
    {
        if (!_sourceBaseline.Matches(_sourceRoot))
        {
            throw HostChanged(_sourceRoot);
        }
        var parent = Path.GetDirectoryName(relativePath);
        while (!string.IsNullOrEmpty(parent))
        {
            var path = Path.Combine(_sourceRoot, parent);
            if (!_baseline.TryGetValue(parent, out var baseline) || !baseline.Matches(path) || !baseline.IsDirectory)
            {
                throw HostChanged(path);
            }
            parent = Path.GetDirectoryName(parent);
        }
    }

    private void EnsureAncestorsSafeForApply(string relativePath, IReadOnlyList<UpperEntry> entries)
    {
        if (!_sourceBaseline.Matches(_sourceRoot))
        {
            throw HostChanged(_sourceRoot);
        }
        var parent = Path.GetDirectoryName(relativePath);
        while (!string.IsNullOrEmpty(parent))
        {
            if (!entries.Any(entry => entry.IsOpaque && string.Equals(entry.RelativePath, parent, StringComparison.Ordinal)))
            {
                var path = Path.Combine(_sourceRoot, parent);
                if (!_baseline.TryGetValue(parent, out var baseline) || !baseline.Matches(path) || !baseline.IsDirectory)
                {
                    throw HostChanged(path);
                }
            }
            parent = Path.GetDirectoryName(parent);
        }
    }

    private void ValidateOpaqueDirectory(string relativePath)
    {
        var destination = Path.Combine(_sourceRoot, relativePath);
        if (!Directory.Exists(destination))
        {
            return;
        }

        foreach (var path in Directory.EnumerateFileSystemEntries(destination, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(_sourceRoot, path);
            if (!_baseline.TryGetValue(relative, out var baseline))
            {
                throw new InvalidOperationException(
                    $"Cannot apply COW change to '{path}' because the host created that path after the sandbox started.");
            }
            if (!baseline.Matches(path))
            {
                throw HostChanged(path);
            }
        }

        foreach (var pair in _baseline.Where(pair => IsDescendant(relativePath, pair.Key)))
        {
            var path = Path.Combine(_sourceRoot, pair.Key);
            if (!pair.Value.Matches(path))
            {
                throw HostChanged(path);
            }
        }
    }

    private static bool IsDescendant(string parent, string candidate) =>
        candidate.Length > parent.Length
        && candidate.StartsWith(parent, StringComparison.Ordinal)
        && candidate[parent.Length] == Path.DirectorySeparatorChar;

    private static InvalidOperationException HostChanged(string path) =>
        new($"Cannot apply COW change to '{path}' because the host source changed.");

    private IEnumerable<UpperEntry> EnumerateUpperEntries()
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(_upperRoot, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(_upperRoot, path);
            var status = GetStatus(path);
            var type = status.Mode & FileTypeMask;
            var whiteout = type == CharacterDevice && status.DeviceId == 0;
            var kind = type switch
            {
                DirectoryFile => UpperEntryKind.Directory,
                RegularFile => UpperEntryKind.RegularFile,
                _ when whiteout => UpperEntryKind.Whiteout,
                _ => UpperEntryKind.Unsupported,
            };
            yield return new UpperEntry(relative, path, kind, IsOpaqueDirectory(path, kind));
        }
    }

    private static bool IsOpaqueDirectory(string path, UpperEntryKind kind)
    {
        if (kind != UpperEntryKind.Directory)
        {
            return false;
        }

        Span<byte> value = stackalloc byte[1];
        var length = getxattr(path, "user.overlay.opaque", ref MemoryMarshal.GetReference(value), (nuint)value.Length);
        if (length < 0)
        {
            var error = Marshal.GetLastPInvokeError();
            const int NoData = 61;
            const int NotSupported = 95;
            if (error is NoData or NotSupported)
            {
                return false;
            }
            throw new IOException($"Reading OverlayFS metadata for '{path}' failed with errno {error}.");
        }
        return length == 1 && value[0] == (byte)'y';
    }

    private static void DeleteWithoutFollowingLinks(string path)
    {
        var status = GetStatus(path);
        if ((status.Mode & FileTypeMask) == DirectoryFile)
        {
            Directory.Delete(path, recursive: true);
        }
        else
        {
            File.Delete(path);
        }
    }

    private static int PathDepth(string path) =>
        path.Count(static character => character == Path.DirectorySeparatorChar);

    [StructLayout(LayoutKind.Sequential, Size = 144)]
    private struct LinuxStat
    {
        public ulong Device;
        public ulong Inode;
        public ulong Links;
        public uint Mode;
        public uint UserId;
        public uint GroupId;
        private int _padding;
        public ulong DeviceId;
    }

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int lstat(string path, out LinuxStat status);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial nint getxattr(string path, string name, ref byte value, nuint size);

    private static LinuxStat GetStatus(string path)
    {
        if (lstat(path, out var status) != 0)
        {
            throw new IOException($"Reading filesystem metadata for '{path}' failed with errno {Marshal.GetLastPInvokeError()}.");
        }
        return status;
    }

    private static bool TryGetStatus(string path, out LinuxStat status)
    {
        if (lstat(path, out status) == 0)
        {
            return true;
        }
        const int NotFound = 2;
        const int NotDirectory = 20;
        var error = Marshal.GetLastPInvokeError();
        if (error is NotFound or NotDirectory)
        {
            return false;
        }
        throw new IOException($"Reading filesystem metadata for '{path}' failed with errno {error}.");
    }

    private static bool PathExists(string path) => TryGetStatus(path, out _);

    private static Dictionary<string, BaselineEntry> CaptureBaseline(string root)
    {
        var entries = new Dictionary<string, BaselineEntry>(StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(root, path);
            entries[relative] = BaselineEntry.Capture(path);
        }
        return entries;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (Directory.Exists(_stateRoot))
        {
            ClearReadOnlyModes(_stateRoot);
            Directory.Delete(_stateRoot, recursive: true);
        }
    }

    private static void ClearReadOnlyModes(string root)
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories).Prepend(root))
        {
            try
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            catch (IOException)
            {
            }
        }
    }

    private enum UpperEntryKind
    {
        Directory,
        RegularFile,
        Whiteout,
        Unsupported,
    }

    private sealed record UpperEntry(
        string RelativePath,
        string UpperPath,
        UpperEntryKind Kind,
        bool IsOpaque)
    {
        public bool IsWhiteout => Kind == UpperEntryKind.Whiteout;
    }

    private sealed record BaselineEntry(
        uint Type,
        ulong Device,
        ulong Inode,
        long Length,
        long LastWriteTicks,
        string? Content)
    {
        public bool IsDirectory => Type == DirectoryFile;

        public static BaselineEntry Capture(string path)
        {
            var status = GetStatus(path);
            var type = status.Mode & FileTypeMask;
            return type switch
            {
                DirectoryFile => new(type, status.Device, status.Inode, 0, Directory.GetLastWriteTimeUtc(path).Ticks, null),
                RegularFile => CaptureRegular(path, status),
                SymbolicLink => new(type, status.Device, status.Inode, 0, 0, new FileInfo(path).LinkTarget),
                _ => new(type, status.Device, status.Inode, 0, 0, null),
            };
        }

        private static BaselineEntry CaptureRegular(string path, LinuxStat status)
        {
            var info = new FileInfo(path);
            using var stream = File.OpenRead(path);
            return new(
                RegularFile,
                status.Device,
                status.Inode,
                info.Length,
                info.LastWriteTimeUtc.Ticks,
                Convert.ToHexString(SHA256.HashData(stream)));
        }

        public bool Matches(string path)
        {
            if (!TryGetStatus(path, out var status) || (status.Mode & FileTypeMask) != Type)
            {
                return false;
            }
            if (status.Device != Device || status.Inode != Inode)
            {
                return false;
            }
            if (Type == RegularFile)
            {
                return this == Capture(path);
            }
            if (Type == SymbolicLink)
            {
                return string.Equals(Content, new FileInfo(path).LinkTarget, StringComparison.Ordinal);
            }
            return true;
        }
    }
}
