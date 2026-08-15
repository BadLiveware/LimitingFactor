using System.Collections.Immutable;
using FuseDotNet;
using FuseDotNet.Extensions;
using LTRData.Extensions.Native.Memory;
using System.Runtime.Versioning;

namespace LimitingFactor.LowLevel;

[SupportedOSPlatform("linux")]
internal sealed class ApprovalFileSystem(
    string sourceRoot,
    ISandboxMutationApprover? approver,
    CancellationToken cancellationToken) : IFuseOperations
{
    private readonly string _sourceRoot = SandboxPath.Normalize(sourceRoot);
    private readonly object _policyLock = new();
    private ImmutableArray<string> _writablePrefixes = [];

    public PosixResult Access(ReadOnlyNativeMemory<byte> path, PosixAccessMode mask) =>
        Exists(GetSourcePath(path)) ? PosixResult.Success : PosixResult.ENOENT;

    public PosixResult Create(ReadOnlyNativeMemory<byte> path, int mode, ref FuseFileInfo fileInfo)
    {
        fileInfo.Context = null;
        return OpenCore(path, ref fileInfo, SandboxMutationOperation.CreateFile, FileMode.CreateNew);
    }

    public PosixResult Open(ReadOnlyNativeMemory<byte> path, ref FuseFileInfo fileInfo)
    {
        const int LinuxOpenTruncate = 0x200;
        var truncates = ((int)fileInfo.flags & LinuxOpenTruncate) != 0;
        return OpenCore(
            path,
            ref fileInfo,
            truncates ? SandboxMutationOperation.Truncate : SandboxMutationOperation.OpenForWrite,
            truncates ? FileMode.Truncate : FileMode.Open);
    }

    private PosixResult OpenCore(
        ReadOnlyNativeMemory<byte> path,
        ref FuseFileInfo fileInfo,
        SandboxMutationOperation operation,
        FileMode fileMode)
    {
        var sourcePath = GetSourcePath(path);
        var access = fileInfo.flags.ToFileAccess();
        var mutates = access is FileAccess.Write or FileAccess.ReadWrite;
        if (mutates)
        {
            var decision = EnsureWritable(sourcePath, operation);
            if (decision != PosixResult.Success)
            {
                return decision;
            }
        }

        if (ContainsSymbolicLink(
            sourcePath,
            allowMissingLeaf: operation == SandboxMutationOperation.CreateFile))
        {
            return PosixResult.ENOTSUP;
        }

        var backingPath = sourcePath;
        fileInfo.Context = File.Open(backingPath, fileMode, access, FileShare.ReadWrite | FileShare.Delete);
        return PosixResult.Success;
    }

    public PosixResult Truncate(ReadOnlyNativeMemory<byte> path, long size)
    {
        var sourcePath = GetSourcePath(path);
        var decision = EnsureWritable(sourcePath, SandboxMutationOperation.Truncate);
        if (decision != PosixResult.Success)
        {
            return decision;
        }

        if (ContainsSymbolicLink(sourcePath, allowMissingLeaf: false))
        {
            return PosixResult.ENOTSUP;
        }

        using var file = File.Open(sourcePath, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
        file.SetLength(size);
        return PosixResult.Success;
    }

    private PosixResult EnsureWritable(string sourcePath, SandboxMutationOperation operation)
    {
        lock (_policyLock)
        {
            if (_writablePrefixes.Any(prefix => SandboxPath.Contains(prefix, sourcePath)))
            {
                return PosixResult.Success;
            }
        }

        SandboxMutationDecision decision;
        try
        {
            decision = Task.Run(
                async () => await (approver ?? throw new InvalidOperationException("No access approver is configured.")).ApproveAsync(
                    new SandboxMutationRequest(operation, sourcePath, _sourceRoot),
                    cancellationToken).ConfigureAwait(false),
                cancellationToken).GetAwaiter().GetResult();
        }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException)
        {
            return PosixResult.EACCES;
        }

        if (!decision.IsAllowed || decision.WritablePrefix is null)
        {
            return PosixResult.EACCES;
        }


        if (!SandboxPath.Contains(_sourceRoot, decision.WritablePrefix)
            || !SandboxPath.Contains(decision.WritablePrefix, sourcePath))
        {
            return PosixResult.EACCES;
        }

        lock (_policyLock)
        {
            _writablePrefixes = _writablePrefixes
                .Where(prefix => !SandboxPath.Contains(decision.WritablePrefix, prefix))
                .Append(decision.WritablePrefix)
                .ToImmutableArray();
        }

        return PosixResult.Success;
    }

    public PosixResult GetAttr(
        ReadOnlyNativeMemory<byte> path,
        out FuseFileStat stat,
        ref FuseFileInfo fileInfo)
    {
        var sourcePath = GetSourcePath(path);
        if (ContainsSymbolicLink(sourcePath, allowMissingLeaf: false))
        {
            stat = default;
            return PosixResult.ENOTSUP;
        }

        var visiblePath = sourcePath;
        if (File.Exists(visiblePath))
        {
            var info = new FileInfo(visiblePath);
            stat = new FuseFileStat
            {
                st_size = info.Length,
                st_birthtim = info.CreationTimeUtc,
                st_mtim = info.LastWriteTimeUtc,
                st_ctim = info.LastWriteTimeUtc,
                st_atim = info.LastAccessTimeUtc,
                st_mode = ToMode(info),
                st_nlink = 1,
            };
            return PosixResult.Success;
        }

        if (Directory.Exists(visiblePath))
        {
            var info = new DirectoryInfo(visiblePath);
            stat = new FuseFileStat
            {
                st_birthtim = info.CreationTimeUtc,
                st_mtim = info.LastWriteTimeUtc,
                st_ctim = info.LastWriteTimeUtc,
                st_atim = info.LastAccessTimeUtc,
                st_mode = ToMode(info),
                st_nlink = 2,
            };
            return PosixResult.Success;
        }

        stat = default;
        return PosixResult.ENOENT;
    }

    public PosixResult OpenDir(ReadOnlyNativeMemory<byte> path, ref FuseFileInfo fileInfo)
    {
        var sourcePath = GetSourcePath(path);
        var visiblePath = sourcePath;
        return !Directory.Exists(visiblePath)
            ? PosixResult.ENOENT
            : PosixResult.Success;
    }

    public PosixResult ReadDir(
        ReadOnlyNativeMemory<byte> path,
        out IEnumerable<FuseDirEntry> entries,
        ref FuseFileInfo fileInfo,
        long offset,
        FuseReadDirFlags flags)
    {
        var sourcePath = GetSourcePath(path);
        var visiblePath = sourcePath;
        if (!Directory.Exists(visiblePath))
        {
            entries = [];
            return PosixResult.ENOENT;
        }

        var names = Directory.EnumerateFileSystemEntries(sourcePath).Select(Path.GetFileName).ToArray()!;
        entries = FuseHelper.DotEntries.Concat(names.Select(name =>
        {
            var child = Path.Combine(sourcePath, name!);
            var type = Directory.Exists(child) ? PosixFileMode.Directory : PosixFileMode.Regular;
            return new FuseDirEntry(name!, 0, 0, new FuseFileStat { st_mode = type });
        }));
        return PosixResult.Success;
    }

    public PosixResult Read(
        ReadOnlyNativeMemory<byte> path,
        NativeMemory<byte> buffer,
        long position,
        out int readLength,
        ref FuseFileInfo fileInfo)
    {
        if (fileInfo.Context is not Stream stream)
        {
            readLength = 0;
            return PosixResult.EBADF;
        }

        stream.Position = position;
        readLength = stream.Read(buffer.Span);
        return PosixResult.Success;
    }

    public PosixResult Write(
        ReadOnlyNativeMemory<byte> path,
        ReadOnlyNativeMemory<byte> buffer,
        long position,
        out int writtenLength,
        ref FuseFileInfo fileInfo)
    {
        if (fileInfo.Context is not Stream stream)
        {
            writtenLength = 0;
            return PosixResult.EBADF;
        }

        stream.Position = position;
        stream.Write(buffer.Span);
        writtenLength = buffer.Length;
        return PosixResult.Success;
    }

    public PosixResult Release(ReadOnlyNativeMemory<byte> path, ref FuseFileInfo fileInfo)
    {
        if (fileInfo.Context is IDisposable disposable)
        {
            disposable.Dispose();
            fileInfo.Context = null;
        }

        return PosixResult.Success;
    }

    public PosixResult Flush(ReadOnlyNativeMemory<byte> path, ref FuseFileInfo fileInfo)
    {
        if (fileInfo.Context is Stream stream)
        {
            stream.Flush();
        }

        return PosixResult.Success;
    }

    public PosixResult FSync(ReadOnlyNativeMemory<byte> path, bool datasync, ref FuseFileInfo fileInfo)
    {
        if (fileInfo.Context is FileStream stream)
        {
            stream.Flush(flushToDisk: true);
        }

        return PosixResult.Success;
    }

    private string GetSourcePath(ReadOnlyNativeMemory<byte> path)
    {
        var relative = FuseHelper.GetString(path).TrimStart(Path.DirectorySeparatorChar);
        var result = SandboxPath.Normalize(Path.Combine(_sourceRoot, relative));
        if (!SandboxPath.Contains(_sourceRoot, result))
        {
            throw new UnauthorizedAccessException("The FUSE path escaped its source root.");
        }

        return result;
    }

    private bool ContainsSymbolicLink(string path, bool allowMissingLeaf)
    {
        var relative = Path.GetRelativePath(_sourceRoot, path);
        var current = _sourceRoot;
        var components = relative == "." ? [] : relative.Split(Path.DirectorySeparatorChar);
        for (var index = 0; index < components.Length; index++)
        {
            current = Path.Combine(current, components[index]);
            if (!Exists(current))
            {
                return !(allowMissingLeaf && index == components.Length - 1);
            }

            if (File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Exists(string path) => File.Exists(path) || Directory.Exists(path);

    private static PosixFileMode ToMode(FileSystemInfo info)
    {
        var type = info.Attributes.HasFlag(FileAttributes.Directory)
            ? PosixFileMode.Directory
            : PosixFileMode.Regular;
        var unixMode = File.GetUnixFileMode(info.FullName);
        return type | (PosixFileMode)((int)unixMode & 0x1FF);
    }

    public void Init(ref FuseConnInfo fuse_conn_info) { }
    public void Dispose() { }
    public PosixResult FSyncDir(ReadOnlyNativeMemory<byte> path, bool datasync, ref FuseFileInfo fileInfo) => PosixResult.Success;
    public PosixResult ReleaseDir(ReadOnlyNativeMemory<byte> path, ref FuseFileInfo fileInfo) => PosixResult.Success;
    public PosixResult StatFs(ReadOnlyNativeMemory<byte> path, out FuseVfsStat stat)
    {
        stat = new FuseVfsStat { f_bsize = 4096, f_frsize = 4096 };
        return PosixResult.Success;
    }

    public PosixResult ReadLink(ReadOnlyNativeMemory<byte> path, NativeMemory<byte> target) => PosixResult.ENOTSUP;
    public PosixResult Link(ReadOnlyNativeMemory<byte> from, ReadOnlyNativeMemory<byte> to) => PosixResult.ENOTSUP;
    public PosixResult MkDir(ReadOnlyNativeMemory<byte> path, PosixFileMode mode)
    {
        var sourcePath = GetSourcePath(path);
        if (ContainsSymbolicLink(sourcePath, allowMissingLeaf: true))
        {
            return PosixResult.ENOTSUP;
        }
        var decision = EnsureWritable(sourcePath, SandboxMutationOperation.CreateDirectory);
        if (decision != PosixResult.Success)
        {
            return decision;
        }

        Directory.CreateDirectory(sourcePath);
        return PosixResult.Success;
    }

    public PosixResult RmDir(ReadOnlyNativeMemory<byte> path) => Delete(path, SandboxMutationOperation.RemoveDirectory);
    public PosixResult Unlink(ReadOnlyNativeMemory<byte> path) => Delete(path, SandboxMutationOperation.RemoveFile);

    private PosixResult Delete(ReadOnlyNativeMemory<byte> path, SandboxMutationOperation operation)
    {
        var sourcePath = GetSourcePath(path);
        if (ContainsSymbolicLink(sourcePath, allowMissingLeaf: false))
        {
            return PosixResult.ENOTSUP;
        }
        var decision = EnsureWritable(sourcePath, operation);
        if (decision != PosixResult.Success)
        {
            return decision;
        }

        if (operation == SandboxMutationOperation.RemoveDirectory)
        {
            Directory.Delete(sourcePath);
        }
        else
        {
            File.Delete(sourcePath);
        }
        return PosixResult.Success;
    }
    public PosixResult SymLink(ReadOnlyNativeMemory<byte> from, ReadOnlyNativeMemory<byte> to) => PosixResult.ENOTSUP;
    public PosixResult Rename(ReadOnlyNativeMemory<byte> from, ReadOnlyNativeMemory<byte> to) => PosixResult.ENOTSUP;
    public PosixResult UTime(ReadOnlyNativeMemory<byte> path, TimeSpec atime, TimeSpec mtime, ref FuseFileInfo fileInfo) => PosixResult.ENOTSUP;
    public PosixResult IoCtl(ReadOnlyNativeMemory<byte> path, int cmd, nint arg, ref FuseFileInfo fileInfo, FuseIoctlFlags flags, nint data) => PosixResult.ENOTSUP;
    public PosixResult ChMod(NativeMemory<byte> path, PosixFileMode mode) => PosixResult.ENOTSUP;
    public PosixResult ChOwn(NativeMemory<byte> path, int uid, int gid) => PosixResult.ENOTSUP;
    public PosixResult FAllocate(NativeMemory<byte> path, FuseAllocateMode mode, long offset, long length, ref FuseFileInfo fileInfo) => PosixResult.ENOTSUP;
}
