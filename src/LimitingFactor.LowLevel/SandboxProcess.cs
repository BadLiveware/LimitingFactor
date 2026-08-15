using LimitingFactor.Native;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.Versioning;

namespace LimitingFactor.LowLevel;

/// <summary>Owns a process launched by the packaged native sandbox helper.</summary>
[SupportedOSPlatform("linux")]
public sealed partial class SandboxProcess : IDisposable, IAsyncDisposable
{
    private readonly IReadOnlyList<ApprovalMount> _approvalMounts;
    private bool _disposed;

    private SandboxProcess(Process process, IReadOnlyList<ApprovalMount> approvalMounts)
    {
        Process = process;
        _approvalMounts = approvalMounts;
    }

    public Process Process { get; }

    public static async Task<SandboxProcess> StartAsync(
        SandboxLaunchOptions options,
        IReadOnlyDictionary<string, ISandboxMutationApprover> approvalRoots,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(approvalRoots);

        var socketPath = Path.Combine(
            Path.GetTempPath(),
            $"limiting-factor-{Environment.ProcessId}-{Guid.NewGuid():N}.sock");
        using var listener = new Socket(AddressFamily.Unix, SocketType.Seqpacket, ProtocolType.Unspecified);
        listener.Bind(new UnixDomainSocketEndPoint(socketPath));
        listener.Listen(1);

        Process? process = null;
        var mounts = new List<ApprovalMount>();
        try
        {
            var startInfo = BuildStartInfo(options, approvalRoots.Keys, socketPath);
            process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("The native sandbox helper did not start.");

            using var registration = cancellationToken.Register(
                static value => ((Socket)value!).Dispose(), listener);
            using var connection = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            using var connectionRegistration = cancellationToken.Register(
                static value => CancelConnection((Socket)value!), connection);

            for (var expectedTag = 0; expectedTag < approvalRoots.Count; expectedTag++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var received = UnixDescriptorReceiver.Receive(connection, cancellationToken);
                if (received.Tag != expectedTag)
                {
                    close(received.FileDescriptor);
                    throw new IOException(
                        $"The native sandbox helper sent FUSE descriptor tag {received.Tag}; expected {expectedTag}.");
                }

                var root = approvalRoots.Keys.ElementAt(expectedTag);
                var mount = ApprovalMount.Start(
                    root,
                    received.FileDescriptor,
                    approvalRoots[root],
                    cancellationToken);
                mounts.Add(mount);
            }

            await WaitForApprovalMountsAsync(
                process,
                approvalRoots.Keys,
                mounts,
                cancellationToken).ConfigureAwait(false);
            connection.Send([1]);
            return new SandboxProcess(process, mounts);
        }
        catch
        {
            if (process is { HasExited: false })
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
            process?.Dispose();
            foreach (var mount in mounts)
            {
                mount.Dispose();
            }
            throw;
        }
        finally
        {
            try
            {
                File.Delete(socketPath);
            }
            catch (IOException)
            {
            }
        }
    }

    private static void CancelConnection(Socket connection)
    {
        try
        {
            connection.Shutdown(SocketShutdown.Both);
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static async Task WaitForApprovalMountsAsync(
        Process helperProcess,
        IEnumerable<string> roots,
        IReadOnlyList<ApprovalMount> mounts,
        CancellationToken cancellationToken)
    {
        var pending = roots.ToHashSet(StringComparer.Ordinal);
        for (var attempt = 0; attempt < 500 && pending.Count > 0; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (helperProcess.HasExited)
            {
                throw new InvalidOperationException(
                    $"The native sandbox helper exited with code {helperProcess.ExitCode} before its approval mounts became ready.");
            }

            foreach (var mount in mounts)
            {
                mount.ThrowIfFaulted();
            }

            foreach (var root in pending.ToArray())
            {
                if (File.ReadLines($"/proc/{helperProcess.Id}/mountinfo").Any(line =>
                    line.Split(' ').Length > 4
                    && string.Equals(
                        UnescapeMountInfo(line.Split(' ')[4]),
                        root,
                        StringComparison.Ordinal)))
                {
                    pending.Remove(root);
                }
            }

            if (pending.Count > 0)
            {
                await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            }
        }

        if (pending.Count > 0)
        {
            throw new TimeoutException(
                $"Approval mounts did not become ready within five seconds: {string.Join(", ", pending)}");
        }
    }

    private static string UnescapeMountInfo(string value) =>
        value.Replace("\\040", " ", StringComparison.Ordinal)
            .Replace("\\011", "\t", StringComparison.Ordinal)
            .Replace("\\012", "\n", StringComparison.Ordinal)
            .Replace("\\134", "\\", StringComparison.Ordinal);

    private static ProcessStartInfo BuildStartInfo(
        SandboxLaunchOptions options,
        IEnumerable<string> approvalRoots,
        string socketPath)
    {
        var startInfo = new ProcessStartInfo(NativeSandboxHelper.GetPath())
        {
            WorkingDirectory = options.WorkingDirectory,
            RedirectStandardInput = options.RedirectStandardInput,
            RedirectStandardOutput = options.RedirectStandardOutput,
            RedirectStandardError = options.RedirectStandardError,
            UseShellExecute = false,
        };
        foreach (var pair in options.Environment)
        {
            startInfo.Environment[pair.Key] = pair.Value;
        }

        AddArguments(startInfo, "--control", socketPath);
        foreach (var mount in options.Mounts)
        {
            switch (mount)
            {
                case SandboxMount.ReadWrite readWrite:
                    AddArguments(startInfo, "--rw", readWrite.Path);
                    break;
                case SandboxMount.Gateway gateway:
                    AddArguments(startInfo, "--gateway", gateway.MountPath, gateway.DestinationPath);
                    break;
                case SandboxMount.Overlay overlay:
                    AddArguments(
                        startInfo,
                        "--overlay",
                        overlay.SourcePath,
                        overlay.LowerPath,
                        overlay.UpperPath,
                        overlay.WorkPath);
                    break;
            }
        }
        foreach (var root in approvalRoots)
        {
            AddArguments(startInfo, "--approval", root);
        }
        AddArguments(startInfo, "--chdir", options.WorkingDirectory, "--", options.FileName);
        foreach (var argument in options.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        return startInfo;
    }

    private static void AddArguments(ProcessStartInfo startInfo, params ReadOnlySpan<string> arguments)
    {
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
    }

    public Task WaitForExitAsync(CancellationToken cancellationToken = default) =>
        Process.WaitForExitAsync(cancellationToken);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (!Process.HasExited)
        {
            Process.Kill(entireProcessTree: true);
            Process.WaitForExit();
        }
        Process.Dispose();
        foreach (var mount in _approvalMounts)
        {
            mount.Dispose();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (!Process.HasExited)
        {
            Process.Kill(entireProcessTree: true);
            await Process.WaitForExitAsync().ConfigureAwait(false);
        }
        Process.Dispose();
        foreach (var mount in _approvalMounts)
        {
            mount.Dispose();
        }
    }

    [System.Runtime.InteropServices.LibraryImport("libc", SetLastError = true)]
    private static partial int close(int fileDescriptor);
}
