using System.Diagnostics;

namespace LimitingFactor.LowLevel;

/// <summary>Reports whether local Linux sandbox prerequisites are available.</summary>
public sealed record SandboxRuntimeSupport(bool IsAvailable, string Reason)
{
    public static SandboxRuntimeSupport Get(
        bool requireFuse = true,
        bool requireOverlay = true)
    {
        if (!OperatingSystem.IsLinux())
        {
            return new(false, "LimitingFactor.LowLevel currently supports Linux only.");
        }

        if (requireFuse && !File.Exists("/dev/fuse"))
        {
            return new(false, "FUSE is unavailable because /dev/fuse does not exist.");
        }

        const string UnprivilegedUserNamespaces = "/proc/sys/kernel/unprivileged_userns_clone";
        if (File.Exists(UnprivilegedUserNamespaces)
            && string.Equals(File.ReadAllText(UnprivilegedUserNamespaces).Trim(), "0", StringComparison.Ordinal))
        {
            return new(false, "Unprivileged user namespaces are disabled by kernel.unprivileged_userns_clone.");
        }

        const string UserNamespaceLimit = "/proc/sys/user/max_user_namespaces";
        if (File.Exists(UserNamespaceLimit)
            && long.TryParse(File.ReadAllText(UserNamespaceLimit).Trim(), out var userNamespaceLimit)
            && userNamespaceLimit == 0)
        {
            return new(false, "User namespaces are disabled because user.max_user_namespaces is zero.");
        }

        if (requireOverlay && !File.ReadLines("/proc/filesystems").Any(line =>
            line.Trim().EndsWith("overlay", StringComparison.Ordinal)))
        {
            return new(false, "OverlayFS is unavailable because /proc/filesystems does not list overlay.");
        }

        string helperPath;
        try
        {
            helperPath = LimitingFactor.Native.NativeSandboxHelper.GetPath();
        }
        catch (Exception exception) when (exception is FileNotFoundException or PlatformNotSupportedException)
        {
            return new(false, exception.Message);
        }

        try
        {
            using var probe = Process.Start(new ProcessStartInfo(helperPath, "--probe")
            {
                RedirectStandardError = true,
                UseShellExecute = false,
            });
            if (probe is null)
            {
                return new(false, "The packaged native sandbox helper could not be started.");
            }
            var errorTask = probe.StandardError.ReadToEndAsync();
            if (!probe.WaitForExit(5_000))
            {
                probe.Kill(entireProcessTree: true);
                probe.WaitForExit();
                return new(false, "The packaged native sandbox helper support probe timed out.");
            }
            var error = errorTask.GetAwaiter().GetResult();
            if (probe.ExitCode != 0)
            {
                return new(false,
                    $"The packaged native sandbox helper cannot establish the required user/mount namespaces and mount attributes: {error.Trim()}");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new(false, $"The packaged native sandbox helper support probe failed: {exception.Message}");
        }

        var features = new List<string> { "Linux", "user namespaces", "mount attributes" };
        if (requireFuse)
        {
            features.Add("FUSE");
        }
        if (requireOverlay)
        {
            features.Add("OverlayFS");
        }
        features.Add("the packaged native sandbox helper");
        return new(true, $"{string.Join(", ", features)} are available.");
    }
}
