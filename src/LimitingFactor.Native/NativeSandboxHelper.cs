using System.Runtime.InteropServices;

namespace LimitingFactor.Native;

/// <summary>Locates the RID-specific native sandbox setup helper packaged with this assembly.</summary>
public static class NativeSandboxHelper
{
    public static string GetPath()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("LimitingFactor.Native supports Linux only.");
        }

        if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
        {
            throw new PlatformNotSupportedException(
                $"LimitingFactor.Native currently supports x64, not '{RuntimeInformation.ProcessArchitecture}'.");
        }

        const string rid = "linux-x64";
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "runtimes", rid, "native", "limiting-factor-helper"),
            Path.Combine(Path.GetDirectoryName(typeof(NativeSandboxHelper).Assembly.Location)!, "runtimes", rid, "native", "limiting-factor-helper"),
        };

        return candidates.FirstOrDefault(File.Exists)
            ?? throw new FileNotFoundException(
                $"The packaged Limiting Factor sandbox helper was not found. Searched: {string.Join(", ", candidates)}");
    }
}
