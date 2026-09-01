using LimitingFactor.LowLevel;
using System.Runtime.Versioning;

namespace LimitingFactor.Tests;

[SupportedOSPlatform("linux")]
public sealed class SandboxMountPlanTests
{
    [Fact]
    public void Nested_mounts_are_transformed_to_distinct_captured_sources()
    {
        using var parent = new TemporaryDirectory();
        var readWrite = Directory.CreateDirectory(Path.Combine(parent.Path, "read-write")).FullName;
        var copyOnWrite = Directory.CreateDirectory(Path.Combine(readWrite, "copy-on-write")).FullName;
        var lower = Directory.CreateDirectory(Path.Combine(parent.Path, "lower")).FullName;
        var upper = Directory.CreateDirectory(Path.Combine(parent.Path, "upper")).FullName;
        var work = Directory.CreateDirectory(Path.Combine(parent.Path, "work")).FullName;

        using var plan = new SandboxMountPlan([
            new SandboxMount.ReadWrite(parent.Path),
            new SandboxMount.ReadWrite(readWrite),
            new SandboxMount.Overlay(copyOnWrite, lower, upper, work),
        ]);

        var parentMount = Assert.IsType<SandboxMount.ReadWrite>(plan.Mounts[0]);
        var readWriteMount = Assert.IsType<SandboxMount.CapturedReadWrite>(plan.Mounts[1]);
        var overlayMount = Assert.IsType<SandboxMount.CapturedOverlay>(plan.Mounts[2]);
        Assert.Equal(parent.Path, parentMount.Path);
        Assert.NotEqual(readWrite, readWriteMount.BackingPath);
        Assert.NotEqual(copyOnWrite, overlayMount.BackingPath);
        Assert.True(Directory.Exists(readWriteMount.BackingPath));
        Assert.True(Directory.Exists(overlayMount.BackingPath));
    }

    [Fact]
    public void Duplicate_nested_mounts_share_one_captured_source()
    {
        using var parent = new TemporaryDirectory();
        var child = Directory.CreateDirectory(Path.Combine(parent.Path, "child")).FullName;

        using var plan = new SandboxMountPlan([
            new SandboxMount.ReadWrite(parent.Path),
            new SandboxMount.ReadWrite(child),
            new SandboxMount.ReadWrite(child),
        ]);

        var captured = plan.Mounts.OfType<SandboxMount.CapturedReadWrite>().ToArray();
        Assert.Equal(2, captured.Length);
        Assert.Equal(captured[0].BackingPath, captured[1].BackingPath);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"limiting-factor-mount-plan-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
