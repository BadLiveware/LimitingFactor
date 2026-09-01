using LimitingFactor.LowLevel;

namespace LimitingFactor.Tests;

public sealed class MountTableTests
{
    [Fact]
    public void Descendant_mounts_are_detected_without_treating_the_root_mount_as_a_child()
    {
        string[] mountInfo =
        [
            "31 22 0:28 / /some/path rw - tmpfs tmpfs rw",
            "32 31 0:29 / /some/path/mounted rw - tmpfs tmpfs rw",
            "33 22 0:30 / /some/path-sibling rw - tmpfs tmpfs rw",
        ];

        Assert.True(MountTable.HasDescendantMount("/some/path", mountInfo));
        Assert.False(MountTable.HasDescendantMount("/some/path/mounted", mountInfo));
        Assert.False(MountTable.HasDescendantMount("/unrelated", mountInfo));
    }

    [Fact]
    public void Escaped_mount_points_are_decoded_before_comparison()
    {
        string[] mountInfo =
        [
            "31 22 0:28 / /some\\040path/mounted rw - tmpfs tmpfs rw",
        ];

        Assert.True(MountTable.HasDescendantMount("/some path", mountInfo));
    }
}
