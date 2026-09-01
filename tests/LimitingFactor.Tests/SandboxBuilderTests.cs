using LimitingFactor.LowLevel;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace LimitingFactor.Tests;

[SupportedOSPlatform("linux")]
public sealed class SandboxBuilderTests
{
    [Fact]
    public void Build_adds_the_working_directory_as_a_direct_read_write_grant()
    {
        using var directory = new TemporaryDirectory();

        var policy = new SandboxBuilder()
            .WithWorkingDirectory(directory.Path)
            .Build();

        var grant = Assert.Single(policy.Grants);
        Assert.Equal(directory.Path, grant.Path);
        Assert.Equal(SandboxAccessMode.ReadWrite, grant.Mode);
    }

    [Fact]
    public void Build_uses_an_explicit_read_write_parent_as_the_working_directory_grant()
    {
        using var parent = new TemporaryDirectory();
        var working = Directory.CreateDirectory(Path.Combine(parent.Path, "workspace")).FullName;

        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .Build();

        var grant = Assert.Single(policy.Grants);
        Assert.Equal(parent.Path, grant.Path);
        Assert.Equal(SandboxAccessMode.ReadWrite, grant.Mode);
    }

    [Fact]
    public async Task Read_write_parent_covers_the_working_directory_and_siblings()
    {
        var support = SandboxSupport.Get(requireFuse: false, requireOverlay: false);
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var parent = new TemporaryDirectory();
        var working = Directory.CreateDirectory(Path.Combine(parent.Path, "workspace")).FullName;
        var sibling = Directory.CreateDirectory(Path.Combine(parent.Path, "sibling")).FullName;
        var workingOutput = Path.Combine(working, "working.txt");
        var siblingOutput = Path.Combine(sibling, "sibling.txt");
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .Build();
        var command = new ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf working > {QuoteShell(workingOutput)} && printf sibling > {QuoteShell(siblingOutput)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, session.Process.ExitCode);
        Assert.Equal("working", await File.ReadAllTextAsync(workingOutput, TestContext.Current.CancellationToken));
        Assert.Equal("sibling", await File.ReadAllTextAsync(siblingOutput, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Approval_roots_require_an_approver()
    {
        using var working = new TemporaryDirectory();
        using var approval = new TemporaryDirectory();

        Assert.Throws<InvalidOperationException>(() => new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddApprovalRoot(approval.Path)
            .Build());
    }

    [Fact]
    public void Approval_roots_cannot_be_hidden_by_native_grants()
    {
        using var working = new TemporaryDirectory();
        var child = Directory.CreateDirectory(Path.Combine(working.Path, "child")).FullName;

        var exception = Assert.Throws<InvalidOperationException>(() => new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddApprovalRoot(child)
            .UseApprover(new DenyingApprover())
            .Build());

        Assert.Contains("overlap", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Native_grants_cannot_be_nested_beneath_an_approval_root()
    {
        using var working = new TemporaryDirectory();
        using var approval = new TemporaryDirectory();
        var nativeChild = Directory.CreateDirectory(Path.Combine(approval.Path, "native")).FullName;

        var exception = Assert.Throws<InvalidOperationException>(() => new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddApprovalRoot(approval.Path)
            .AddGrant(nativeChild, SandboxAccessMode.ReadWrite)
            .UseApprover(new DenyingApprover())
            .Build());

        Assert.Contains("overlap", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Native_grants_allow_nested_modes_and_keep_the_most_specific_grant()
    {
        using var parent = new TemporaryDirectory();
        var working = Directory.CreateDirectory(Path.Combine(parent.Path, "workspace")).FullName;
        var nested = Directory.CreateDirectory(Path.Combine(parent.Path, "nested")).FullName;

        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .AddGrant(nested, SandboxAccessMode.CopyOnWrite)
            .Build();

        Assert.Contains(policy.Grants, grant =>
            grant.Path == parent.Path && grant.Mode == SandboxAccessMode.ReadWrite);
        Assert.Contains(policy.Grants, grant =>
            grant.Path == nested && grant.Mode == SandboxAccessMode.CopyOnWrite);
    }

    [Fact]
    public void Build_preserves_a_writable_working_directory_below_a_more_specific_read_only_parent()
    {
        using var parent = new TemporaryDirectory();
        var readOnly = Directory.CreateDirectory(Path.Combine(parent.Path, "read-only")).FullName;
        var working = Directory.CreateDirectory(Path.Combine(readOnly, "workspace")).FullName;

        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .AddGrant(readOnly, SandboxAccessMode.ReadOnly)
            .Build();

        Assert.Contains(policy.Grants, grant =>
            grant.Path == working && grant.Mode == SandboxAccessMode.ReadWrite);
    }

    [Fact]
    public void Native_grants_allow_a_read_only_child_to_override_a_read_write_parent()
    {
        using var parent = new TemporaryDirectory();
        var working = Directory.CreateDirectory(Path.Combine(parent.Path, "workspace")).FullName;
        var readOnly = Directory.CreateDirectory(Path.Combine(parent.Path, "read-only")).FullName;

        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .AddGrant(readOnly, SandboxAccessMode.ReadOnly)
            .Build();

        Assert.Contains(policy.Grants, grant =>
            grant.Path == readOnly && grant.Mode == SandboxAccessMode.ReadOnly);
    }

    [Fact]
    public void Native_grants_reject_undefined_access_modes()
    {
        using var working = new TemporaryDirectory();
        using var external = new TemporaryDirectory();

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(external.Path, (SandboxAccessMode)999));

        Assert.Equal("mode", exception.ParamName);
    }

    [Fact]
    public void Native_grants_reject_different_modes_for_the_exact_same_path()
    {
        using var working = new TemporaryDirectory();
        using var external = new TemporaryDirectory();

        var exception = Assert.Throws<InvalidOperationException>(() => new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(external.Path, SandboxAccessMode.ReadWrite)
            .AddGrant(external.Path, SandboxAccessMode.CopyOnWrite)
            .Build());

        Assert.Contains("same path", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Most_specific_nested_read_only_grant_overrides_a_read_write_parent()
    {
        var support = SandboxSupport.Get(requireFuse: false, requireOverlay: false);
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var parent = new TemporaryDirectory();
        var working = Directory.CreateDirectory(Path.Combine(parent.Path, "workspace")).FullName;
        var readOnly = Directory.CreateDirectory(Path.Combine(parent.Path, "read-only")).FullName;
        var writableOutput = Path.Combine(parent.Path, "writable.txt");
        var blockedOutput = Path.Combine(readOnly, "blocked.txt");
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .AddGrant(readOnly, SandboxAccessMode.ReadOnly)
            .Build();
        var command = new ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add(
            $"printf writable > {QuoteShell(writableOutput)} && ! printf blocked > {QuoteShell(blockedOutput)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, session.Process.ExitCode);
        Assert.Equal("writable", await File.ReadAllTextAsync(writableOutput, TestContext.Current.CancellationToken));
        Assert.False(File.Exists(blockedOutput));
    }

    [Fact]
    public async Task Nested_grant_capture_state_is_not_writable_from_the_sandbox()
    {
        var support = SandboxSupport.Get(requireFuse: false, requireOverlay: false);
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var parent = new TemporaryDirectory();
        var working = Directory.CreateDirectory(Path.Combine(parent.Path, "workspace")).FullName;
        var readOnly = Directory.CreateDirectory(Path.Combine(parent.Path, "read-only")).FullName;
        var marker = Path.Combine(readOnly, "marker.txt");
        await File.WriteAllTextAsync(marker, "host", TestContext.Current.CancellationToken);
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .AddGrant(readOnly, SandboxAccessMode.ReadOnly)
            .Build();
        var command = new ProcessStartInfo("sh")
        {
            RedirectStandardOutput = true,
        };
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add(
            "root=$(find \"${TMPDIR:-/tmp}\" -maxdepth 1 -type d -name 'limiting-factor-mounts-*' -print -quit); " +
            "test -n \"$root\"; " +
            "printf '%s' \"$root\"; " +
            "for path in \"$root\"/*; do " +
            "if [ -f \"$path/marker.txt\" ]; then printf bypass > \"$path/marker.txt\"; fi; done");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        var discoveredStateRoot = session.Process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, session.Process.ExitCode);
        Assert.Contains("limiting-factor-mounts-", await discoveredStateRoot, StringComparison.Ordinal);
        Assert.Equal("host", await File.ReadAllTextAsync(marker, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Most_specific_nested_copy_on_write_overrides_read_write_parents()
    {
        var support = SandboxSupport.Get(requireFuse: false, requireOverlay: true);
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var parent = new TemporaryDirectory();
        var working = Directory.CreateDirectory(Path.Combine(parent.Path, "workspace")).FullName;
        var deeper = Directory.CreateDirectory(Path.Combine(parent.Path, "deeper")).FullName;
        var copyOnWrite = Directory.CreateDirectory(Path.Combine(deeper, "copy-on-write")).FullName;
        var directOutput = Path.Combine(deeper, "direct.txt");
        var stagedOutput = Path.Combine(copyOnWrite, "staged.txt");
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working)
            .AddGrant(parent.Path, SandboxAccessMode.ReadWrite)
            .AddGrant(deeper, SandboxAccessMode.ReadWrite)
            .AddGrant(copyOnWrite, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf direct > {QuoteShell(directOutput)} && printf staged > {QuoteShell(stagedOutput)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, session.Process.ExitCode);
        Assert.Equal("direct", await File.ReadAllTextAsync(directOutput, TestContext.Current.CancellationToken));
        Assert.False(File.Exists(stagedOutput));
        var change = Assert.Single(session.GetChanges());
        Assert.Equal(SandboxChangeKind.Created, change.Kind);
        Assert.Equal(stagedOutput, change.Path);
    }

    [Fact]
    public void Approval_roots_cannot_overlap_each_other()
    {
        using var working = new TemporaryDirectory();
        using var approval = new TemporaryDirectory();
        var nested = Directory.CreateDirectory(Path.Combine(approval.Path, "nested")).FullName;

        var exception = Assert.Throws<InvalidOperationException>(() => new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddApprovalRoot(approval.Path)
            .AddApprovalRoot(nested)
            .UseApprover(new DenyingApprover())
            .Build());

        Assert.Contains("overlap", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Sandbox_keeps_standard_devices_but_cannot_mount_host_paths()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var victim = new TemporaryDirectory();
        var mountPoint = Directory.CreateDirectory(Path.Combine(working.Path, "mount")).FullName;
        var escaped = Path.Combine(victim.Path, "escaped");
        var policy = new SandboxBuilder().WithWorkingDirectory(working.Path).Build();
        var command = new ProcessStartInfo("sh") { RedirectStandardError = true };
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add(
            $"cat /dev/null && ! mount --bind {QuoteShell(victim.Path)} {QuoteShell(mountPoint)} && " +
            $"test ! -e {QuoteShell(escaped)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        var error = session.Process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.True(session.Process.ExitCode == 0, await error);
        Assert.False(File.Exists(escaped));
    }

    [Fact]
    public void Support_can_check_only_the_features_required_by_a_policy()
    {
        var directOnly = SandboxSupport.Get(requireFuse: false, requireOverlay: false);
        var full = SandboxSupport.Get();

        Assert.Contains("mount attributes", directOnly.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("FUSE", directOnly.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("OverlayFS", directOnly.Reason, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(full.IsAvailable, SandboxSupport.Get().IsAvailable);
    }

    [Fact]
    public async Task Command_exit_terminates_daemonized_descendants()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        var policy = new SandboxBuilder().WithWorkingDirectory(working.Path).Build();
        var command = new ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add("sleep 30 & exit 7");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken)
            .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);

        Assert.Equal(7, session.Process.ExitCode);
    }

    [Fact]
    public void Copy_on_write_state_is_outside_the_source_and_supports_read_only_sources()
    {
        using var source = new TemporaryDirectory();
        var originalMode = File.GetUnixFileMode(source.Path);
        File.SetUnixFileMode(source.Path, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            using var overlay = new CopyOnWriteOverlay(source.Path);

            Assert.NotEqual(source.Path, Path.GetDirectoryName(overlay.LowerRoot));
            Assert.Empty(Directory.EnumerateFileSystemEntries(source.Path));
        }
        finally
        {
            File.SetUnixFileMode(source.Path, originalMode);
        }
    }

    [Fact]
    public async Task Arbitrary_descendant_write_is_approved_transparently()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var approval = new TemporaryDirectory();
        var target = Path.Combine(approval.Path, "target.txt");
        await File.WriteAllTextAsync(target, "before", TestContext.Current.CancellationToken);
        var approver = new RecordingApprover(request =>
            SandboxAccessDecision.AllowReadWrite(request.ApprovalRoot));
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddApprovalRoot(approval.Path)
            .UseApprover(approver)
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("sh")
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add(
            $"python -c 'from pathlib import Path; Path({QuotePython(target)}).write_text(\"after\")'");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        var standardOutput = session.Process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
        var standardError = session.Process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.True(
            session.Process.ExitCode == 0,
            $"stdout: {await standardOutput}\nstderr: {await standardError}");
        Assert.Equal("after", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
        var request = Assert.Single(approver.Requests);
        Assert.Equal(target, request.Path);
        Assert.Equal(SandboxFileOperation.Truncate, request.Operation);
    }

    [Fact]
    public async Task Async_approvers_can_wait_for_an_external_decision_without_deadlocking()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var approval = new TemporaryDirectory();
        var target = Path.Combine(approval.Path, "target.txt");
        await File.WriteAllTextAsync(target, "before", TestContext.Current.CancellationToken);
        var approver = new DeferredApprover();
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddApprovalRoot(approval.Path)
            .UseApprover(approver)
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf after > {QuoteShell(target)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        var request = await approver.Requested.Task.WaitAsync(
            TimeSpan.FromSeconds(5),
            TestContext.Current.CancellationToken);
        Assert.Equal(target, request.Path);
        Assert.Equal("before", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));

        approver.Complete(SandboxAccessDecision.AllowReadWrite(request.ApprovalRoot));
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, session.Process.ExitCode);
        Assert.Equal("after", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Copy_on_write_stages_changes_without_mutating_the_host_and_can_apply_them()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        var target = Path.Combine(cow.Path, "target.txt");
        var created = Path.Combine(cow.Path, "created.txt");
        await File.WriteAllTextAsync(target, "before", TestContext.Current.CancellationToken);
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add(
            $"printf after > {QuoteShell(target)} && printf created > {QuoteShell(created)} && " +
            $"test \"$(cat {QuoteShell(target)})\" = after");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, session.Process.ExitCode);
        Assert.Equal("before", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
        Assert.False(File.Exists(created));
        Assert.Collection(
            session.GetChanges().OrderBy(static change => change.Path),
            change =>
            {
                Assert.Equal(SandboxChangeKind.Created, change.Kind);
                Assert.Equal(created, change.Path);
            },
            change =>
            {
                Assert.Equal(SandboxChangeKind.Modified, change.Kind);
                Assert.Equal(target, change.Path);
            });

        session.ApplyChanges();

        Assert.Equal("after", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
        Assert.Equal("created", await File.ReadAllTextAsync(created, TestContext.Current.CancellationToken));
        Assert.Empty(session.GetChanges());
    }

    [Fact]
    public async Task Copy_on_write_replaces_opaque_directories_when_applied()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        var directory = Directory.CreateDirectory(Path.Combine(cow.Path, "directory")).FullName;
        var oldFile = Path.Combine(directory, "old.txt");
        var newFile = Path.Combine(directory, "new.txt");
        await File.WriteAllTextAsync(oldFile, "old", TestContext.Current.CancellationToken);
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add(
            $"rm -rf {QuoteShell(directory)} && mkdir {QuoteShell(directory)} && printf new > {QuoteShell(newFile)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);
        session.ApplyChanges();

        Assert.False(File.Exists(oldFile));
        Assert.Equal("new", await File.ReadAllTextAsync(newFile, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Copy_on_write_rejects_replaced_directory_ancestors()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        using var outside = new TemporaryDirectory();
        var directory = Directory.CreateDirectory(Path.Combine(cow.Path, "directory")).FullName;
        var staged = Path.Combine(directory, "staged.txt");
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf staged > {QuoteShell(staged)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);
        Directory.Delete(directory, recursive: true);
        Directory.CreateSymbolicLink(directory, outside.Path);

        var exception = Assert.Throws<InvalidOperationException>(session.ApplyChanges);
        Assert.Contains("host source changed", exception.Message, StringComparison.Ordinal);
        Assert.False(File.Exists(Path.Combine(outside.Path, "staged.txt")));
    }

    [Fact]
    public async Task Copy_on_write_rejects_apply_when_the_source_root_is_replaced()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        using var outside = new TemporaryDirectory();
        var staged = Path.Combine(cow.Path, "staged.txt");
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf staged > {QuoteShell(staged)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);
        var moved = cow.Path + "-moved";
        Directory.Move(cow.Path, moved);
        Directory.CreateSymbolicLink(cow.Path, outside.Path);
        try
        {
            var exception = Assert.Throws<InvalidOperationException>(session.ApplyChanges);
            Assert.Contains("host source changed", exception.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(outside.Path, "staged.txt")));
        }
        finally
        {
            Directory.Delete(cow.Path);
            Directory.Move(moved, cow.Path);
        }
    }

    [Fact]
    public async Task Copy_on_write_rejects_apply_when_the_host_creates_a_staged_destination()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        var target = Path.Combine(cow.Path, "created.txt");
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf staged > {QuoteShell(target)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(target, "host-created", TestContext.Current.CancellationToken);

        var exception = Assert.Throws<InvalidOperationException>(session.ApplyChanges);
        Assert.Contains("host created", exception.Message, StringComparison.Ordinal);
        Assert.Equal("host-created", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Copy_on_write_stages_deletions_and_applies_them_explicitly()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        var target = Path.Combine(cow.Path, "target.txt");
        await File.WriteAllTextAsync(target, "before", TestContext.Current.CancellationToken);
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("rm");
        command.ArgumentList.Add(target);

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, session.Process.ExitCode);
        Assert.True(File.Exists(target));
        var change = Assert.Single(session.GetChanges());
        Assert.Equal(SandboxChangeKind.Deleted, change.Kind);
        Assert.Equal(target, change.Path);

        session.ApplyChanges();

        Assert.False(File.Exists(target));
    }

    [Fact]
    public async Task Copy_on_write_rejects_apply_when_the_host_source_changed()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        var target = Path.Combine(cow.Path, "target.txt");
        await File.WriteAllTextAsync(target, "before", TestContext.Current.CancellationToken);
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf staged > {QuoteShell(target)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);
        await File.WriteAllTextAsync(target, "host-change", TestContext.Current.CancellationToken);

        var exception = Assert.Throws<InvalidOperationException>(session.ApplyChanges);
        Assert.Contains("host source changed", exception.Message, StringComparison.Ordinal);
        Assert.Equal("host-change", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Copy_on_write_changes_can_be_discarded()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var cow = new TemporaryDirectory();
        var target = Path.Combine(cow.Path, "target.txt");
        await File.WriteAllTextAsync(target, "before", TestContext.Current.CancellationToken);
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddGrant(cow.Path, SandboxAccessMode.CopyOnWrite)
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("sh");
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf after > {QuoteShell(target)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);
        session.DiscardChanges();

        Assert.Equal("before", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
        Assert.Empty(session.GetChanges());
    }

    [Fact]
    public async Task Denied_descendant_write_returns_a_permission_error_without_host_changes()
    {
        var support = SandboxSupport.Get();
        if (!support.IsAvailable)
        {
            Assert.Skip(support.Reason);
        }

        using var working = new TemporaryDirectory();
        using var approval = new TemporaryDirectory();
        var target = Path.Combine(approval.Path, "target.txt");
        await File.WriteAllTextAsync(target, "before", TestContext.Current.CancellationToken);
        var policy = new SandboxBuilder()
            .WithWorkingDirectory(working.Path)
            .AddApprovalRoot(approval.Path)
            .UseApprover(new DenyingApprover())
            .Build();
        var command = new System.Diagnostics.ProcessStartInfo("sh")
        {
            RedirectStandardError = true,
        };
        command.ArgumentList.Add("-c");
        command.ArgumentList.Add($"printf after > {QuoteShell(target)}");

        await using var session = await Sandbox.StartAsync(
            policy,
            command,
            TestContext.Current.CancellationToken);
        var error = session.Process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
        await session.WaitForExitAsync(TestContext.Current.CancellationToken);

        Assert.NotEqual(0, session.Process.ExitCode);
        Assert.Contains("Permission denied", await error, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("before", await File.ReadAllTextAsync(target, TestContext.Current.CancellationToken));
    }

    private static string QuotePython(string value) =>
        $"{System.Text.Json.JsonSerializer.Serialize(value)}";

    private static string QuoteShell(string value) =>
        "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";

    private sealed class DenyingApprover : ISandboxAccessApprover
    {
        public ValueTask<SandboxAccessDecision> ApproveAsync(
            SandboxAccessRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(SandboxAccessDecision.Deny);
    }

    private sealed class DeferredApprover : ISandboxAccessApprover
    {
        private readonly TaskCompletionSource<SandboxAccessDecision> _decision =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<SandboxAccessRequest> Requested { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<SandboxAccessDecision> ApproveAsync(
            SandboxAccessRequest request,
            CancellationToken cancellationToken)
        {
            Requested.TrySetResult(request);
            return await _decision.Task.WaitAsync(cancellationToken);
        }

        public void Complete(SandboxAccessDecision decision) => _decision.TrySetResult(decision);
    }

    private sealed class RecordingApprover(
        Func<SandboxAccessRequest, SandboxAccessDecision> decision) : ISandboxAccessApprover
    {
        public List<SandboxAccessRequest> Requests { get; } = [];

        public ValueTask<SandboxAccessDecision> ApproveAsync(
            SandboxAccessRequest request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            return ValueTask.FromResult(decision(request));
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"limiting-factor-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
