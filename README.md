# Limiting Factor

Linux process sandboxing for .NET applications, developer tools, and local agents.

Limiting Factor starts an arbitrary process tree with the host filesystem read-only by default. A host application can grant selected paths direct read-write access, stage writes with copy-on-write, or asynchronously decide mutations beneath approval roots. The library is presentation- and transport-agnostic: approval decisions may come from a terminal, desktop UI, webpage, policy engine, RPC service, or another host-controlled workflow.

## Packages

| Package | Purpose |
| --- | --- |
| `LimitingFactor` | Validated policies, approval requests, process sessions, and COW apply/discard |
| `LimitingFactor.LowLevel` | Explicit namespace, mount, FUSE, process, descriptor, and OverlayFS lifetimes |
| `LimitingFactor.Native` | RID-specific native setup helper built from project-owned C source |

Most applications should reference only `LimitingFactor`. The runtime invokes the native helper directly without a command shell and does not require `bwrap` or `fusermount3`.

## Requirements

- x86-64 Linux
- .NET 10
- unprivileged user namespaces
- recursive mount attributes (`mount_setattr`)
- `/dev/fuse` and libfuse3 for approval roots
- OverlayFS for copy-on-write grants
- a C17 compiler when building `LimitingFactor.Native` from source

Check the complete feature set:

```csharp
var support = LimitingFactor.SandboxSupport.Get();
if (!support.IsAvailable)
{
    throw new PlatformNotSupportedException(support.Reason);
}
```

A direct-RW-only host can request a narrower diagnostic:

```csharp
var support = LimitingFactor.SandboxSupport.Get(
    requireFuse: false,
    requireOverlay: false);
```

## Run a sandboxed tool

```csharp
using System.Diagnostics;
using LimitingFactor;

var policy = new SandboxBuilder()
    .WithWorkingDirectory(Environment.CurrentDirectory)
    .Build();

var command = new ProcessStartInfo("git")
{
    RedirectStandardOutput = true,
    RedirectStandardError = true,
};
command.ArgumentList.Add("status");
command.ArgumentList.Add("--short");

await using var session = await Sandbox.StartAsync(policy, command, cancellationToken);

var stdout = session.Process.StandardOutput.ReadToEndAsync(cancellationToken);
var stderr = session.Process.StandardError.ReadToEndAsync(cancellationToken);
await session.WaitForExitAsync(cancellationToken);

Console.Write(await stdout);
Console.Error.Write(await stderr);
```

The working directory is automatically a direct read-write grant. All other visible host paths remain read-only unless the policy grants another mode. Use `ProcessStartInfo.ArgumentList`; `Sandbox.StartAsync` rejects the ambiguous `Arguments` string.

## Asynchronous approvals

An approval root presents the host tree through a FUSE gateway. The first undecided mutation remains blocked while the host resolves `ISandboxAccessApprover.ApproveAsync`:

```csharp
var externalProject = Path.GetFullPath("../external-project");
var policy = new SandboxBuilder()
    .WithWorkingDirectory(Environment.CurrentDirectory)
    .AddApprovalRoot(externalProject)
    .UseApprover(new HostApprover())
    .Build();

sealed class HostApprover : ISandboxAccessApprover
{
    public async ValueTask<SandboxAccessDecision> ApproveAsync(
        SandboxAccessRequest request,
        CancellationToken cancellationToken)
    {
        var allowed = await RequestDecisionAsync(request, cancellationToken);
        return allowed
            ? SandboxAccessDecision.AllowReadWrite(request.ApprovalRoot)
            : SandboxAccessDecision.Deny;
    }
}
```

The approver executes in the trusted host, outside the sandbox. Limiting Factor defines the request and asynchronous decision contract but does not depend on a UI framework, network protocol, or interaction model.

## Copy-on-write

Use a disjoint scratch working directory when the main project should be COW, because the working directory itself is direct RW:

```csharp
var policy = new SandboxBuilder()
    .WithWorkingDirectory(scratchDirectory)
    .AddGrant(projectDirectory, SandboxAccessMode.CopyOnWrite)
    .Build();

await using var session = await Sandbox.StartAsync(policy, command, cancellationToken);
await session.WaitForExitAsync(cancellationToken);

foreach (var change in session.GetChanges())
{
    Console.WriteLine($"{change.Kind}: {change.Path}");
}

if (acceptChanges)
{
    session.ApplyChanges();
}
else
{
    session.DiscardChanges();
}
```

The host source remains unchanged until `ApplyChanges`. Apply checks source identity and content conflicts before replaying staged regular files, directories, whiteouts, and opaque-directory replacement. Apply/discard is valid only after the process exits.

## Policy constraints

- Native grants and approval roots must be disjoint.
- Native grants with overlapping path trees are rejected.
- The current implementation supports one COW grant per session.
- Approval roots do not yet support rename, links, symlinks, arbitrary ioctls, or full xattr/ACL/locking fidelity.
- COW apply rejects staged special files and symlinks.
- COW change reporting represents renames as OverlayFS entry changes rather than a rename event.
- External daemons such as Docker do not inherit this process boundary.

## Publishing

NuGet.org publishing uses GitHub Actions trusted publishing, so the repository stores no long-lived API key. The `badliveware` NuGet.org account trusts `BadLiveware/LimitingFactor` and the workflow file `publish.yml`.

To release all three packages with one version:

1. Create a GitHub release whose tag is `v<semver>`, such as `v0.1.0` or `v0.2.0-beta.1`.
2. `.github/workflows/publish.yml` restores and tests the solution, packs `LimitingFactor`, `LimitingFactor.LowLevel`, and `LimitingFactor.Native` with the tag-derived version, then authenticates to NuGet.org through OIDC.
3. The workflow uploads the `.nupkg` files as a workflow artifact and publishes them to `https://api.nuget.org/v3/index.json`.

The release fails before publishing when its tag is not a `v`-prefixed semantic version. Package IDs and versions are immutable once accepted by NuGet.org; publish corrections with a new version.

## Security boundary

The helper establishes user, mount, IPC, UTS, and PID namespaces; makes inherited host mounts read-only and non-device-capable; creates a minimal private `/dev`; drops target capabilities; and installs a seccomp filter that blocks mount, namespace, ptrace, and `io_uring` setup escape surfaces. Direct-RW grants remain genuine host writes and should be scoped narrowly.

Limiting Factor is intended to constrain local tools and process trees. It is not presented as a hostile multi-tenant container runtime.
