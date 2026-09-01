using System.Collections.Immutable;

namespace LimitingFactor;

/// <summary>Builds a validated sandbox policy without coupling it to a presentation or transport layer.</summary>
public sealed class SandboxBuilder
{
    private readonly List<SandboxGrant> _grants = [];
    private readonly List<string> _approvalRoots = [];
    private string _workingDirectory = SandboxPath.Normalize(Environment.CurrentDirectory);
    private ISandboxAccessApprover? _approver;

    public SandboxBuilder WithWorkingDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _workingDirectory = SandboxPath.Normalize(path);
        return this;
    }

    public SandboxBuilder AddGrant(string path, SandboxAccessMode mode)
    {
        _grants.Add(new SandboxGrant(path, mode));
        return this;
    }

    public SandboxBuilder AddApprovalRoot(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _approvalRoots.Add(SandboxPath.Normalize(path));
        return this;
    }

    public SandboxBuilder UseApprover(ISandboxAccessApprover approver)
    {
        _approver = approver ?? throw new ArgumentNullException(nameof(approver));
        return this;
    }

    public SandboxPolicy Build()
    {
        if (!Directory.Exists(_workingDirectory))
        {
            throw new DirectoryNotFoundException($"Sandbox working directory '{_workingDirectory}' does not exist.");
        }

        var requestedGrants = _grants
            .DistinctBy(static grant => (grant.Path, grant.Mode))
            .ToList();
        var workingDirectoryGrant = requestedGrants
            .Where(grant => SandboxPath.Contains(grant.Path, _workingDirectory))
            .OrderByDescending(static grant => grant.Path.Length)
            .FirstOrDefault();
        if (workingDirectoryGrant?.Mode is not SandboxAccessMode.ReadWrite)
        {
            requestedGrants.Add(new SandboxGrant(_workingDirectory, SandboxAccessMode.ReadWrite));
        }
        var grants = requestedGrants.ToImmutableArray();
        var approvalRoots = _approvalRoots.Distinct(StringComparer.Ordinal).ToImmutableArray();

        var conflictingGrant = grants
            .GroupBy(static grant => grant.Path, StringComparer.Ordinal)
            .FirstOrDefault(static group => group.Select(static grant => grant.Mode).Distinct().Count() > 1);
        if (conflictingGrant is not null)
        {
            throw new InvalidOperationException(
                $"Sandbox grants for the same path '{conflictingGrant.Key}' must use one access mode.");
        }

        foreach (var root in approvalRoots)
        {
            if (!Directory.Exists(root))
            {
                throw new DirectoryNotFoundException($"Sandbox approval root '{root}' does not exist.");
            }

            var overlap = grants.FirstOrDefault(grant => SandboxPath.Overlaps(grant.Path, root));
            if (overlap is not null)
            {
                throw new InvalidOperationException(
                    $"Approval root '{root}' overlaps the {overlap.Mode} grant '{overlap.Path}'. " +
                    "Native and prompted trees must be disjoint so mount order cannot change policy semantics.");
            }

            var overlappingRoot = approvalRoots.FirstOrDefault(other =>
                !string.Equals(other, root, StringComparison.Ordinal)
                && SandboxPath.Overlaps(other, root));
            if (overlappingRoot is not null)
            {
                throw new InvalidOperationException(
                    $"Approval roots '{root}' and '{overlappingRoot}' overlap. " +
                    "Each host path must have exactly one policy FUSE mount.");
            }
        }

        if (approvalRoots.Length > 0 && _approver is null)
        {
            throw new InvalidOperationException("An access approver is required when approval roots are configured.");
        }

        if (grants.Count(static grant => grant.Mode == SandboxAccessMode.CopyOnWrite) > 1)
        {
            throw new NotSupportedException("The first LimitingFactor COW slice supports one COW grant per session.");
        }

        return new SandboxPolicy(_workingDirectory, grants, approvalRoots, _approver);
    }
}

/// <summary>An immutable, validated sandbox launch policy.</summary>
public sealed record SandboxPolicy
{
    internal SandboxPolicy(
        string workingDirectory,
        ImmutableArray<SandboxGrant> grants,
        ImmutableArray<string> approvalRoots,
        ISandboxAccessApprover? approver)
    {
        WorkingDirectory = workingDirectory;
        Grants = grants;
        ApprovalRoots = approvalRoots;
        Approver = approver;
    }

    public string WorkingDirectory { get; }
    public ImmutableArray<SandboxGrant> Grants { get; }
    public ImmutableArray<string> ApprovalRoots { get; }
    internal ISandboxAccessApprover? Approver { get; }
}
