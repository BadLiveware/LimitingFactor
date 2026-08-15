namespace LimitingFactor.LowLevel;

/// <summary>Identifies a filesystem mutation presented by an approval filesystem.</summary>
public enum SandboxMutationOperation
{
    OpenForWrite,
    CreateFile,
    Truncate,
    CreateDirectory,
    RemoveFile,
    RemoveDirectory,
    Rename,
    CreateHardLink,
    CreateSymbolicLink,
    ChangeMode,
    ChangeOwner,
    ChangeTimes,
    Allocate,
}
