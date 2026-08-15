namespace LimitingFactor;

/// <summary>Identifies the filesystem mutation that crossed an undecided policy boundary.</summary>
public enum SandboxFileOperation
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
