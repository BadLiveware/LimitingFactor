namespace LimitingFactor;

internal static class SandboxPath
{
    public static string Normalize(string path)
    {
        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        return normalized.Length == 0 ? Path.DirectorySeparatorChar.ToString() : normalized;
    }

    public static bool Contains(string root, string path)
    {
        if (string.Equals(root, path, StringComparison.Ordinal))
        {
            return true;
        }

        if (root == Path.DirectorySeparatorChar.ToString())
        {
            return path.StartsWith(root, StringComparison.Ordinal);
        }

        return path.Length > root.Length
            && path.StartsWith(root, StringComparison.Ordinal)
            && path[root.Length] == Path.DirectorySeparatorChar;
    }

    public static bool Overlaps(string first, string second) =>
        Contains(first, second) || Contains(second, first);
}
