namespace LimitingFactor.LowLevel;

internal static class MountTable
{
    public static bool HasDescendantMount(string root, IEnumerable<string> mountInfo)
    {
        var normalizedRoot = SandboxPath.Normalize(root);
        foreach (var line in mountInfo)
        {
            var fields = line.Split(' ');
            if (fields.Length < 5)
            {
                continue;
            }

            var mountPoint = SandboxPath.Normalize(Unescape(fields[4]));
            if (!string.Equals(mountPoint, normalizedRoot, StringComparison.Ordinal)
                && SandboxPath.Contains(normalizedRoot, mountPoint))
            {
                return true;
            }
        }

        return false;
    }

    private static string Unescape(string value) =>
        value.Replace("\\040", " ", StringComparison.Ordinal)
            .Replace("\\011", "\t", StringComparison.Ordinal)
            .Replace("\\012", "\n", StringComparison.Ordinal)
            .Replace("\\134", "\\", StringComparison.Ordinal);
}
