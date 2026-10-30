using System.Collections.Generic;
using System.Linq;
using Dalamud.Plugin.Internal.Types.Manifest;

namespace Dalamud.Interface.Internal.Windows.PluginInstaller;

/// <summary>
/// 插件搜索的分词、加权匹配与结果缓存。
/// </summary>
internal sealed class PluginSearchQuery
{
    private readonly string[]                         terms;
    private readonly HashSet<string>                  chineseTerms;
    private readonly Dictionary<IPluginManifest, int> scores = new(ReferenceEqualityComparer.Instance);

    public PluginSearchQuery
    (
        string text
    )
    {
        this.Text = text;
        this.terms =
        [
            .. text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                   .Distinct(StringComparer.OrdinalIgnoreCase)
                   .Where(term => term.Length >= 2 || IsChinese(term))
        ];
        this.chineseTerms = this.terms.Where(IsChinese).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public string Text { get; }

    public int GetScore
    (
        IPluginManifest manifest
    )
    {
        if (this.terms.Length == 0)
            return 0;

        if (this.scores.TryGetValue(manifest, out var cached))
            return cached;

        var score = this.ScoreField(manifest.Name,         200) +
                    this.ScoreField(manifest.InternalName, 180) +
                    this.ScoreField(manifest.Author,       150) +
                    this.ScoreField(manifest.Punchline,    120) +
                    this.ScoreField(manifest.Description,  100);

        if (manifest.Tags != null)
        {
            foreach (var tag in manifest.Tags)
                score += this.ScoreField(tag, 100);
        }

        this.scores.Add(manifest, score);
        return score;
    }

    private static bool IsChinese
    (
        string text
    )
    {
        foreach (var rune in text.EnumerateRunes())
        {
            var value = (uint)rune.Value;
            if (value - 0x4E00u  > 0x9FFFu  - 0x4E00u  &&
                value - 0x3400u  > 0x4DBFu  - 0x3400u  &&
                value - 0x20000u > 0x2FA1Fu - 0x20000u &&
                value - 0x30000u > 0x323AFu - 0x30000u &&
                value - 0xF900u  > 0xFAFFu  - 0xF900u)
                return false;
        }

        return text.Length > 0;
    }

    private int ScoreField
    (
        string? text,
        int     weight
    )
    {
        if (string.IsNullOrWhiteSpace(text))
            return 0;

        var target = text.AsSpan().Trim();
        var score  = 0;

        foreach (var term in this.terms)
        {
            var position = target.IndexOf(term, StringComparison.OrdinalIgnoreCase);
            if (position < 0)
                continue;

            if (target.Equals(term, StringComparison.OrdinalIgnoreCase))
                score += weight * 2;
            else if (position == 0 || char.IsWhiteSpace(target[position - 1]))
                score += weight * 3 / 2;
            else
                score += weight;

            if (this.chineseTerms.Contains(term))
                score += weight * 13 / 10;

            if (term.Length >= 4)
                score += 50;
        }

        return score;
    }
}
