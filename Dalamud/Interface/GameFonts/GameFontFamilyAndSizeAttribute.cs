using Dalamud.Common;

namespace Dalamud.Interface.GameFonts;

/// <summary>
/// Marks the path for an enum value.
/// </summary>
[AttributeUsage(AttributeTargets.Field)]
internal class GameFontFamilyAndSizeAttribute : Attribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GameFontFamilyAndSizeAttribute"/> class.
    /// </summary>
    /// <param name="path">Inner path of the file.</param>
    /// <param name="texPathFormat">the file path format for the relevant .tex files.</param>
    /// <param name="horizontalOffset">Horizontal offset of the corresponding font.</param>
    // REGION TODO: 自适应的区域字体路径修改
    public GameFontFamilyAndSizeAttribute(string path, string texPathFormat, int horizontalOffset)
    {
        var fontCode = DalamudStartInfo.DefaultLanguage switch
        {
            ClientLanguage.ChineseSimplified  => "chn",
            ClientLanguage.Korean             => "krn",
            ClientLanguage.TraditionalChinese => "tc",
            _                                 => null
        };

        if (fontCode != null)
        {
            (string InputSize, string TargetSize)[] mappings =
            [
                ("12", "12"), 
                ("14", "14"), 
                ("18", "18"), 
                ("36", "36"),
                ("96", "12")
            ];

            foreach (var (input, target) in mappings)
            {
                if (path.Contains($"common/font/AXIS_{input}.fdt"))
                {
                    path          = $"common/font/{fontCode}axis_{target}0.fdt";
                    texPathFormat = $"common/font/font_{fontCode}_{{0}}.tex";
                    break;
                }
            }
        }

        this.Path             = path;
        this.TexPathFormat    = texPathFormat;
        this.HorizontalOffset = horizontalOffset;
    }

    /// <summary>
    /// Gets the path.
    /// </summary>
    public string Path { get; }

    /// <summary>
    /// Gets the file path format for the relevant .tex files.<br />
    /// Used for <see cref="string.Format(string,object?)"/>(<see cref="TexPathFormat"/>, <see cref="int"/>).
    /// </summary>
    public string TexPathFormat { get; }

    /// <summary>
    /// Gets the horizontal offset of the corresponding font.
    /// </summary>
    public int HorizontalOffset { get; }
}
