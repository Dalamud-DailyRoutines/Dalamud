using System.Collections.Generic;
using System.Numerics;

using Dalamud.Bindings.ImGui;
using Dalamud.Interface.Colors;
using Dalamud.Interface.Windowing;

using Newtonsoft.Json;

namespace Dalamud.Interface.Style;

/// <summary>
/// Version one of the Dalamud style model.
/// </summary>
public class StyleModelV1 : StyleModel
{
    /// <summary>
    /// Initializes a new instance of the <see cref="StyleModelV1"/> class.
    /// </summary>
    private StyleModelV1()
    {
        this.Colors = [];
        this.Name = "Unknown";
    }

    /// <summary>
    /// Gets the standard Dalamud look.
    /// </summary>
    public static StyleModel DalamudStandard { get; } = Deserialize(
        "DS1H4sIAAAAAAAACpWYTXPiOBCG/8qWz6mUvizL3CbD7uQw2UpN2JrdvQmjgAdjM8aQj6n895GwWpaxIcoJI/qRul+12i1+RTKa4Gt0Fc2jya/oX/2FmG//6Qd0jd6uogyGFtEEmU9lDdF1fLTTn9rsUZtdRUswXlnjHAbk3I78gHWQXYcfl1nrkaMfhbXbWDvRMyvH6WrUeAvGENFx9Gc0IUe61iPcPOxgvgYe9vBwiCbUfD5BHM/WvZdRFV7dKPJGpbTDvOeezCwuFx1GUSoQTbHFEccpR4mgV9H/5jvGOCYp0z9/P/4sKE1TIcxs3b4gRmlCYnAMCZ6wGMMMTCQoFsLNgPX0jJoZHgfeIwshsDYJURXGbqaeG2efMguk4khgS7SKG9NpvpPzQnWRckskdolEeMT3vFxUTzfLzqGYCSqQSCyFCWKMcYD1N46R8cJN8XmVFwt/hiRNiCCwLOYMEw6ykoTzOEHMhsk0f19t99seDyQDCMxTo/9NVS9UHaRga/qwkjrGIOCvWm6U5wtGbVZAMMQylOCYC+7LYNHb6qBqT31MLMogGs4hmo76lDX5QQ2hBBZMARImz2d5U6jepoFkkHv+HlvrkzXOytyDPldFIbc7L6B3uDtV7m9k7TvnMgGCIZ79Q1brJeZ9grkD5c7SGPKllvOhZibzjtBZ5uwexXBE+Dk0dKPgaKhsfSfrtQNAvNRp0ROjyHW+joc1TIU07iE917BL84SNaXizb5qqHBhzWATqXkqccV+1jhFkLOla5oxPjPeWaYlbJXvnWrgCAlL5B6e1Dt1JPRA7KPywcSOw2spaNlXnGTsVSxBrj337s74N1yE+F7iPRg+NfVO7/FV9qfNtgAiE9IgPeMj65AckNODMS+jL5WAWfjrtns4Gh7LLHCgftL/CP+Vjle17Re1yAfWQj1XRaZWt83J5X6tDrp5C9KId9edm27wEV/n7omq+5qXahRYnB3zsYBvsNt811VK/ugIKSHzKnFtutCjMTC/THtuQFsGD7Lu/qatyGXJ0eR/8mi9XTQCHBHDf+n3UhS6jM/9UNCF9DxG2uXtQhcoa5bdbl8qKaa+mtVxO62o7k/VSNe9ucltd/5aHWy1A4YlwCYlbpG0mdeaespe9FCf0NN8ECElNYbmrFrJowTAqJm/mcqObrmgSzbQseSaLPx5kmTV7Wb9E+vbVdt1yEDZxPbBfTrrCxsmlRjvrcsndY1xH6FfArigRqGPUdTSxZ6gCLwXdZcO1seloQVi+d5pbs1VogckDu54fgVKvh5nIR14hRbcj9LS0pL6Am8CtKwPjqEKF2YZ6+DNsR+qhgPCujP3pdkMBIQWpb9eEBrLvcvU0pxMUe3e8Q6CE3SuSpRCxc5H6Mz6HSdP9e8DhkJiZ7V3Un/A1MAvdfwzelBSD3tS/2bqu5x0nZRbopVHStMjo7TcBWyY7TxIAAA==")!;

    /// <summary>
    /// Gets the standard Dalamud look.
    /// </summary>
    public static StyleModel DalamudClassic { get; } = Deserialize(
        "DS1H4sIAAAAAAAACqWYS3PiOBCA/0rKZ3ZKlmRL5jZJdieHyVYqydZs5iZAAQ8OZowhj6n899HbkgW74OQQCtH9uR/qVsu/EpaM009glEyS8a/k32RM5ZcH9fk+SqbJOJcLs2QM5Cc3UsBIgU+ZkHoUjFEyN7ILQyyTMZafbGLkfxjl3Chj9YilEauM1JORwkYqU1Kr3qrWrXurUK2u98r+FD8ruxphnzJhY7xtxYJ69Nbo7BRplDyb7y/GtFfnfeZ5/xbFJJXLjJl1ZNaRMoNNjT6bdXoE0iID2KgDSjDBIMtHyXeFgykuUoJGyTf9M0JFQamEdflIAQQZArk1weloBAGAUowdIgWEYiQRj5H5wCgBKy03Ql1JuXv+0jr5AqcpyW0oiiynOSSZUS7UN5wpRqoYUvmy3LBJxTvfcVrkwhZLwdKsFBFDyXABhADyKN/K1ax+Pp97nmuEc10YhQlw0dOG5B7iYlFWM58AU2k8sgCcgYIC6wn0NG/q9XbtazrRh/BZWlMGQPzuAc7rZsYbp99JKH2Yqz9q9JGj9/TvFkzEoEucEkOFdQCoyKc2jS5PjvJXw56474aNmLZCoEREbA4gARmlcI/+Vb3jjZdLCFEGxdMsR2fPeaOjjGPO52lb7rytrNKJrTcdVWNUuv2Y3pdtFXgTupMq97E1o6P3AX0zJCSjhcU4PRMVlRwYYy7qqmLrjReXk0nXfLU9Z43vEyIynKnbaIoALUJFFvpBuZs2wo5JCNHbBLoeIRMEXYswQYsRXxo2Gb5lA0y0ZVR9W7eQ/sMGhpWTKT4E6yVMbxPrnYPo7YuD+ufT5TVrlgfMyFS+CgOgUSO7q0pRhGFUBgL+04WgjOMqPt+2bb06lBisy8amN5dBQFmsH2VEC2LXkG34FIbERawx/eJRGy21NYigMt+1dZ1nf7NdceY3xpNLRut/uCNpzAcb0h1fs4a19aA+30XHJ324bixoaM3c8k35xr805frkPS94AaDvy0mbvsP0POmFOLNZ0ebolPnN2ive0zv9nkZ2atncR8UPKQIFIQ4BMUHEDVSivdM8K/IQ8c/qsZ5ug8Pm5NPPo/QtcufKQ5Dw72GDcajLerosV/Obhu9K/jywORrIn0/r9vVDY95NVbdfyxXfDNtpTr2fahxGJfeikpqhuSNclZu2nos5p1MPraDaEdsZ5eSVF4cgkSn6QHcsWwKm5evj3c90xXWH+8hooTBmEG2bejUfPht4qK/lfNEOnkgV6HbwvQD0IJ+rdkh8dKeT95w7XvFpy/1bxvHtEsoqaNj8sqnX96yZc2tM6u5o+pYE8+CqpkPxN9tdiVhWQTxP2vmCoG9Zogz7qGNNcIDL8mlwUuQd97qesUrTQtQJtx7h8bt8iSBuG8k4uWRl9Xp2W29bWd1nf5xd1DMu/k2YyPoomemrLoscBns87Q4RYqTsJiWe1PQoqVn8esF2BU+K9+xKjV1h6+lu9ZRQ1x3ccUj8ep5HnhJQ7PF1Eb0pyPc8uYyk3NmjpxRP9kcXF3tcHoz08oDfampxUlVH7Ie6CPa414/7w48ntfKP1d5jfePqyGmMij3B6YanHBWuuTkLg+D8jNIiZpo9z+6mTOrKCjummPs92e4opK5L2/QoupNsj0r21pt/rJF20xJ/+tudsCueY2huoSjVZ4qHfjly+3Zv74jDAuze8vjWvh1V++4Nn0eEe3lu1vw/G9n0WCNlTOV9Cbz/Bu3VCfDEFQAA")!;

    /// <summary>
    /// Gets the "hazy" Dalamud look.
    /// </summary>
    public static StyleModelV1 DalamudHazy => new()
    {
        Name = "Dalamud Hazy",

        Alpha = 1,
        WindowPadding = new Vector2(8, 8),
        WindowRounding = 4,
        WindowBorderSize = 0,
        WindowTitleAlign = new Vector2(0, 0.5f),
        WindowMenuButtonPosition = ImGuiDir.Right,
        ChildRounding = 0,
        ChildBorderSize = 1,
        PopupRounding = 0,
        PopupBorderSize = 0,
        FramePadding = new Vector2(4, 3),
        FrameRounding = 4,
        FrameBorderSize = 0,
        ItemSpacing = new Vector2(8, 4),
        ItemInnerSpacing = new Vector2(4, 4),
        CellPadding = new Vector2(4, 2),
        TouchExtraPadding = new Vector2(0, 0),
        IndentSpacing = 21,
        ScrollbarSize = 16,
        ScrollbarRounding = 9,
        GrabMinSize = 13,
        GrabRounding = 3,
        LogSliderDeadzone = 4,
        TabRounding = 4,
        TabBorderSize = 0,
        ButtonTextAlign = new Vector2(0.5f, 0.5f),
        SelectableTextAlign = new Vector2(0, 0),
        DisplaySafeAreaPadding = new Vector2(3, 3),

        Colors = new Dictionary<string, Vector4>
        {
            { "Text", new Vector4(1, 1, 1, 1) },
            { "TextDisabled", new Vector4(0.5f, 0.5f, 0.5f, 1) },
            { "WindowBg", new Vector4(0.06f, 0.06f, 0.06f, 0.80f) },
            { "ChildBg", new Vector4(0, 0, 0, 0) },
            { "PopupBg", new Vector4(0.08f, 0.08f, 0.08f, 0.94f) },
            { "Border", new Vector4(0.43f, 0.43f, 0.5f, 0.5f) },
            { "BorderShadow", new Vector4(0, 0, 0, 0) },
            { "FrameBg", new Vector4(0.29f, 0.29f, 0.29f, 0.54f) },
            { "FrameBgHovered", new Vector4(0.54f, 0.54f, 0.54f, 0.4f) },
            { "FrameBgActive", new Vector4(0.64f, 0.64f, 0.64f, 0.67f) },
            { "TitleBg", new Vector4(0.022624433f, 0.022624206f, 0.022624206f, 0.85067874f) },
            { "TitleBgActive", new Vector4(0.439f, 0.105f, 0.141f, 0.827f) },
            { "TitleBgCollapsed", new Vector4(0, 0, 0, 0.51f) },
            { "MenuBarBg", new Vector4(0.14f, 0.14f, 0.14f, 1) },
            { "ScrollbarBg", new Vector4(0, 0, 0, 0) },
            { "ScrollbarGrab", new Vector4(0.31f, 0.31f, 0.31f, 1) },
            { "ScrollbarGrabHovered", new Vector4(0.41f, 0.41f, 0.41f, 1) },
            { "ScrollbarGrabActive", new Vector4(0.51f, 0.51f, 0.51f, 1) },
            { "CheckMark", new Vector4(0.86f, 0.86f, 0.86f, 1) },
            { "SliderGrab", new Vector4(0.54f, 0.54f, 0.54f, 1) },
            { "SliderGrabActive", new Vector4(0.67f, 0.67f, 0.67f, 1) },
            { "Button", new Vector4(0.71f, 0.71f, 0.71f, 0.4f) },
            { "ButtonHovered", new Vector4(0.3647059f, 0.078431375f, 0.078431375f, 0.94509804f) },
            { "ButtonActive", new Vector4(0.48416287f, 0.10077597f, 0.10077597f, 0.94509804f) },
            { "Header", new Vector4(0.59f, 0.59f, 0.59f, 0.31f) },
            { "HeaderHovered", new Vector4(0.5f, 0.5f, 0.5f, 0.8f) },
            { "HeaderActive", new Vector4(0.6f, 0.6f, 0.6f, 1) },
            { "Separator", new Vector4(0.43f, 0.43f, 0.5f, 0.5f) },
            { "SeparatorHovered", new Vector4(0.3647059f, 0.078431375f, 0.078431375f, 0.78280544f) },
            { "SeparatorActive", new Vector4(0.3647059f, 0.078431375f, 0.078431375f, 0.94509804f) },
            { "ResizeGrip", new Vector4(0.79f, 0.79f, 0.79f, 0.25f) },
            { "ResizeGripHovered", new Vector4(0.78f, 0.78f, 0.78f, 0.67f) },
            { "ResizeGripActive", new Vector4(0.3647059f, 0.078431375f, 0.078431375f, 0.94509804f) },
            { "Tab", new Vector4(0.23f, 0.23f, 0.23f, 0.86f) },
            { "TabHovered", new Vector4(0.58371043f, 0.30374074f, 0.30374074f, 0.7647059f) },
            { "TabActive", new Vector4(0.47963798f, 0.15843244f, 0.15843244f, 0.7647059f) },
            { "TabUnfocused", new Vector4(0.068f, 0.10199998f, 0.14800003f, 0.9724f) },
            { "TabUnfocusedActive", new Vector4(0.13599998f, 0.26199996f, 0.424f, 1) },
            { "DockingPreview", new Vector4(0.26f, 0.59f, 0.98f, 0.7f) },
            { "DockingEmptyBg", new Vector4(0.2f, 0.2f, 0.2f, 1) },
            { "PlotLines", new Vector4(0.61f, 0.61f, 0.61f, 1) },
            { "PlotLinesHovered", new Vector4(1, 0.43f, 0.35f, 1) },
            { "PlotHistogram", new Vector4(0.578199f, 0.16989735f, 0.16989735f, 0.78431374f) },
            { "PlotHistogramHovered", new Vector4(0.7819905f, 0.12230185f, 0.12230185f, 0.78431374f) },
            { "TableHeaderBg", new Vector4(0.19f, 0.19f, 0.2f, 1) },
            { "TableBorderStrong", new Vector4(0.31f, 0.31f, 0.35f, 1) },
            { "TableBorderLight", new Vector4(0.23f, 0.23f, 0.25f, 1) },
            { "TableRowBg", new Vector4(0, 0, 0, 0) },
            { "TableRowBgAlt", new Vector4(1, 1, 1, 0.06f) },
            { "TextSelectedBg", new Vector4(0.26f, 0.59f, 0.98f, 0.35f) },
            { "DragDropTarget", new Vector4(1, 1, 0, 0.9f) },
            { "NavHighlight", new Vector4(0.26f, 0.59f, 0.98f, 1) },
            { "NavWindowingHighlight", new Vector4(1, 1, 1, 0.7f) },
            { "NavWindowingDimBg", new Vector4(0.8f, 0.8f, 0.8f, 0.2f) },
            { "ModalWindowDimBg", new Vector4(0.8f, 0.8f, 0.8f, 0.35f) },
        },

        BuiltInColors = new DalamudColors
        {
            DalamudRed = new Vector4(1f, 0f, 0f, 1f),
            DalamudGrey = new Vector4(0.7f, 0.7f, 0.7f, 1f),
            DalamudGrey2 = new Vector4(0.7f, 0.7f, 0.7f, 1f),
            DalamudGrey3 = new Vector4(0.5f, 0.5f, 0.5f, 1f),
            DalamudWhite = new Vector4(1f, 1f, 1f, 1f),
            DalamudWhite2 = new Vector4(0.878f, 0.878f, 0.878f, 1f),
            DalamudOrange = new Vector4(1f, 0.709f, 0f, 1f),
            DalamudYellow = new Vector4(1f, 1f, .4f, 1f),
            DalamudViolet = new Vector4(0.770f, 0.700f, 0.965f, 1.000f),
            TankBlue = new Vector4(0f, 0.6f, 1f, 1f),
            HealerGreen = new Vector4(0f, 0.8f, 0.1333333f, 1f),
            DPSRed = new Vector4(0.7058824f, 0f, 0f, 1f),
            ParsedGrey = new Vector4(0.4f, 0.4f, 0.4f, 1f),
            ParsedGreen = new Vector4(0.117f, 1f, 0f, 1f),
            ParsedBlue = new Vector4(0f, 0.439f, 1f, 1f),
            ParsedPurple = new Vector4(0.639f, 0.207f, 0.933f, 1f),
            ParsedOrange = new Vector4(1f, 0.501f, 0f, 1f),
            ParsedPink = new Vector4(0.886f, 0.407f, 0.658f, 1f),
            ParsedGold = new Vector4(0.898f, 0.8f, 0.501f, 1f),
            InfoForeground = new Vector4(0f, 0.6f, 1f, 1f),
            InfoBackground = new Vector4(0.2f, 0.45f, 0.6f, 0.4f),
            SuccessForeground = new Vector4(0f, 0.8f, 0.1333333f, 1f),
            SuccessBackground = new Vector4(0.3f, 0.6f, 0.35f, 0.4f),
            WarningForeground = new Vector4(1f, 0.709f, 0f, 1f),
            WarningBackground = new Vector4(0.75f, 0.65f, 0.3f, 0.4f),
            ErrorForeground = new Vector4(1f, 0f, 0f, 1f),
            ErrorBackground = new Vector4(0.7f, 0.3f, 0.3f, 0.4f),
            AttentionForeground = new Vector4(1f, 0.709f, 0f, 1f),
            AttentionBackground = new Vector4(0.75f, 0.65f, 0.3f, 0.4f),
        },

        WindowBlurStrength = 0.5f,
        WindowBlurTintActive = new Vector4(0.27200785f, 0.06505883f, 0.08736471f, 0.08107843f),
        WindowBlurTint = new Vector4(0.014018277f, 0.014018136f, 0.014018136f, 0.08339988f),
        WindowBlurLuminosity = Vector4.Zero,
    };

    /// <summary>
    /// Gets the version prefix for this version.
    /// </summary>
    public static string SerializedPrefix => "DS1";

#pragma warning disable SA1600

    [JsonProperty("a")]
    public float Alpha { get; set; }

    [JsonProperty("b")]
    public Vector2 WindowPadding { get; set; }

    [JsonProperty("c")]
    public float WindowRounding { get; set; }

    [JsonProperty("d")]
    public float WindowBorderSize { get; set; }

    [JsonProperty("e")]
    public Vector2 WindowTitleAlign { get; set; }

    [JsonProperty("f")]
    public ImGuiDir WindowMenuButtonPosition { get; set; }

    [JsonProperty("g")]
    public float ChildRounding { get; set; }

    [JsonProperty("h")]
    public float ChildBorderSize { get; set; }

    [JsonProperty("i")]
    public float PopupRounding { get; set; }

    [JsonProperty("ab")]
    public float PopupBorderSize { get; set; }

    [JsonProperty("j")]
    public Vector2 FramePadding { get; set; }

    [JsonProperty("k")]
    public float FrameRounding { get; set; }

    [JsonProperty("l")]
    public float FrameBorderSize { get; set; }

    [JsonProperty("m")]
    public Vector2 ItemSpacing { get; set; }

    [JsonProperty("n")]
    public Vector2 ItemInnerSpacing { get; set; }

    [JsonProperty("o")]
    public Vector2 CellPadding { get; set; }

    [JsonProperty("p")]
    public Vector2 TouchExtraPadding { get; set; }

    [JsonProperty("q")]
    public float IndentSpacing { get; set; }

    [JsonProperty("r")]
    public float ScrollbarSize { get; set; }

    [JsonProperty("s")]
    public float ScrollbarRounding { get; set; }

    [JsonProperty("t")]
    public float GrabMinSize { get; set; }

    [JsonProperty("u")]
    public float GrabRounding { get; set; }

    [JsonProperty("v")]
    public float LogSliderDeadzone { get; set; }

    [JsonProperty("w")]
    public float TabRounding { get; set; }

    [JsonProperty("x")]
    public float TabBorderSize { get; set; }

    [JsonProperty("y")]
    public Vector2 ButtonTextAlign { get; set; }

    [JsonProperty("z")]
    public Vector2 SelectableTextAlign { get; set; }

    [JsonProperty("aa")]
    public Vector2 DisplaySafeAreaPadding { get; set; }

    [JsonProperty("ac")]
    public float WindowBlurStrength { get; set; }

    [JsonProperty("ad")]
    public Vector4 WindowBlurTint { get; set; }

    [JsonProperty("ae")]
    public Vector4 WindowBlurTintActive { get; set; }

    [JsonProperty("af")]
    public Vector4 WindowBlurLuminosity { get; set; }

#pragma warning restore SA1600

    /// <summary>
    /// Gets or sets a dictionary mapping ImGui color names to colors.
    /// </summary>
    [JsonProperty("col")]
    public Dictionary<string, Vector4> Colors { get; set; }

    /// <summary>
    /// Get a <see cref="StyleModel"/> instance via ImGui.
    /// </summary>
    /// <returns>The newly created <see cref="StyleModel"/> instance.</returns>
    public static StyleModelV1 Get()
    {
        var model = new StyleModelV1();
        var style = ImGui.GetStyle();

        model.Alpha = style.Alpha;
        model.WindowPadding = style.WindowPadding;
        model.WindowRounding = style.WindowRounding;
        model.WindowBorderSize = style.WindowBorderSize;
        model.WindowTitleAlign = style.WindowTitleAlign;
        model.WindowMenuButtonPosition = style.WindowMenuButtonPosition;
        model.ChildRounding = style.ChildRounding;
        model.ChildBorderSize = style.ChildBorderSize;
        model.PopupRounding = style.PopupRounding;
        model.PopupBorderSize = style.PopupBorderSize;
        model.FramePadding = style.FramePadding;
        model.FrameRounding = style.FrameRounding;
        model.FrameBorderSize = style.FrameBorderSize;
        model.ItemSpacing = style.ItemSpacing;
        model.ItemInnerSpacing = style.ItemInnerSpacing;
        model.CellPadding = style.CellPadding;
        model.TouchExtraPadding = style.TouchExtraPadding;
        model.IndentSpacing = style.IndentSpacing;
        model.ScrollbarSize = style.ScrollbarSize;
        model.ScrollbarRounding = style.ScrollbarRounding;
        model.GrabMinSize = style.GrabMinSize;
        model.GrabRounding = style.GrabRounding;
        model.LogSliderDeadzone = style.LogSliderDeadzone;
        model.TabRounding = style.TabRounding;
        model.TabBorderSize = style.TabBorderSize;
        model.ButtonTextAlign = style.ButtonTextAlign;
        model.SelectableTextAlign = style.SelectableTextAlign;
        model.DisplaySafeAreaPadding = style.DisplaySafeAreaPadding;

        model.Colors = [];

        foreach (var imGuiCol in Enum.GetValues<ImGuiCol>())
        {
            if (imGuiCol == ImGuiCol.Count)
            {
                continue;
            }

            model.Colors[imGuiCol.ToString()] = style.Colors[(int)imGuiCol];
        }

        model.BuiltInColors = new DalamudColors
        {
            DalamudRed = ImGuiColors.DalamudRed,
            DalamudGrey = ImGuiColors.DalamudGrey,
            DalamudGrey2 = ImGuiColors.DalamudGrey2,
            DalamudGrey3 = ImGuiColors.DalamudGrey3,
            DalamudWhite = ImGuiColors.DalamudWhite,
            DalamudWhite2 = ImGuiColors.DalamudWhite2,
            DalamudOrange = ImGuiColors.DalamudOrange,
            DalamudYellow = ImGuiColors.DalamudYellow,
            DalamudViolet = ImGuiColors.DalamudViolet,
            TankBlue = ImGuiColors.TankBlue,
            HealerGreen = ImGuiColors.HealerGreen,
            DPSRed = ImGuiColors.DPSRed,
            ParsedGrey = ImGuiColors.ParsedGrey,
            ParsedGreen = ImGuiColors.ParsedGreen,
            ParsedBlue = ImGuiColors.ParsedBlue,
            ParsedPurple = ImGuiColors.ParsedPurple,
            ParsedOrange = ImGuiColors.ParsedOrange,
            ParsedPink = ImGuiColors.ParsedPink,
            ParsedGold = ImGuiColors.ParsedGold,
            InfoForeground = ImGuiColors.InfoForeground,
            InfoBackground = ImGuiColors.InfoBackground,
            SuccessForeground = ImGuiColors.SuccessForeground,
            SuccessBackground = ImGuiColors.SuccessBackground,
            WarningForeground = ImGuiColors.WarningForeground,
            WarningBackground = ImGuiColors.WarningBackground,
            ErrorForeground = ImGuiColors.ErrorForeground,
            ErrorBackground = ImGuiColors.ErrorBackground,
            AttentionForeground = ImGuiColors.AttentionForeground,
            AttentionBackground = ImGuiColors.AttentionBackground,
        };

        model.WindowBlurStrength = WindowSystem.DefaultBackgroundBlurStrength;
        model.WindowBlurTint = WindowSystem.DefaultBackgroundBlurTint;
        model.WindowBlurTintActive = WindowSystem.DefaultBackgroundBlurTintActive;
        model.WindowBlurLuminosity = WindowSystem.DefaultBackgroundBlurLuminosity;

        return model;
    }

    public override StyleModel Clone()
    {
        var clone = (StyleModelV1)this.MemberwiseClone();
        clone.Colors        = new Dictionary<string, Vector4>(this.Colors);
        clone.BuiltInColors = this.BuiltInColors?.Clone();
        return clone;
    }

    /// <summary>
    /// Apply this StyleModel via ImGui.
    /// </summary>
    public override void Apply()
    {
        var style = ImGui.GetStyle();

        style.Alpha = this.Alpha;
        style.WindowPadding = this.WindowPadding;
        style.WindowRounding = this.WindowRounding;
        style.WindowBorderSize = this.WindowBorderSize;
        style.WindowTitleAlign = this.WindowTitleAlign;
        style.WindowMenuButtonPosition = this.WindowMenuButtonPosition;
        style.ChildRounding = this.ChildRounding;
        style.ChildBorderSize = this.ChildBorderSize;
        style.PopupRounding = this.PopupRounding;
        style.PopupBorderSize = this.PopupBorderSize;
        style.FramePadding = this.FramePadding;
        style.FrameRounding = this.FrameRounding;
        style.FrameBorderSize = this.FrameBorderSize;
        style.ItemSpacing = this.ItemSpacing;
        style.ItemInnerSpacing = this.ItemInnerSpacing;
        style.CellPadding = this.CellPadding;
        style.TouchExtraPadding = this.TouchExtraPadding;
        style.IndentSpacing = this.IndentSpacing;
        style.ScrollbarSize = this.ScrollbarSize;
        style.ScrollbarRounding = this.ScrollbarRounding;
        style.GrabMinSize = this.GrabMinSize;
        style.GrabRounding = this.GrabRounding;
        style.LogSliderDeadzone = this.LogSliderDeadzone;
        style.TabRounding = this.TabRounding;
        style.TabBorderSize = this.TabBorderSize;
        style.ButtonTextAlign = this.ButtonTextAlign;
        style.SelectableTextAlign = this.SelectableTextAlign;
        style.DisplaySafeAreaPadding = this.DisplaySafeAreaPadding;

        foreach (var imGuiCol in Enum.GetValues<ImGuiCol>())
        {
            if (imGuiCol == ImGuiCol.Count)
            {
                continue;
            }

            style.Colors[(int)imGuiCol] = this.Colors[imGuiCol.ToString()];
        }

        this.BuiltInColors?.Apply();
        WindowSystem.DefaultBackgroundBlurStrength = this.WindowBlurStrength;
        WindowSystem.DefaultBackgroundBlurTint = this.WindowBlurTint;
        WindowSystem.DefaultBackgroundBlurTintActive = this.WindowBlurTintActive;
        WindowSystem.DefaultBackgroundBlurLuminosity = this.WindowBlurLuminosity;
    }

    /// <inheritdoc/>
    public override void Push()
    {
        this.PushStyleHelper(ImGuiStyleVar.Alpha, this.Alpha);
        this.PushStyleHelper(ImGuiStyleVar.WindowPadding, this.WindowPadding);
        this.PushStyleHelper(ImGuiStyleVar.WindowRounding, this.WindowRounding);
        this.PushStyleHelper(ImGuiStyleVar.WindowBorderSize, this.WindowBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.WindowTitleAlign, this.WindowTitleAlign);
        this.PushStyleHelper(ImGuiStyleVar.ChildRounding, this.ChildRounding);
        this.PushStyleHelper(ImGuiStyleVar.ChildBorderSize, this.ChildBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.PopupRounding, this.PopupRounding);
        this.PushStyleHelper(ImGuiStyleVar.PopupBorderSize, this.PopupBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.FramePadding, this.FramePadding);
        this.PushStyleHelper(ImGuiStyleVar.FrameRounding, this.FrameRounding);
        this.PushStyleHelper(ImGuiStyleVar.FrameBorderSize, this.FrameBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.ItemSpacing, this.ItemSpacing);
        this.PushStyleHelper(ImGuiStyleVar.ItemInnerSpacing, this.ItemInnerSpacing);
        this.PushStyleHelper(ImGuiStyleVar.CellPadding, this.CellPadding);
        this.PushStyleHelper(ImGuiStyleVar.IndentSpacing, this.IndentSpacing);
        this.PushStyleHelper(ImGuiStyleVar.ScrollbarSize, this.ScrollbarSize);
        this.PushStyleHelper(ImGuiStyleVar.ScrollbarRounding, this.ScrollbarRounding);
        this.PushStyleHelper(ImGuiStyleVar.GrabMinSize, this.GrabMinSize);
        this.PushStyleHelper(ImGuiStyleVar.GrabRounding, this.GrabRounding);
        this.PushStyleHelper(ImGuiStyleVar.TabRounding, this.TabRounding);
        this.PushStyleHelper(ImGuiStyleVar.ButtonTextAlign, this.ButtonTextAlign);
        this.PushStyleHelper(ImGuiStyleVar.SelectableTextAlign, this.SelectableTextAlign);

        foreach (var imGuiCol in Enum.GetValues<ImGuiCol>())
        {
            if (imGuiCol == ImGuiCol.Count)
            {
                continue;
            }

            this.PushColorHelper(imGuiCol, this.Colors[imGuiCol.ToString()]);
        }

        this.DonePushing();
    }
}
