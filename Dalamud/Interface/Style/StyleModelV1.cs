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
        this.Name   = "Unknown";
    }

    /// <summary>
    /// Gets the standard Dalamud look.
    /// </summary>
    public static StyleModel DalamudStandard { get; } = new StyleModelV1
    {
        Alpha                    = 1f,
        WindowPadding            = new(12f, 10f),
        WindowRounding           = 12f,
        WindowBorderSize         = 0f,
        WindowTitleAlign         = new(0.5f, 0.5f),
        WindowMenuButtonPosition = ImGuiDir.Right,
        ChildRounding            = 12f,
        ChildBorderSize          = 0f,
        PopupRounding            = 12f,
        PopupBorderSize          = 0f,
        FramePadding             = new(10f, 6f),
        FrameRounding            = 11f,
        FrameBorderSize          = 0f,
        ItemSpacing              = new(8f, 6f),
        ItemInnerSpacing         = new(10f, 6f),
        CellPadding              = new(8f, 6f),
        TouchExtraPadding        = new(1f, 1f),
        IndentSpacing            = 20f,
        ScrollbarSize            = 16f,
        ScrollbarRounding        = 10f,
        GrabMinSize              = 10f,
        GrabRounding             = 10f,
        LogSliderDeadzone        = 3f,
        TabRounding              = 12f,
        TabBorderSize            = 0f,
        ButtonTextAlign          = new(0.5f, 0.5f),
        SelectableTextAlign      = new(0f, 0.5f),
        DisplaySafeAreaPadding   = new(6f, 6f),
        WindowBlurStrength       = 0.5f,
        WindowBlurTint           = new(0.030980391f, 0.061960783f, 0.11152941f, 0.08339988f),
        WindowBlurTintActive     = new(0.04337255f, 0.0867451f, 0.14870588f, 0.08107843f),
        WindowBlurLuminosity     = new(0f, 0f, 0f, 0f),
        Name                     = "Tropical Sanctuary",
        Version                  = 0,
        Colors = new Dictionary<string, Vector4>
        {
            [nameof(ImGuiCol.Text)]                  = new(0.94f, 0.98f, 1f, 1f),
            [nameof(ImGuiCol.TextDisabled)]          = new(0.6f, 0.7f, 0.78f, 1f),
            [nameof(ImGuiCol.WindowBg)]              = new(0.054838087f, 0.12044467f, 0.20461094f, 1f),
            [nameof(ImGuiCol.ChildBg)]               = new(0.09f, 0.18f, 0.3f, 0.8f),
            [nameof(ImGuiCol.PopupBg)]               = new(0.085f, 0.17f, 0.285f, 0.99f),
            [nameof(ImGuiCol.Border)]                = new(0.4f, 0.62f, 0.82f, 0.24f),
            [nameof(ImGuiCol.BorderShadow)]          = new(0f, 0f, 0f, 0f),
            [nameof(ImGuiCol.FrameBg)]               = new(0.14f, 0.27f, 0.42f, 1f),
            [nameof(ImGuiCol.FrameBgHovered)]        = new(0.09f, 0.35f, 0.5f, 1f),
            [nameof(ImGuiCol.FrameBgActive)]         = new(0.08f, 0.42f, 0.58f, 1f),
            [nameof(ImGuiCol.TitleBg)]               = new(0.05f, 0.1f, 0.18f, 1f),
            [nameof(ImGuiCol.TitleBgActive)]         = new(0.07f, 0.14f, 0.24f, 1f),
            [nameof(ImGuiCol.TitleBgCollapsed)]      = new(0.07f, 0.14f, 0.24f, 1f),
            [nameof(ImGuiCol.MenuBarBg)]             = new(0.085f, 0.18f, 0.29f, 1f),
            [nameof(ImGuiCol.ScrollbarBg)]           = new(0.04f, 0.08f, 0.14f, 1f),
            [nameof(ImGuiCol.ScrollbarGrab)]         = new(0.12f, 0.26f, 0.4f, 1f),
            [nameof(ImGuiCol.ScrollbarGrabHovered)]  = new(0.12f, 0.5f, 0.76f, 1f),
            [nameof(ImGuiCol.ScrollbarGrabActive)]   = new(0.12f, 0.72f, 0.96f, 1f),
            [nameof(ImGuiCol.CheckMark)]             = new(0.7f, 0.92f, 0.22f, 1f),
            [nameof(ImGuiCol.SliderGrab)]            = new(0.12f, 0.72f, 0.96f, 0.95f),
            [nameof(ImGuiCol.SliderGrabActive)]      = new(1f, 0.74f, 0.14f, 1f),
            [nameof(ImGuiCol.Button)]                = new(1f, 0.62f, 0.1f, 0.92f),
            [nameof(ImGuiCol.ButtonHovered)]         = new(1f, 0.82f, 0.18f, 1f),
            [nameof(ImGuiCol.ButtonActive)]          = new(1f, 0.46f, 0.1f, 1f),
            [nameof(ImGuiCol.Header)]                = new(0.11f, 0.28f, 0.4f, 0.9f),
            [nameof(ImGuiCol.HeaderHovered)]         = new(0.105f, 0.35f, 0.5f, 0.95f),
            [nameof(ImGuiCol.HeaderActive)]          = new(0.08f, 0.42f, 0.58f, 0.96f),
            [nameof(ImGuiCol.Separator)]             = new(0.4f, 0.62f, 0.82f, 0.26f),
            [nameof(ImGuiCol.SeparatorHovered)]      = new(0.12f, 0.72f, 0.96f, 0.65f),
            [nameof(ImGuiCol.SeparatorActive)]       = new(1f, 0.74f, 0.14f, 0.85f),
            [nameof(ImGuiCol.ResizeGrip)]            = new(0.12f, 0.5f, 0.76f, 0.22f),
            [nameof(ImGuiCol.ResizeGripHovered)]     = new(0.12f, 0.72f, 0.96f, 0.42f),
            [nameof(ImGuiCol.ResizeGripActive)]      = new(0.12f, 0.72f, 0.96f, 0.62f),
            [nameof(ImGuiCol.Tab)]                   = new(0.06f, 0.12f, 0.2f, 1f),
            [nameof(ImGuiCol.TabHovered)]            = new(0.11f, 0.38f, 0.54f, 1f),
            [nameof(ImGuiCol.TabActive)]             = new(0.1f, 0.32f, 0.46f, 1f),
            [nameof(ImGuiCol.TabUnfocused)]          = new(0.05f, 0.1f, 0.18f, 1f),
            [nameof(ImGuiCol.TabUnfocusedActive)]    = new(0.085f, 0.23f, 0.35f, 1f),
            [nameof(ImGuiCol.DockingPreview)]        = new(0.12f, 0.72f, 0.96f, 0.3f),
            [nameof(ImGuiCol.DockingEmptyBg)]        = new(0.05f, 0.1f, 0.18f, 1f),
            [nameof(ImGuiCol.PlotLines)]             = new(0.12f, 0.72f, 0.96f, 1f),
            [nameof(ImGuiCol.PlotLinesHovered)]      = new(1f, 0.82f, 0.18f, 1f),
            [nameof(ImGuiCol.PlotHistogram)]         = new(1f, 0.62f, 0.1f, 0.95f),
            [nameof(ImGuiCol.PlotHistogramHovered)]  = new(1f, 0.46f, 0.1f, 1f),
            [nameof(ImGuiCol.TableHeaderBg)]         = new(0.105f, 0.22f, 0.35f, 1f),
            [nameof(ImGuiCol.TableBorderStrong)]     = new(0.4f, 0.62f, 0.82f, 0.28f),
            [nameof(ImGuiCol.TableBorderLight)]      = new(0.4f, 0.62f, 0.82f, 0.14f),
            [nameof(ImGuiCol.TableRowBg)]            = new(0f, 0f, 0f, 0f),
            [nameof(ImGuiCol.TableRowBgAlt)]         = new(0.22f, 0.42f, 0.58f, 0.12f),
            [nameof(ImGuiCol.TextSelectedBg)]        = new(0.12f, 0.72f, 0.96f, 0.24f),
            [nameof(ImGuiCol.DragDropTarget)]        = new(1f, 0.82f, 0.18f, 0.9f),
            [nameof(ImGuiCol.NavHighlight)]          = new(1f, 0.82f, 0.18f, 0.9f),
            [nameof(ImGuiCol.NavWindowingHighlight)] = new(0.12f, 0.72f, 0.96f, 0.28f),
            [nameof(ImGuiCol.NavWindowingDimBg)]     = new(0f, 0f, 0f, 0.32f),
            [nameof(ImGuiCol.ModalWindowDimBg)]      = new(0f, 0f, 0f, 0.52f)
        },
        BuiltInColors = new DalamudColors
        {
            DalamudRed          = new(1f, 0.27f, 0.23f, 1f),
            DalamudGrey         = new(0.62f, 0.7f, 0.78f, 1f),
            DalamudGrey2        = new(0.45f, 0.54f, 0.62f, 1f),
            DalamudGrey3        = new(0.28f, 0.36f, 0.45f, 1f),
            DalamudWhite        = new(0.94f, 0.98f, 1f, 1f),
            DalamudWhite2       = new(0.86f, 0.92f, 0.96f, 1f),
            DalamudOrange       = new(1f, 0.62f, 0.1f, 1f),
            TankBlue            = new(0.12f, 0.72f, 0.96f, 1f),
            HealerGreen         = new(0.7f, 0.92f, 0.22f, 1f),
            DPSRed              = new(1f, 0.27f, 0.23f, 1f),
            DalamudYellow       = new(1f, 0.86f, 0.2f, 1f),
            DalamudViolet       = new(0.63f, 0.46f, 0.95f, 1f),
            ParsedGrey          = new(0.62f, 0.7f, 0.78f, 1f),
            ParsedGreen         = new(0.7f, 0.92f, 0.22f, 1f),
            ParsedBlue          = new(0.12f, 0.72f, 0.96f, 1f),
            ParsedPurple        = new(0.63f, 0.46f, 0.95f, 1f),
            ParsedOrange        = new(1f, 0.62f, 0.1f, 1f),
            ParsedPink          = new(1f, 0.25f, 0.55f, 1f),
            ParsedGold          = new(1f, 0.84f, 0.35f, 1f),
            InfoForeground      = new(0.12f, 0.72f, 0.96f, 1f),
            InfoBackground      = new(0.2f, 0.54f, 0.705f, 0.4f),
            SuccessForeground   = new(0.7f, 0.92f, 0.22f, 1f),
            SuccessBackground   = new(0.49f, 0.64f, 0.335f, 0.4f),
            WarningForeground   = new(1f, 0.62f, 0.1f, 1f),
            WarningBackground   = new(0.64f, 0.49f, 0.275f, 0.4f),
            ErrorForeground     = new(1f, 0.27f, 0.23f, 1f),
            ErrorBackground     = new(0.64f, 0.315f, 0.34f, 0.4f),
            AttentionForeground = new(1f, 0.62f, 0.1f, 1f),
            AttentionBackground = new(0.64f, 0.49f, 0.275f, 0.4f)
        }
    };

    /// <summary>
    /// Gets the standard Dalamud look.
    /// </summary>
    public static StyleModel DalamudClassic { get; } = new StyleModelV1
    {
        Alpha                    = 1f,
        WindowPadding            = new(8f, 8f),
        WindowRounding           = 6f,
        WindowBorderSize         = 0f,
        WindowTitleAlign         = new(0f, 0.5f),
        WindowMenuButtonPosition = ImGuiDir.Right,
        ChildRounding            = 6f,
        ChildBorderSize          = 1f,
        PopupRounding            = 4f,
        PopupBorderSize          = 0f,
        FramePadding             = new(6f, 4f),
        FrameRounding            = 4f,
        FrameBorderSize          = 0f,
        ItemSpacing              = new(4f, 5f),
        ItemInnerSpacing         = new(4f, 4f),
        CellPadding              = new(4f, 2f),
        TouchExtraPadding        = new(4f, 4f),
        IndentSpacing            = 21f,
        ScrollbarSize            = 16f,
        ScrollbarRounding        = 8f,
        GrabMinSize              = 10f,
        GrabRounding             = 4f,
        LogSliderDeadzone        = 2f,
        TabRounding              = 4f,
        TabBorderSize            = 0f,
        ButtonTextAlign          = new(0.5f, 0.5f),
        SelectableTextAlign      = new(0f, 0.15f),
        DisplaySafeAreaPadding   = new(3f, 3f),
        WindowBlurStrength       = 0.5f,
        WindowBlurTint           = new(0.07289504f, 0.087474056f, 0.12149173f, 0.08339988f),
        WindowBlurTintActive     = new(0.10205306f, 0.12149173f, 0.17008844f, 0.08107843f),
        WindowBlurLuminosity     = new(0f, 0f, 0f, 0f),
        Name                     = "Code Cobalt",
        Version                  = 0,
        Colors = new Dictionary<string, Vector4>
        {
            [nameof(ImGuiCol.Text)]                  = new(0.9411765f, 0.95686275f, 0.96862745f, 1f),
            [nameof(ImGuiCol.TextDisabled)]          = new(0.41960785f, 0.47843137f, 0.54901963f, 1f),
            [nameof(ImGuiCol.WindowBg)]              = new(0.101960786f, 0.11764706f, 0.16862746f, 1f),
            [nameof(ImGuiCol.ChildBg)]               = new(0.12156863f, 0.14509805f, 0.2f, 1f),
            [nameof(ImGuiCol.PopupBg)]               = new(0.14509805f, 0.16862746f, 0.22745098f, 1f),
            [nameof(ImGuiCol.Border)]                = new(0.22745098f, 0.26666668f, 0.34509805f, 1f),
            [nameof(ImGuiCol.BorderShadow)]          = new(0.050980393f, 0.0627451f, 0.09411765f, 1f),
            [nameof(ImGuiCol.FrameBg)]               = new(0.1764706f, 0.20392157f, 0.27058825f, 1f),
            [nameof(ImGuiCol.FrameBgHovered)]        = new(0.22352941f, 0.25490198f, 0.32156864f, 1f),
            [nameof(ImGuiCol.FrameBgActive)]         = new(0.19607843f, 0.22352941f, 0.3019608f, 1f),
            [nameof(ImGuiCol.TitleBg)]               = new(0.11764706f, 0.14117648f, 0.19607843f, 1f),
            [nameof(ImGuiCol.TitleBgActive)]         = new(0.16470589f, 0.19607843f, 0.27450982f, 1f),
            [nameof(ImGuiCol.TitleBgCollapsed)]      = new(0.16470589f, 0.19607843f, 0.27450982f, 1f),
            [nameof(ImGuiCol.MenuBarBg)]             = new(0.13725491f, 0.16078432f, 0.21568628f, 1f),
            [nameof(ImGuiCol.ScrollbarBg)]           = new(0.10980392f, 0.1254902f, 0.1764706f, 1f),
            [nameof(ImGuiCol.ScrollbarGrab)]         = new(0.22745098f, 0.26666668f, 0.34509805f, 1f),
            [nameof(ImGuiCol.ScrollbarGrabHovered)]  = new(0.2901961f, 0.33333334f, 0.40784314f, 1f),
            [nameof(ImGuiCol.ScrollbarGrabActive)]   = new(0.3529412f, 0.4f, 0.47058824f, 1f),
            [nameof(ImGuiCol.CheckMark)]             = new(0.2901961f, 0.5647059f, 0.8862745f, 1f),
            [nameof(ImGuiCol.SliderGrab)]            = new(0.2901961f, 0.5647059f, 0.8862745f, 1f),
            [nameof(ImGuiCol.SliderGrabActive)]      = new(0.3529412f, 0.627451f, 0.9411765f, 1f),
            [nameof(ImGuiCol.Button)]                = new(0.22745098f, 0.42352942f, 0.65882355f, 1f),
            [nameof(ImGuiCol.ButtonHovered)]         = new(0.25882354f, 0.47058824f, 0.72156864f, 1f),
            [nameof(ImGuiCol.ButtonActive)]          = new(0.18039216f, 0.32941177f, 0.53333336f, 1f),
            [nameof(ImGuiCol.Header)]                = new(0.16470589f, 0.19607843f, 0.27450982f, 1f),
            [nameof(ImGuiCol.HeaderHovered)]         = new(0.22352941f, 0.25490198f, 0.32156864f, 1f),
            [nameof(ImGuiCol.HeaderActive)]          = new(0.19607843f, 0.22352941f, 0.3019608f, 1f),
            [nameof(ImGuiCol.Separator)]             = new(0.22745098f, 0.26666668f, 0.34509805f, 0.53333336f),
            [nameof(ImGuiCol.SeparatorHovered)]      = new(0.2901961f, 0.33333334f, 0.40784314f, 1f),
            [nameof(ImGuiCol.SeparatorActive)]       = new(0.3529412f, 0.4f, 0.47058824f, 1f),
            [nameof(ImGuiCol.ResizeGrip)]            = new(0.2901961f, 0.5647059f, 0.8862745f, 0.4f),
            [nameof(ImGuiCol.ResizeGripHovered)]     = new(0.3529412f, 0.627451f, 0.9411765f, 1f),
            [nameof(ImGuiCol.ResizeGripActive)]      = new(0.22745098f, 0.5019608f, 0.8235294f, 1f),
            [nameof(ImGuiCol.Tab)]                   = new(0.16470589f, 0.19607843f, 0.27450982f, 1f),
            [nameof(ImGuiCol.TabHovered)]            = new(0.25882354f, 0.47058824f, 0.72156864f, 1f),
            [nameof(ImGuiCol.TabActive)]             = new(0.28309774f, 0.42473775f, 0.62886596f, 1f),
            [nameof(ImGuiCol.TabUnfocused)]          = new(0.11764706f, 0.14117648f, 0.19607843f, 1f),
            [nameof(ImGuiCol.TabUnfocusedActive)]    = new(0.21568628f, 0.2901961f, 0.42352942f, 1f),
            [nameof(ImGuiCol.DockingPreview)]        = new(0.2901961f, 0.5647059f, 0.8862745f, 1f),
            [nameof(ImGuiCol.DockingEmptyBg)]        = new(0.101960786f, 0.11764706f, 0.16862746f, 1f),
            [nameof(ImGuiCol.PlotLines)]             = new(0.3529412f, 0.627451f, 0.9411765f, 1f),
            [nameof(ImGuiCol.PlotLinesHovered)]      = new(0.41568628f, 0.6901961f, 1f, 1f),
            [nameof(ImGuiCol.PlotHistogram)]         = new(0.43529412f, 0.8117647f, 0.5921569f, 1f),
            [nameof(ImGuiCol.PlotHistogramHovered)]  = new(0.49803922f, 0.8745098f, 0.654902f, 1f),
            [nameof(ImGuiCol.TableHeaderBg)]         = new(0.13725491f, 0.16078432f, 0.21568628f, 1f),
            [nameof(ImGuiCol.TableBorderStrong)]     = new(0.22745098f, 0.26666668f, 0.34509805f, 1f),
            [nameof(ImGuiCol.TableBorderLight)]      = new(0.1764706f, 0.20392157f, 0.27058825f, 1f),
            [nameof(ImGuiCol.TableRowBg)]            = new(0.101960786f, 0.11764706f, 0.16862746f, 0f),
            [nameof(ImGuiCol.TableRowBgAlt)]         = new(0.13725491f, 0.16078432f, 0.21568628f, 0.4f),
            [nameof(ImGuiCol.TextSelectedBg)]        = new(0.2901961f, 0.5647059f, 0.8862745f, 0.2f),
            [nameof(ImGuiCol.DragDropTarget)]        = new(1f, 0.84313726f, 0f, 1f),
            [nameof(ImGuiCol.NavHighlight)]          = new(0.3529412f, 0.627451f, 0.9411765f, 1f),
            [nameof(ImGuiCol.NavWindowingHighlight)] = new(1f, 0.84313726f, 0f, 1f),
            [nameof(ImGuiCol.NavWindowingDimBg)]     = new(0.101960786f, 0.11764706f, 0.16862746f, 0.8f),
            [nameof(ImGuiCol.ModalWindowDimBg)]      = new(0.050980393f, 0.0627451f, 0.09411765f, 0.6f)
        },
        BuiltInColors = new DalamudColors
        {
            DalamudRed          = new(1f, 0f, 0f, 1f),
            DalamudGrey         = new(0.7f, 0.7f, 0.7f, 1f),
            DalamudGrey2        = new(0.7f, 0.7f, 0.7f, 1f),
            DalamudGrey3        = new(0.5f, 0.5f, 0.5f, 1f),
            DalamudWhite        = new(1f, 1f, 1f, 1f),
            DalamudWhite2       = new(0.878f, 0.878f, 0.878f, 1f),
            DalamudOrange       = new(1f, 0.709f, 0f, 1f),
            TankBlue            = new(0f, 0.6f, 1f, 1f),
            HealerGreen         = new(0f, 0.8f, 0.1333333f, 1f),
            DPSRed              = new(0.7058824f, 0f, 0f, 1f),
            DalamudYellow       = new(1f, 1f, 0.4f, 1f),
            DalamudViolet       = new(0.77f, 0.7f, 0.965f, 1f),
            ParsedGrey          = new(0.4f, 0.4f, 0.4f, 1f),
            ParsedGreen         = new(0.117f, 1f, 0f, 1f),
            ParsedBlue          = new(0f, 0.439f, 1f, 1f),
            ParsedPurple        = new(0.639f, 0.207f, 0.933f, 1f),
            ParsedOrange        = new(1f, 0.501f, 0f, 1f),
            ParsedPink          = new(0.886f, 0.407f, 0.658f, 1f),
            ParsedGold          = new(0.898f, 0.8f, 0.501f, 1f),
            InfoForeground      = new(0f, 0.6f, 1f, 1f),
            InfoBackground      = new(0.25f, 0.55f, 0.75f, 0.4f),
            SuccessForeground   = new(0f, 0.8f, 0.1333333f, 1f),
            SuccessBackground   = new(0.25f, 0.65f, 0.31666666f, 0.4f),
            WarningForeground   = new(1f, 0.709f, 0f, 1f),
            WarningBackground   = new(0.75f, 0.6045f, 0.25f, 0.4f),
            ErrorForeground     = new(1f, 0f, 0f, 1f),
            ErrorBackground     = new(0.75f, 0.25f, 0.25f, 0.4f),
            AttentionForeground = new(1f, 0.709f, 0f, 1f),
            AttentionBackground = new(0.75f, 0.6045f, 0.25f, 0.4f)
        }
    };

    /// <summary>
    /// Gets the "hazy" Dalamud look.
    /// </summary>
    public static StyleModelV1 DalamudHazy => new()
    {
        Name = "Dalamud Hazy",

        Alpha                    = 1,
        WindowPadding            = new Vector2(8, 8),
        WindowRounding           = 4,
        WindowBorderSize         = 0,
        WindowTitleAlign         = new Vector2(0, 0.5f),
        WindowMenuButtonPosition = ImGuiDir.Right,
        ChildRounding            = 0,
        ChildBorderSize          = 1,
        PopupRounding            = 0,
        PopupBorderSize          = 0,
        FramePadding             = new Vector2(4, 3),
        FrameRounding            = 4,
        FrameBorderSize          = 0,
        ItemSpacing              = new Vector2(8, 4),
        ItemInnerSpacing         = new Vector2(4, 4),
        CellPadding              = new Vector2(4, 2),
        TouchExtraPadding        = new Vector2(0, 0),
        IndentSpacing            = 21,
        ScrollbarSize            = 16,
        ScrollbarRounding        = 9,
        GrabMinSize              = 13,
        GrabRounding             = 3,
        LogSliderDeadzone        = 4,
        TabRounding              = 4,
        TabBorderSize            = 0,
        ButtonTextAlign          = new Vector2(0.5f, 0.5f),
        SelectableTextAlign      = new Vector2(0,    0),
        DisplaySafeAreaPadding   = new Vector2(3,    3),

        Colors = new Dictionary<string, Vector4>
        {
            { "Text", new Vector4(1,                          1,            1,            1) },
            { "TextDisabled", new Vector4(0.5f,               0.5f,         0.5f,         1) },
            { "WindowBg", new Vector4(0.06f,                  0.06f,        0.06f,        0.80f) },
            { "ChildBg", new Vector4(0,                       0,            0,            0) },
            { "PopupBg", new Vector4(0.08f,                   0.08f,        0.08f,        0.94f) },
            { "Border", new Vector4(0.43f,                    0.43f,        0.5f,         0.5f) },
            { "BorderShadow", new Vector4(0,                  0,            0,            0) },
            { "FrameBg", new Vector4(0.29f,                   0.29f,        0.29f,        0.54f) },
            { "FrameBgHovered", new Vector4(0.54f,            0.54f,        0.54f,        0.4f) },
            { "FrameBgActive", new Vector4(0.64f,             0.64f,        0.64f,        0.67f) },
            { "TitleBg", new Vector4(0.022624433f,            0.022624206f, 0.022624206f, 0.85067874f) },
            { "TitleBgActive", new Vector4(0.439f,            0.105f,       0.141f,       0.827f) },
            { "TitleBgCollapsed", new Vector4(0,              0,            0,            0.51f) },
            { "MenuBarBg", new Vector4(0.14f,                 0.14f,        0.14f,        1) },
            { "ScrollbarBg", new Vector4(0,                   0,            0,            0) },
            { "ScrollbarGrab", new Vector4(0.31f,             0.31f,        0.31f,        1) },
            { "ScrollbarGrabHovered", new Vector4(0.41f,      0.41f,        0.41f,        1) },
            { "ScrollbarGrabActive", new Vector4(0.51f,       0.51f,        0.51f,        1) },
            { "CheckMark", new Vector4(0.86f,                 0.86f,        0.86f,        1) },
            { "SliderGrab", new Vector4(0.54f,                0.54f,        0.54f,        1) },
            { "SliderGrabActive", new Vector4(0.67f,          0.67f,        0.67f,        1) },
            { "Button", new Vector4(0.71f,                    0.71f,        0.71f,        0.4f) },
            { "ButtonHovered", new Vector4(0.3647059f,        0.078431375f, 0.078431375f, 0.94509804f) },
            { "ButtonActive", new Vector4(0.48416287f,        0.10077597f,  0.10077597f,  0.94509804f) },
            { "Header", new Vector4(0.59f,                    0.59f,        0.59f,        0.31f) },
            { "HeaderHovered", new Vector4(0.5f,              0.5f,         0.5f,         0.8f) },
            { "HeaderActive", new Vector4(0.6f,               0.6f,         0.6f,         1) },
            { "Separator", new Vector4(0.43f,                 0.43f,        0.5f,         0.5f) },
            { "SeparatorHovered", new Vector4(0.3647059f,     0.078431375f, 0.078431375f, 0.78280544f) },
            { "SeparatorActive", new Vector4(0.3647059f,      0.078431375f, 0.078431375f, 0.94509804f) },
            { "ResizeGrip", new Vector4(0.79f,                0.79f,        0.79f,        0.25f) },
            { "ResizeGripHovered", new Vector4(0.78f,         0.78f,        0.78f,        0.67f) },
            { "ResizeGripActive", new Vector4(0.3647059f,     0.078431375f, 0.078431375f, 0.94509804f) },
            { "Tab", new Vector4(0.23f,                       0.23f,        0.23f,        0.86f) },
            { "TabHovered", new Vector4(0.58371043f,          0.30374074f,  0.30374074f,  0.7647059f) },
            { "TabActive", new Vector4(0.47963798f,           0.15843244f,  0.15843244f,  0.7647059f) },
            { "TabUnfocused", new Vector4(0.068f,             0.10199998f,  0.14800003f,  0.9724f) },
            { "TabUnfocusedActive", new Vector4(0.13599998f,  0.26199996f,  0.424f,       1) },
            { "DockingPreview", new Vector4(0.26f,            0.59f,        0.98f,        0.7f) },
            { "DockingEmptyBg", new Vector4(0.2f,             0.2f,         0.2f,         1) },
            { "PlotLines", new Vector4(0.61f,                 0.61f,        0.61f,        1) },
            { "PlotLinesHovered", new Vector4(1,              0.43f,        0.35f,        1) },
            { "PlotHistogram", new Vector4(0.578199f,         0.16989735f,  0.16989735f,  0.78431374f) },
            { "PlotHistogramHovered", new Vector4(0.7819905f, 0.12230185f,  0.12230185f,  0.78431374f) },
            { "TableHeaderBg", new Vector4(0.19f,             0.19f,        0.2f,         1) },
            { "TableBorderStrong", new Vector4(0.31f,         0.31f,        0.35f,        1) },
            { "TableBorderLight", new Vector4(0.23f,          0.23f,        0.25f,        1) },
            { "TableRowBg", new Vector4(0,                    0,            0,            0) },
            { "TableRowBgAlt", new Vector4(1,                 1,            1,            0.06f) },
            { "TextSelectedBg", new Vector4(0.26f,            0.59f,        0.98f,        0.35f) },
            { "DragDropTarget", new Vector4(1,                1,            0,            0.9f) },
            { "NavHighlight", new Vector4(0.26f,              0.59f,        0.98f,        1) },
            { "NavWindowingHighlight", new Vector4(1,         1,            1,            0.7f) },
            { "NavWindowingDimBg", new Vector4(0.8f,          0.8f,         0.8f,         0.2f) },
            { "ModalWindowDimBg", new Vector4(0.8f,           0.8f,         0.8f,         0.35f) }
        },

        BuiltInColors = new DalamudColors
        {
            DalamudRed          = new Vector4(1f,         0f,     0f,         1f),
            DalamudGrey         = new Vector4(0.7f,       0.7f,   0.7f,       1f),
            DalamudGrey2        = new Vector4(0.7f,       0.7f,   0.7f,       1f),
            DalamudGrey3        = new Vector4(0.5f,       0.5f,   0.5f,       1f),
            DalamudWhite        = new Vector4(1f,         1f,     1f,         1f),
            DalamudWhite2       = new Vector4(0.878f,     0.878f, 0.878f,     1f),
            DalamudOrange       = new Vector4(1f,         0.709f, 0f,         1f),
            DalamudYellow       = new Vector4(1f,         1f,     .4f,        1f),
            DalamudViolet       = new Vector4(0.770f,     0.700f, 0.965f,     1.000f),
            TankBlue            = new Vector4(0f,         0.6f,   1f,         1f),
            HealerGreen         = new Vector4(0f,         0.8f,   0.1333333f, 1f),
            DPSRed              = new Vector4(0.7058824f, 0f,     0f,         1f),
            ParsedGrey          = new Vector4(0.4f,       0.4f,   0.4f,       1f),
            ParsedGreen         = new Vector4(0.117f,     1f,     0f,         1f),
            ParsedBlue          = new Vector4(0f,         0.439f, 1f,         1f),
            ParsedPurple        = new Vector4(0.639f,     0.207f, 0.933f,     1f),
            ParsedOrange        = new Vector4(1f,         0.501f, 0f,         1f),
            ParsedPink          = new Vector4(0.886f,     0.407f, 0.658f,     1f),
            ParsedGold          = new Vector4(0.898f,     0.8f,   0.501f,     1f),
            InfoForeground      = new Vector4(0f,         0.6f,   1f,         1f),
            InfoBackground      = new Vector4(0.2f,       0.45f,  0.6f,       0.4f),
            SuccessForeground   = new Vector4(0f,         0.8f,   0.1333333f, 1f),
            SuccessBackground   = new Vector4(0.3f,       0.6f,   0.35f,      0.4f),
            WarningForeground   = new Vector4(1f,         0.709f, 0f,         1f),
            WarningBackground   = new Vector4(0.75f,      0.65f,  0.3f,       0.4f),
            ErrorForeground     = new Vector4(1f,         0f,     0f,         1f),
            ErrorBackground     = new Vector4(0.7f,       0.3f,   0.3f,       0.4f),
            AttentionForeground = new Vector4(1f,         0.709f, 0f,         1f),
            AttentionBackground = new Vector4(0.75f,      0.65f,  0.3f,       0.4f)
        },

        WindowBlurStrength   = 0.5f,
        WindowBlurTintActive = new Vector4(0.27200785f,  0.06505883f,  0.08736471f,  0.08107843f),
        WindowBlurTint       = new Vector4(0.014018277f, 0.014018136f, 0.014018136f, 0.08339988f),
        WindowBlurLuminosity = Vector4.Zero
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

        model.Alpha                    = style.Alpha;
        model.WindowPadding            = style.WindowPadding;
        model.WindowRounding           = style.WindowRounding;
        model.WindowBorderSize         = style.WindowBorderSize;
        model.WindowTitleAlign         = style.WindowTitleAlign;
        model.WindowMenuButtonPosition = style.WindowMenuButtonPosition;
        model.ChildRounding            = style.ChildRounding;
        model.ChildBorderSize          = style.ChildBorderSize;
        model.PopupRounding            = style.PopupRounding;
        model.PopupBorderSize          = style.PopupBorderSize;
        model.FramePadding             = style.FramePadding;
        model.FrameRounding            = style.FrameRounding;
        model.FrameBorderSize          = style.FrameBorderSize;
        model.ItemSpacing              = style.ItemSpacing;
        model.ItemInnerSpacing         = style.ItemInnerSpacing;
        model.CellPadding              = style.CellPadding;
        model.TouchExtraPadding        = style.TouchExtraPadding;
        model.IndentSpacing            = style.IndentSpacing;
        model.ScrollbarSize            = style.ScrollbarSize;
        model.ScrollbarRounding        = style.ScrollbarRounding;
        model.GrabMinSize              = style.GrabMinSize;
        model.GrabRounding             = style.GrabRounding;
        model.LogSliderDeadzone        = style.LogSliderDeadzone;
        model.TabRounding              = style.TabRounding;
        model.TabBorderSize            = style.TabBorderSize;
        model.ButtonTextAlign          = style.ButtonTextAlign;
        model.SelectableTextAlign      = style.SelectableTextAlign;
        model.DisplaySafeAreaPadding   = style.DisplaySafeAreaPadding;

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
            DalamudRed          = ImGuiColors.DalamudRed,
            DalamudGrey         = ImGuiColors.DalamudGrey,
            DalamudGrey2        = ImGuiColors.DalamudGrey2,
            DalamudGrey3        = ImGuiColors.DalamudGrey3,
            DalamudWhite        = ImGuiColors.DalamudWhite,
            DalamudWhite2       = ImGuiColors.DalamudWhite2,
            DalamudOrange       = ImGuiColors.DalamudOrange,
            DalamudYellow       = ImGuiColors.DalamudYellow,
            DalamudViolet       = ImGuiColors.DalamudViolet,
            TankBlue            = ImGuiColors.TankBlue,
            HealerGreen         = ImGuiColors.HealerGreen,
            DPSRed              = ImGuiColors.DPSRed,
            ParsedGrey          = ImGuiColors.ParsedGrey,
            ParsedGreen         = ImGuiColors.ParsedGreen,
            ParsedBlue          = ImGuiColors.ParsedBlue,
            ParsedPurple        = ImGuiColors.ParsedPurple,
            ParsedOrange        = ImGuiColors.ParsedOrange,
            ParsedPink          = ImGuiColors.ParsedPink,
            ParsedGold          = ImGuiColors.ParsedGold,
            InfoForeground      = ImGuiColors.InfoForeground,
            InfoBackground      = ImGuiColors.InfoBackground,
            SuccessForeground   = ImGuiColors.SuccessForeground,
            SuccessBackground   = ImGuiColors.SuccessBackground,
            WarningForeground   = ImGuiColors.WarningForeground,
            WarningBackground   = ImGuiColors.WarningBackground,
            ErrorForeground     = ImGuiColors.ErrorForeground,
            ErrorBackground     = ImGuiColors.ErrorBackground,
            AttentionForeground = ImGuiColors.AttentionForeground,
            AttentionBackground = ImGuiColors.AttentionBackground
        };

        model.WindowBlurStrength   = WindowSystem.DefaultBackgroundBlurStrength;
        model.WindowBlurTint       = WindowSystem.DefaultBackgroundBlurTint;
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

        style.Alpha                    = this.Alpha;
        style.WindowPadding            = this.WindowPadding;
        style.WindowRounding           = this.WindowRounding;
        style.WindowBorderSize         = this.WindowBorderSize;
        style.WindowTitleAlign         = this.WindowTitleAlign;
        style.WindowMenuButtonPosition = this.WindowMenuButtonPosition;
        style.ChildRounding            = this.ChildRounding;
        style.ChildBorderSize          = this.ChildBorderSize;
        style.PopupRounding            = this.PopupRounding;
        style.PopupBorderSize          = this.PopupBorderSize;
        style.FramePadding             = this.FramePadding;
        style.FrameRounding            = this.FrameRounding;
        style.FrameBorderSize          = this.FrameBorderSize;
        style.ItemSpacing              = this.ItemSpacing;
        style.ItemInnerSpacing         = this.ItemInnerSpacing;
        style.CellPadding              = this.CellPadding;
        style.TouchExtraPadding        = this.TouchExtraPadding;
        style.IndentSpacing            = this.IndentSpacing;
        style.ScrollbarSize            = this.ScrollbarSize;
        style.ScrollbarRounding        = this.ScrollbarRounding;
        style.GrabMinSize              = this.GrabMinSize;
        style.GrabRounding             = this.GrabRounding;
        style.LogSliderDeadzone        = this.LogSliderDeadzone;
        style.TabRounding              = this.TabRounding;
        style.TabBorderSize            = this.TabBorderSize;
        style.ButtonTextAlign          = this.ButtonTextAlign;
        style.SelectableTextAlign      = this.SelectableTextAlign;
        style.DisplaySafeAreaPadding   = this.DisplaySafeAreaPadding;

        foreach (var imGuiCol in Enum.GetValues<ImGuiCol>())
        {
            if (imGuiCol == ImGuiCol.Count)
            {
                continue;
            }

            style.Colors[(int)imGuiCol] = this.Colors[imGuiCol.ToString()];
        }

        this.BuiltInColors?.Apply();
        WindowSystem.DefaultBackgroundBlurStrength   = this.WindowBlurStrength;
        WindowSystem.DefaultBackgroundBlurTint       = this.WindowBlurTint;
        WindowSystem.DefaultBackgroundBlurTintActive = this.WindowBlurTintActive;
        WindowSystem.DefaultBackgroundBlurLuminosity = this.WindowBlurLuminosity;
    }

    /// <inheritdoc/>
    public override void Push()
    {
        this.PushStyleHelper(ImGuiStyleVar.Alpha,               this.Alpha);
        this.PushStyleHelper(ImGuiStyleVar.WindowPadding,       this.WindowPadding);
        this.PushStyleHelper(ImGuiStyleVar.WindowRounding,      this.WindowRounding);
        this.PushStyleHelper(ImGuiStyleVar.WindowBorderSize,    this.WindowBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.WindowTitleAlign,    this.WindowTitleAlign);
        this.PushStyleHelper(ImGuiStyleVar.ChildRounding,       this.ChildRounding);
        this.PushStyleHelper(ImGuiStyleVar.ChildBorderSize,     this.ChildBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.PopupRounding,       this.PopupRounding);
        this.PushStyleHelper(ImGuiStyleVar.PopupBorderSize,     this.PopupBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.FramePadding,        this.FramePadding);
        this.PushStyleHelper(ImGuiStyleVar.FrameRounding,       this.FrameRounding);
        this.PushStyleHelper(ImGuiStyleVar.FrameBorderSize,     this.FrameBorderSize);
        this.PushStyleHelper(ImGuiStyleVar.ItemSpacing,         this.ItemSpacing);
        this.PushStyleHelper(ImGuiStyleVar.ItemInnerSpacing,    this.ItemInnerSpacing);
        this.PushStyleHelper(ImGuiStyleVar.CellPadding,         this.CellPadding);
        this.PushStyleHelper(ImGuiStyleVar.IndentSpacing,       this.IndentSpacing);
        this.PushStyleHelper(ImGuiStyleVar.ScrollbarSize,       this.ScrollbarSize);
        this.PushStyleHelper(ImGuiStyleVar.ScrollbarRounding,   this.ScrollbarRounding);
        this.PushStyleHelper(ImGuiStyleVar.GrabMinSize,         this.GrabMinSize);
        this.PushStyleHelper(ImGuiStyleVar.GrabRounding,        this.GrabRounding);
        this.PushStyleHelper(ImGuiStyleVar.TabRounding,         this.TabRounding);
        this.PushStyleHelper(ImGuiStyleVar.ButtonTextAlign,     this.ButtonTextAlign);
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
