using System.Collections.Generic;
using System.Numerics;

using Dalamud.Bindings.ImGui;
using Dalamud.Interface.Colors;

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
        "DS1H4sIAAAAAAAACpWXXXPaOhCG/8oZXXsYWbblj7umnNNcNJ1Mw5m0vVOMYlSM5QpDknb47x3ZWlsGDMoVoHkfdvVqtV7/QQxl/gx76Allf9A3lPlE//qOMh/P8MFDOSwtUYb1JzdCPItaHZ5FBw89o8z3UAHilRELWGBPZuUnxGl/fUcZbcOsUea3eZRGtzG6ZCSrztPyrLgGMeyoXf2FMtLSCmU+1V+28H8NfNnBlz3KAv35Avt4Nem9nXXhd7+KrVXGzDIdpZfLUq8v+GvTY2louDTx0A+T+iOkrqVzsWVPJV/2CDVE3AJ4FicW8SiqpXy5KYa8ojAJEpzEhvIJDsOQAkxwSH2ss+j/4uNKlEv7H+I0JgmBsD4NfUID4GNKoxh3PJ6FBw/dy3pXj3ggQ4BAniYHD91IteTqxEhsxJ0fXW120ocVW8oXJ+A/xTbcysXHfkpxnMBmiGEC4kc0obYNBr2Ve64s931i0BB2QynsZqA+5I3Y81MohoApQIkumIVoSjtNDDXmG7lvn7FRH8WYtHkEfZRlyeqttaEr3B2vdjdM2cn1lQCbIZb+IVeyLJ/GBBQ57oq8i3WKfFK6axx7piuvhSaZyTOK4IrQKdT1oOBq8Hx9x9S6B8C8tPdiZEYplnxiW6elkEYjZJQatDQ8i8NzHt7smkZWJ2IKQXyIQXrx2LWBSci5ouuYiZxCOgrTEbecje510jcQsMq+OJ3a9STxLIp6yP2yUW0wr5lijRwyC4/N0g60et/WT+Z2GofYnOM5aj8OHvrKt+I3/6RE7WACISPiHRmGY/IdFmpwYRX05XawcL+d5kwXJ5dyqBxoH8E4wv/Vs8x3o6Z2uYFayPu66Fzma1EV94rvBX9x8SsYqH83dfPm3OXvS9l8FhXfujanHnjfxdbYrdg2slBs49BAomNmKtzZprDQs0x3bV1GBAsyz/5Gyapwubp0DH4Wxapx4HAC3NfxHHVhyhjkH8rGZe4hbRD+2jzwkucNt8etS21Fj1dzxYq5kvWCqYI3Vw+5665f2P5WFKvSMuESos/4C9t3w6SoimP2cpbJET0XGwcjA91Y7uSSlR3oRkXkoN8S2IajDC2UrEXOyn8eWJU3O6bekIeW3dTNTrZN+hnYbidDY9O1MT1o50Mt9S8E/URod8ChKRHoY0E/0USWkDu+FDz3un6MTc82hOLabe5kK9cGIxynnp+OVq9PK7EfDSxZOZxIcNxaUtvAjePRVY77gJfMq8YMj+orGf5yOxEYTSwD4VkZ2X8HjwbLQCjBYNAdPLTXcxg+/AVMRvRx/Q8AAA==")!;

    /// <summary>
    /// Gets the standard Dalamud look.
    /// </summary>
    public static StyleModel DalamudClassic { get; } = Deserialize(
        "DS1H4sIAAAAAAAACqWYW3ObOBSA/0qG52yHi0DgtybeNg9tJxNnp5u+ybaCqYnlYuw0zeS/79EVSdg7AechNvicj3OXxGtAgkn0IbwM5sHkNfg3mOT84kF8vl0Gi2CS8RvLYBLyT6qkQiUVfkhB6hEYl0GpZFeKWAUTxD/JXMn/VMqZUoZfQXmtxGol9aSkkJJKhdTGuyt1mXc3Fne3R2V/wc/CrgbsEybslLct3BCP3iudgyBdBs/q+rcy7cV4n1re/+nFJOK3CVH3E3U/kRFl4OhrcE9/t0avQFGEM80s0izPYgyXP8SluEJw+V0EFhhceVrtyLymSwNBUZGFONcUhHOURAlWlBQVIQgkFuV7tVmy56vSEKJQIjLtBhiFcJgpRCQNySzE9aqqlzYhjrjxiQagNCzyUHsSW5q3bLvf2ppG9MF9ltTkAYDfLcAVa5a0MfqdhNCPM/GXK/3E0D392YpADLoECrGk0A6EIvKRooQmT4byqSFP1HZDR0xaASiIiM5BjMM0z+Mj+jfsQBsrl3GcpDE8TXNk9ow3Msqoz/m4aKtD16MynUh701ElRqTbjul91daON647kXAfaTM6ug/wzeCQNC80xuipqIjkxH3MNatrst1ZcRlM+ko3+yvS2D4lmIdThzaShFgjRGRjOyizRQN2zF2ILJNYQ0SCNMMErY/43PBhOLZkHUyvZER/a7cS+YcUDAknI3QK5iVMlon2zkBk+dqQ6xVdrL+SZn3CjFTkq1CAvDfIZnUFTehGZSTgf11w2rjfxVf7tmWbU4lBsm10ejMehCTt6/cyIgWRGcg6fAKD+00sMX7ziEKLdA8m3K0Im7Eu82wX2w0l9mAc3DJS/+yJJDFnDqQZ3ZKGtGzUnO+iY5PO7hsNGtszd3RX/aGfm2o7uOaB5wB8XwYVfYfxPPFCnOqsSHNkyuxhbTXv8El/ZJANbRtg+B7kSVhgbBAxwgk2GyoY73mWFpmL+GfzyBZ7Z7EZvPpZFN8is648OAn/4Q4Yg5qyxbralLcNPVT0eeRwVJC/n7bty1nbvNuatV+qDd2NqzSj7qcauVHJrKiInbpDuKl2LSthn9Opu1bk0hE9GfnOKytOQXqmyAXdsHQLqJEvl3c70zWVE+6crYXAqI1o27BNOX5vYKG+VOWqHb0jFaC70eeC0IN8rNsx8ZGTjp9zZrSmi5bap4z3j8uYd0FDymnDtvekKak2RpSXzLQ4JcXaGbvqvpHDDcSyduI5qPKBIE9Z0IY+6r0mGMC0ehqdlJzvhdmS1JLmogacesDjN34ah9NGMAmmpKpfLu7YvuXdffHXxTVbUvg3J5B1eGkgj7qk53B4xNNuEcFKShcptqTgfcQ7pJb9c7qeCpYU9ewSn73R82hYOdbtKL7JcuPfjGzZ8xSHujBt5qr3xiA78uSqJ2XWHrlLsWT1qxX+RLVcnoz0+oTfYtdipOqO6Ie6cGrcmsf+5seS6nbXUEzeY23j9BudzmmUyBC6wek2Txn/XQ03Y6ETHHjz46UF9jRHnt3tMmGK6KcbJuz7LdluKczNlNbpEXQlCaKw0MDdt/8ADUD9a2sTAAA=")!;

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
        };

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
