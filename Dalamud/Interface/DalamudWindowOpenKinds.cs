namespace Dalamud.Interface;

/// <summary>
/// Enum describing pages the plugin installer can be opened to.
/// </summary>
public enum PluginInstallerOpenKind
{
    /// <summary>
    /// Open to the "All Plugins" page.
    /// </summary>
    AllPlugins,

    /// <summary>
    /// Open to the "Installed Plugins" page.
    /// </summary>
    InstalledPlugins,

    /// <summary>
    /// Open to the "Can be updated" page.
    /// </summary>
    UpdateablePlugins,

    /// <summary>
    /// Open to the "Plugin Changelogs" page.
    /// </summary>
    Changelogs,

    /// <summary>
    /// Open to the "Dalamud Changelogs" page.
    /// </summary>
    DalamudChangelogs,
}

/// <summary>
/// Enum describing tabs the settings window can be opened to.
/// </summary>
public enum SettingsOpenKind
{
    /// <summary>
    /// Open to the "General" page.
    /// </summary>
    General,

    /// <summary>
    /// Open to the "Look &#038; Feel" page.
    /// </summary>
    LookAndFeel,

    /// <summary>
    /// Open to the "Auto Updates" page.
    /// </summary>
    // REGION TODO: 国服 Dalamud 修改
    // AutoUpdates,

    /// <summary>
    /// Open to the "Server Info Bar" page.
    /// </summary>
    ServerInfoBar,

    /// <summary>
    /// Open to the "Badges" page.
    /// </summary>
    Badge,

    /// <summary>
    /// Open to the "Experimental" page.
    /// </summary>
    Experimental,
    
    /// <summary>
    /// Open to the "Plugin" page.
    /// </summary>
    // REGION TODO: 国服 Dalamud 修改
    Plugin,

    /// <summary>
    /// Open to the "About" page.
    /// </summary>
    About,
}
