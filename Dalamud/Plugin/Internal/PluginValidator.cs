using System.Collections.Generic;
using System.Linq;

using Dalamud.Game.Command;
using Dalamud.Plugin.Internal.Types;

namespace Dalamud.Plugin.Internal;

/// <summary>
/// Class responsible for validating a dev plugin.
/// </summary>
internal static class PluginValidator
{
    private static readonly char[] LineSeparator = [' ', '\n', '\r'];

    /// <summary>
    /// Represents the severity of a validation problem.
    /// </summary>
    public enum ValidationSeverity
    {
        /// <summary>
        /// The problem is informational.
        /// </summary>
        Information,

        /// <summary>
        /// The problem is a warning.
        /// </summary>
        Warning,

        /// <summary>
        /// The problem is fatal.
        /// </summary>
        Fatal,
    }

    /// <summary>
    /// Represents a validation problem.
    /// </summary>
    public interface IValidationProblem
    {
        /// <summary>
        /// Gets the severity of the validation.
        /// </summary>
        ValidationSeverity Severity { get; }

        /// <summary>
        /// Compute the localized description of the problem.
        /// </summary>
        /// <returns>Localized string to be shown to the developer.</returns>
        string GetLocalizedDescription();
    }

    /// <summary>
    /// Check for problems in a plugin.
    /// </summary>
    /// <param name="plugin">The plugin to validate.</param>
    /// <returns>An list of problems.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the plugin is not loaded. A plugin must be loaded to validate it.</exception>
    public static IReadOnlyList<IValidationProblem> CheckForProblems(LocalDevPlugin plugin)
    {
        var problems = new List<IValidationProblem>();

        if (!plugin.IsLoaded)
            throw new InvalidOperationException("插件未加载时无法检测开发问题。");

        if (!plugin.DalamudInterface!.LocalUiBuilder.HasConfigUi)
            problems.Add(new NoConfigUiProblem());

        if (!plugin.DalamudInterface.LocalUiBuilder.HasMainUi)
            problems.Add(new NoMainUiProblem());

        var cmdManager = Service<CommandManager>.Get();

        foreach (var cmd in cmdManager.GetHandlersByAssemblyName(plugin.InternalName).Where(c => c.Key.CommandInfo.ShowInHelp))
        {
            if (string.IsNullOrEmpty(cmd.Key.CommandInfo.HelpMessage))
                problems.Add(new CommandWithoutHelpTextProblem(cmd.Value));
        }

        if (plugin.Manifest.Tags == null || plugin.Manifest.Tags.Count == 0)
            problems.Add(new NoTagsProblem());

        if (string.IsNullOrEmpty(plugin.Manifest.Description) || plugin.Manifest.Description.Split(LineSeparator, StringSplitOptions.RemoveEmptyEntries).Length <= 1)
            problems.Add(new NoDescriptionProblem());

        if (string.IsNullOrEmpty(plugin.Manifest.Punchline))
            problems.Add(new NoPunchlineProblem());

        if (string.IsNullOrEmpty(plugin.Manifest.Name))
            problems.Add(new NoNameProblem());

        if (string.IsNullOrEmpty(plugin.Manifest.Author))
            problems.Add(new NoAuthorProblem());

        if (plugin.IsOutdated)
            problems.Add(new WrongApiLevelProblem());

        if (plugin.InternalName == "SamplePlugin")
            problems.Add(new InternalNameIsSamplePluginProblem());

        return problems;
    }

    /// <summary>
    /// Representing a problem where the plugin does not have a config UI callback.
    /// </summary>
    public class NoConfigUiProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Warning;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "未注册配置界面回调。若有设置界面，可注册 UiBuilder.OpenConfigUi 以便于外部打开。";
    }

    /// <summary>
    /// Representing a problem where the plugin does not have a main UI callback.
    /// </summary>
    public class NoMainUiProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Warning;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "未注册主界面回调。若有主界面，可注册 UiBuilder.OpenMainUi 以便于外部打开。";
    }

    /// <summary>
    /// Representing a problem where a command does not have a help text.
    /// </summary>
    /// <param name="commandName">Name of the command.</param>
    public class CommandWithoutHelpTextProblem(string commandName) : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Fatal;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => $"命令 {commandName} 未配置帮助消息。";
    }

    /// <summary>
    /// Representing a problem where a plugin does not have any tags in its manifest.
    /// </summary>
    public class NoTagsProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Information;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "清单文件中未配置任何标签。";
    }

    /// <summary>
    /// Representing a problem where a plugin does not have a description in its manifest.
    /// </summary>
    public class NoDescriptionProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Information;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "清单文件中未配置描述，或描述过于简略。";
    }

    /// <summary>
    /// Representing a problem where a plugin has no punchline in its manifest.
    /// </summary>
    public class NoPunchlineProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Information;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "清单文件中未配置标语。";
    }

    /// <summary>
    /// Representing a problem where a plugin has no name in its manifest.
    /// </summary>
    public class NoNameProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Fatal;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "清单文件中未配置名称。";
    }

    /// <summary>
    /// Representing a problem where a plugin has no author in its manifest.
    /// </summary>
    public class NoAuthorProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Fatal;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "清单文件中未配置作者。";
    }

    /// <summary>
    /// Representing a problem where a plugin has an outdated API level.
    /// </summary>
    public class WrongApiLevelProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Fatal;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "指向了过时的 API 等级。请更新 DalamudPackager 或 Dalamud.NET.Sdk。";
    }

    /// <summary>
    /// Representing a problem where a plugin has no author in its manifest.
    /// </summary>
    public class InternalNameIsSamplePluginProblem : IValidationProblem
    {
        /// <inheritdoc/>
        public ValidationSeverity Severity => ValidationSeverity.Fatal;

        /// <inheritdoc/>
        public string GetLocalizedDescription() => "内部名称仍为“SamplePlugin”。若需要对外发布，请更改内部名称。";
    }
}
