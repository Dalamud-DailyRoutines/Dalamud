using System;
using System.Collections.Generic;
using Nuke.Common;
using Nuke.Common.Execution;
using Nuke.Common.Git;
using Nuke.Common.IO;
using Nuke.Common.ProjectModel;
using Nuke.Common.Tooling;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Tools.MSBuild;
using Serilog;

[UnsetVisualStudioEnvironmentVariables]
public class DalamudBuild : NukeBuild
{
    /// Support plugins are available for:
    ///   - Microsoft VisualStudio     https://nuke.build/visualstudio
    ///   - JetBrains ReSharper        https://nuke.build/resharper
    ///   - JetBrains Rider            https://nuke.build/rider
    ///   - Microsoft VSCode           https://nuke.build/vscode

    public static int Main() => Execute<DalamudBuild>(x => x.Compile);

    [Parameter("Configuration to build - Default is 'Debug' (local) or 'Release' (server)")]
#if DEBUG
    readonly Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;
#else
    readonly Configuration Configuration = Configuration.Release;
#endif
    
    [Parameter("Whether we are building for documentation - emits generated files")]
    readonly bool IsDocsBuild = false;

    [Solution] Solution Solution;
    [GitRepository] GitRepository GitRepository;

    AbsolutePath DalamudProjectDir => RootDirectory / "Dalamud";
    AbsolutePath DalamudProjectFile => DalamudProjectDir / "Dalamud.csproj";

    AbsolutePath DalamudBootProjectDir => RootDirectory / "Dalamud.Boot";
    AbsolutePath DalamudBootProjectFile => DalamudBootProjectDir / "Dalamud.Boot.vcxproj";
    
    AbsolutePath DalamudCrashHandlerProjectDir => RootDirectory / "DalamudCrashHandler";
    AbsolutePath DalamudCrashHandlerProjectFile => DalamudCrashHandlerProjectDir / "DalamudCrashHandler.vcxproj";

    AbsolutePath InjectorProjectDir => RootDirectory / "Dalamud.Injector";
    AbsolutePath InjectorProjectFile => InjectorProjectDir / "Dalamud.Injector.csproj";
    
    AbsolutePath TestProjectDir => RootDirectory / "Dalamud.Test";
    AbsolutePath TestProjectFile => TestProjectDir / "Dalamud.Test.csproj";

    AbsolutePath ExternalsDir => RootDirectory / "external";
    AbsolutePath CImGuiDir => ExternalsDir / "cimgui";
    AbsolutePath CImGuiProjectFile => CImGuiDir / "cimgui.vcxproj";
    AbsolutePath CImPlotDir => ExternalsDir / "cimplot";
    AbsolutePath CImPlotProjectFile => CImPlotDir / "cimplot.vcxproj";
    AbsolutePath CImGuizmoDir => ExternalsDir / "cimguizmo";
    AbsolutePath CImGuizmoProjectFile => CImGuizmoDir / "cimguizmo.vcxproj";

    AbsolutePath ArtifactsDirectory => RootDirectory / "bin" / Configuration;

    private static AbsolutePath LibraryDirectory => RootDirectory / "lib";

    private static Dictionary<string, string> EnvironmentVariables => new(EnvironmentInfo.Variables);

    private static string ConsoleTemplate => "{Message:l}{NewLine}{Exception}";
    private static bool IsCIBuild => Environment.GetEnvironmentVariable("CI") == "true";

    Target Restore => _ => _
        .Executes(() =>
        {
            DotNetTasks.DotNetRestore(s => s
                .SetProjectFile(Solution)
                .SetProcessAdditionalArguments("--verbosity quiet", MSBUILD_CONSOLE_LOGGER));
        });

    Target CompileCImGui => _ => _
        .Executes(() =>
        {
            // Not necessary, and does not build on Linux
            if (IsDocsBuild)
                return;
            MSBuildTasks.MSBuild(s => s
                .SetTargetPath(CImGuiProjectFile)
#if DEBUG
                .SetProcessToolPath(Environment.GetEnvironmentVariable("MSBuild"))
#endif
                .SetConfiguration(Configuration)
                .SetMaxCpuCount(Environment.ProcessorCount)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargetPlatform(MSBuildTargetPlatform.x64));
        });

    Target CompileCImPlot => _ => _
        .Executes(() =>
        {
            // Not necessary, and does not build on Linux
            if (IsDocsBuild)
                return;
            
            MSBuildTasks.MSBuild(s => s
                .SetTargetPath(CImPlotProjectFile)
#if DEBUG
                .SetProcessToolPath(Environment.GetEnvironmentVariable("MSBuild"))
#endif
                .SetConfiguration(Configuration)
                .SetMaxCpuCount(Environment.ProcessorCount)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargetPlatform(MSBuildTargetPlatform.x64));
        });

    Target CompileCImGuizmo => _ => _
        .Executes(() =>
        {
            // Not necessary, and does not build on Linux
            if (IsDocsBuild)
                return;
            
            MSBuildTasks.MSBuild(s => s
                .SetTargetPath(CImGuizmoProjectFile)
#if DEBUG
                .SetProcessToolPath(Environment.GetEnvironmentVariable("MSBuild"))
#endif
                .SetConfiguration(Configuration)
                .SetMaxCpuCount(Environment.ProcessorCount)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargetPlatform(MSBuildTargetPlatform.x64));
        });

    Target CompileImGuiNatives => _ => _
        .DependsOn(CompileCImGui)
        .DependsOn(CompileCImPlot)
        .DependsOn(CompileCImGuizmo);

    Target CompileDalamud => _ => _
        .DependsOn(Restore)
        .DependsOn(CompileImGuiNatives)
        .Executes(() =>
        {
            DotNetTasks.DotNetBuild(s =>
            {
                s = s
                       .SetProjectFile(DalamudProjectFile)
                       .SetConfiguration(Configuration)
                       .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                       .EnableNoRestore();
                // We need to emit compiler generated files for the docs build, since docfx can't run generators directly
                // TODO: This fails every build after this because of redefinitions...

                // if (IsDocsBuild)
                // { 
                //     Log.Warning("Building for documentation, emitting compiler generated files. This can cause issues on Windows due to path-length limitations");
                //     s = s
                //         .SetProperty("IsDocsBuild", "true");
                // }
                return s;
            });
        });

    Target CompileDalamudBoot => _ => _
        .Executes(() =>
        {
            MSBuildTasks.MSBuild(s => s
                .SetTargetPath(DalamudBootProjectFile)
#if DEBUG
                .SetProcessToolPath(Environment.GetEnvironmentVariable("MSBuild"))
#endif
                .SetMaxCpuCount(Environment.ProcessorCount)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetConfiguration(Configuration));
        });
    
    Target CompileDalamudCrashHandler => _ => _
        .Executes(() =>
        {
            MSBuildTasks.MSBuild(s => s
                                      .SetTargetPath(DalamudCrashHandlerProjectFile)
#if DEBUG
                                      .SetProcessToolPath(Environment.GetEnvironmentVariable("MSBuild"))
#endif
                                      .SetMaxCpuCount(Environment.ProcessorCount)
                                      .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                                      .SetConfiguration(Configuration));
        });

    Target CompileInjector => _ => _
        .DependsOn(Restore)
        .Executes(() =>
        {
            DotNetTasks.DotNetBuild(s => s
                .SetProjectFile(InjectorProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .EnableNoRestore());
        });

    Target SetCILogging => _ => _
        .DependentFor(Compile)
        .OnlyWhenStatic(() => IsCIBuild)
        .Executes(() =>
        {
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console(outputTemplate: ConsoleTemplate)
                .CreateLogger();
        });

    Target Compile => _ => _
    .DependsOn(CompileDalamud)
    .DependsOn(CompileDalamudBoot)
    .DependsOn(CompileDalamudCrashHandler)
    .DependsOn(CompileInjector)
    ;

    Target CI => _ => _
        .DependsOn(Compile)
        .Triggers(Test);

    Target Test => _ => _
        .DependsOn(Compile)
        .Executes(() =>
        {
            DotNetTasks.DotNetTest(s => s
                .SetProjectFile(TestProjectFile)
                .SetConfiguration(Configuration)
                .AddProperty("WarningLevel", "0")
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .EnableNoRestore());
        });

    Target Clean => _ => _
        .Executes(() =>
        {
            MSBuildTasks.MSBuild(s => s
                .SetProjectFile(CImGuiProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargets("Clean"));

            MSBuildTasks.MSBuild(s => s
                .SetProjectFile(CImPlotProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargets("Clean"));

            MSBuildTasks.MSBuild(s => s
                .SetProjectFile(CImGuizmoProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargets("Clean"));

            DotNetTasks.DotNetClean(s => s
                .SetProject(DalamudProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER));

            MSBuildTasks.MSBuild(s => s
                .SetProjectFile(DalamudBootProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargets("Clean"));
            
            MSBuildTasks.MSBuild(s => s
                .SetProjectFile(DalamudCrashHandlerProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER)
                .SetTargets("Clean"));

            DotNetTasks.DotNetClean(s => s
                .SetProject(InjectorProjectFile)
                .SetConfiguration(Configuration)
                .SetProcessAdditionalArguments(MSBUILD_CONSOLE_LOGGER));

            ArtifactsDirectory.CreateOrCleanDirectory();
        });

    #region Constants

    private const string MSBUILD_CONSOLE_LOGGER = "/clp:ErrorsOnly";

    #endregion
}
