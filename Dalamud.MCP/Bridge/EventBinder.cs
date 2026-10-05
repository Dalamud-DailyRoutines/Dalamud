using System.Diagnostics;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using ModelContextProtocol;

namespace Dalamud;

/// <summary>
/// 把任意托管事件绑定到一个转发器，触发时把实参写成证据。
/// </summary>
internal static class EventBinder
{
    private const int STACK_FRAMES = 6;

    private static readonly MethodInfo RECORD_METHOD = typeof(EventBinder)
        .GetMethod(nameof(RecordFromEvent), BindingFlags.Public | BindingFlags.Static)!;

    /// <summary>
    /// 为事件构造一个与处理器签名一致的委托。
    /// </summary>
    /// <param name="store">观察点仓库。</param>
    /// <param name="observation">观察点。</param>
    /// <param name="eventInfo">事件。</param>
    /// <returns>可直接传给 AddEventHandler 的委托。</returns>
    public static Delegate Bind
    (
        ObservationStore store,
        Observation      observation,
        EventInfo        eventInfo
    )
    {
        var handlerType = eventInfo.EventHandlerType ?? throw new McpException($"事件 {eventInfo.Name} 没有处理器类型。");

        var invoke = handlerType.GetMethod("Invoke") ?? throw new McpException($"事件 {eventInfo.Name} 的处理器类型没有 Invoke。");

        if (invoke.ReturnType != typeof(void))
            throw new McpException($"事件 {eventInfo.Name} 的处理器有返回值，暂不支持订阅。");

        var parameters = invoke.GetParameters()
                               .Select(parameter => Expression.Parameter(parameter.ParameterType, parameter.Name))
                               .ToArray();

        var arguments = Expression.NewArrayInit
        (
            typeof(object),
            parameters.Select(parameter => Expression.Convert(parameter, typeof(object)))
        );

        var body = Expression.Call
        (
            RECORD_METHOD,
            Expression.Constant(store),
            Expression.Constant(observation),
            arguments
        );

        return Expression.Lambda(handlerType, body, parameters).Compile();
    }

    /// <summary>
    /// 事件处理器转发入口。
    /// </summary>
    /// <param name="store">观察点仓库。</param>
    /// <param name="observation">观察点。</param>
    /// <param name="arguments">事件实参。</param>
    public static void RecordFromEvent
    (
        ObservationStore store,
        Observation      observation,
        object?[]        arguments
    )
    {
        var builder = new StringBuilder(128);
        builder.Append("event=").Append(observation.EventName);

        for (var index = 0; index < arguments.Length; index++)
        {
            builder.Append(" arg").Append(index).Append('=');
            builder.Append(ValueFormatter.Format(arguments[index], 1));
        }

        store.Record(observation.Id, "hostevent", builder.ToString(), null, CaptureStack());
    }

    private static string CaptureStack()
    {
        var trace   = new StackTrace(2, false);
        var builder = new StringBuilder(256);

        for (var index = 0; index < trace.FrameCount && index < STACK_FRAMES; index++)
        {
            var method = trace.GetFrame(index)?.GetMethod();
            if (method is null)
                continue;

            if (builder.Length > 0)
                builder.Append(" <- ");

            builder.Append(method.DeclaringType?.Name).Append('.').Append(method.Name);
        }

        return builder.ToString();
    }
}
