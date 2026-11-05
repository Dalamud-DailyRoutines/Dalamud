# Dalamud MCP

服务运行于游戏进程内，仅在开发者模式启用时监听本机 MCP HTTP 端点。工具接口版本为 3；客户端连接后应加载工具目录，以获取当前参数定义。

## 发现与调用

托管入口从 `service_list` 开始；插件自定义类型可通过 `object_access` 的 `types` 操作搜索。`describe` 只描述元数据，不执行属性
getter，返回字段、属性、方法、重载、事件及进程内成员标识。方法调用优先使用返回的 `m编号`，名称只有在目标唯一时才可调用。

```json
{"action":"describe","root":"service:ClientState","filter":"TerritoryType"}
```

`read` 显式读取属性，默认仅返回浅层结果与可继续访问的对象引用。`paths` 可以在一次框架线程调度内顺序读取多个路径；这不意味着其他线程不会同时改变数据。

```json
{"action":"read","root":"service:ClientState","paths":["IsLoggedIn","TerritoryType","MapId"],"depth":0}
```

`query` 负责集合分页、精确匹配和字段选择。`offset` 针对匹配结果计数，集合在分页期间仍可能变化；单次最多检查 8192 项。

```json
{"action":"query","root":"service:ObjectTable","fields":["Name","ObjectId"],"limit":16,"offset":0}
```

所有方法实参使用 JSON 值。已有托管对象使用 `{"ref":"o编号"}`；空值直接使用 JSON `null`。不支持开放泛型、按引用参数和按引用返回值。

`object_access` 的 `write.value` 是 JSON 文本字符串，例如写入数字 `42` 时传入 `"42"`，写入空值时传入 `"null"`。

原生入口通过 `ffcs_index` 的 `types`、`describe`、`symbols`、`layout` 发现类型、调用签名、地址与字段。`symbols` 中的 `pattern`
表示特征码；方法参数在 `methods` 内。原生调用通过 `ffcs_call` 使用方法标识和实例地址，统一在框架线程执行。

类型参数支持简单名、全名和程序集限定名。名称存在歧义时，可根据错误列出的候选，使用程序集限定名指定目标。

原生指针参数必须显式使用 `{"address":"0x..."}` 或 `{"text":"文本"}`。文本支持 `byte*`、`CStringPointer` 和 `Utf8String*`
；分配的内存会在调用结束或失败时释放，因此目标函数不得保留文本指针。需要保留的内存必须由调用者提供地址。暂不支持超过
Utf8String 内联缓冲容量的借用文本。

## 引用与异步结果

托管对象引用使用有界强引用，同一对象重复读取返回相同编号；引用不会因垃圾回收或其他读取而自动失效。完成操作后使用
`object_access` 的 `release` 显式释放。引用表满时新引用会被拒绝，重启游戏后全部编号失效。值类型按值返回，引用类型的嵌套展开共享节点预算，默认不会隐式读取属性。

返回任务时，结果包含任务引用与状态。使用 `object_access` 的 `task` 操作等待该引用，最长 15
秒；响应区分等待中、完成、取消与异常。取消等待不会取消目标方法已经启动的任务。

```json
{"action":"task","root":"o12","timeoutSeconds":5}
```

## 观察与证据

`observe` 提供 `memwatch`、`hook`、`managedhook`、`hostevent`
。方法观察使用成员标识；事件观察使用源对象引用或服务名及事件名。每个观察点具有有效期、采样间隔和记录上限；到期或达到上限后后台解除观察。默认有效期为
300 秒，最多记录 256 条，最多同时保留 64 个观察点。

原生方法观察记录调用参数和返回值，仅接受基础类型、枚举及指针签名。托管方法观察记录参数、返回值与异常；同一方法的多个观察点共享补丁并独立释放。事件记录结构化实参与简短托管栈。内存观察是轮询比较，不能捕获两次轮询之间恢复原值的短暂变化。

`evidence` 的 `list` 和 `wait` 均从传入游标之后读取。后续请求使用响应中的 `nextCursor`；`wait` 会先检查已经到达的证据，再原子登记等待。最长等待
15 秒。缓冲保留 4096 条记录，`gap` 表示游标之前的部分证据已被淘汰或清空。观察点解除后，尚在缓冲中的证据仍可按其编号读取。

```json
{"action":"wait","observation":"w1","cursor":0,"timeoutSeconds":5,"limit":32}
```

## 内存、数据与输入

`mem_read`、`mem_write` 支持地址或 `p编号` 指针引用；结构化访问支持字段路径、内联数组下标和长度。字符串读取校验地址并限制在
65536 字节以内。地址可读性检查无法阻止其他线程在检查后释放或改变目标。

数值扫描分别保存整数与浮点值，64 位整数保持精确比较。扫描会话最多保留 16 个；不再使用时通过 `drop`
释放。扫描支持请求取消，特征码块边界不会重复返回同一地址。

`data` 提供 `sheets`、`schema`、`rows`、`row`、`search`。`schema` 返回原始列下标、类型和偏移，`row` 直接索引指定行并按列分页；
`search` 的偏移表示已检查的行数，可用 `nextOffset` 连续搜索。原始列没有业务字段名。

## 截图与输入

`capture` 默认抓取新帧，包含游戏和主窗口内的插件界面。`region` 使用结构化矩形，越界直接拒绝。`maxDimension` 默认为 1600，0
表示原尺寸，正值将最长边缩放至指定像素数，最大为 4096。区域截图仅将对应区域复制到 CPU；PNG 编码在渲染回调之外执行。等待渲染最长
5 秒，超时后尚未执行的回调不会继续抓帧。

```json
{"region":{"x":400,"y":200,"width":800,"height":600},"maxDimension":1600}
```

返回的 `screenshot` 是图像引用，坐标原点为该图左上角。再次提供该编号时，`capture`
从缓存图像裁剪和缩放，保持相同拍摄时间；此时区域使用参考图像像素。可连续裁剪，变换保留浮点精度。缓存最多保留 16 张截图，并以
64 MiB 为总字节预算，旧编号会被淘汰。

```json
{"screenshot":"上一响应中的编号","region":{"x":100,"y":60,"width":200,"height":120},"maxDimension":1200}
```

`input` 的 `play` 接收 `actions` 数组，完整验证后依序播放。`target` 为 `plugin` 或 `game`，只向明确选定的目标注入。插件输入在
ImGui 新帧前消费；游戏输入在鼠标和键盘设备更新后覆盖输入缓冲。播放以真实输入帧推进，按下、保持、释放分开执行，不使用固定毫秒休眠。不会激活游戏窗口、移动系统光标或向其他应用发送键鼠消息。

提供 `screenshot` 后，动作中的 `X`、`Y`、`EndX`、`EndY`
直接使用对应图像上的像素；省略编号时使用原始渲染帧像素。尺寸变化使旧截图无法用于输入，必须重新截图。旧图像仍可能因界面布局变化而过时，截图编号不保证目标仍在原位置。

```json
{"action":"play","target":"plugin","screenshot":"截图编号","actions":[{"action":"click","x":260,"y":140},{"action":"key","keys":["CONTROL","A"]},{"action":"text","text":"搜索文本"}]}
```

动作支持 `move`、`click`、`double_click`、`drag`、`scroll`、`key`、`text`、`wait`。`Button` 为 `left`、`right`、`middle`；`Keys` 使用
`VirtualKey` 名称；`Wheel` 使用整数滚动格数，正数向上。游戏键盘仅接受设备缓冲可表示的键码；Unicode 文本目前仅支持插件输入框。
`Frames` 表示保持或运动帧数，默认 2，范围为 2 至 120。鼠标位置可以沿用同一序列内的前一动作，但首次鼠标操作必须明确给出坐标。

```json
{"action":"play","target":"plugin","screenshot":"截图编号","actions":[{"action":"drag","x":100,"y":100,"endX":400,"endY":300,"frames":20},{"action":"scroll","x":500,"y":400,"wheel":-3},{"action":"wait","frames":4}],"region":{"x":200,"y":100,"width":800,"height":600},"maxDimension":1200}
```

默认 `captureAfter=true`，序列完成后返回新截图；`region` 在此使用渲染帧坐标。输入成功而截图失败时返回 `input` 与
`captureError`，不将已执行输入伪装为未执行。`injected=true` 仅表示输入帧已经交付，不证明目标控件已响应。各输入序列串行执行，最长等待播放
15 秒；取消或失败时解除设备挂钩并释放合成按键。游戏停止更新或停止渲染时无法继续按帧播放；工具不会为此切换前台。

`plugin` 当前只针对主游戏交换链内的插件界面；独立系统窗口中的插件界面不在截图及坐标范围内。`command` 在框架线程调用
Dalamud 命令管理器，不向聊天框发送文本。

```json
{"action":"command","command":"/pdr","captureAfter":false}
```

## 操作状态与共享范围

所有工具返回结构化内容及同内容的 JSON 文本，并带操作编号、状态和 `sharedRuntime`。日志在执行前记录 `begin`，结束后记录
`completed` 或 `failed`，可通过 `trace` 按编号查找。`trace` 查询本身不写入流水。

`trace` 先在当前日志文件内执行 `filter` 筛选，再返回最新一页匹配记录，页内按时间顺序排列。`maxLines` 默认 20，最多 100；
`maxCharacters` 限制结果 JSON 的字符数，默认 8192，范围为 2048 至 16384，不含统一响应外层。单条记录超过约 2048 个字符时返回
`truncated`、`originalCharacters` 与 `preview`，完整内容保留在 `file` 指向的日志中。页级 `truncated` 表示本页存在截断预览。
`hasMore=true` 时，将 `nextBefore` 作为下一次请求的 `before` 继续读取更早记录，并保持相同筛选条件。`line` 是当前文件内的行号；日志轮转后应从 `before=0` 重新查询。

```json
{"filter":"操作编号","maxLines":8,"maxCharacters":4096}
```

HTTP 请求具有 25 秒取消期限。尚未开始的框架调度、扫描及异步等待可以响应取消；已经进入的同步托管或原生函数不能强制中断。超时后应先按操作编号检查日志及目标状态，避免重复执行有副作用的方法。

引用、扫描会话、观察点与证据在同一游戏进程内由全部客户端共享，不提供客户端隔离。`clear` 会影响其他客户端。`control`
仅提供线程目录和运行状态，全进程暂停需要使用进程外调试器。
