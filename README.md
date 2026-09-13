# 电话助手 (Telephony Assistant) — vocat plugin

vocat 本身已经有拨号盘、接听/挂断和来电通知。这个插件只补它没有的部分：

- **来电规则** — 有序策略，命中第一条即生效。黑白名单、号码前缀、联系人簿内/外、匿名号码。
- **联系人簿** — 号码到姓名，通知和记录里显示姓名而不是裸号码。
- **语音留言信箱** — 自动接听、播放提示音、录下对方留言、页面里回放和下载。
- **通知模板** — 按事件（来电/拒接/接听/未接/留言/保号）自定义标题与正文，带渲染预览和真实测试推送。
- **保号任务** — 小时级间隔，可选「仅在线路空闲 N 小时时才执行」。
- **SIP 网关** — iPhone 等软话机（Linphone、Sessiontalk 等）注册进来，用 vocat 的 SIM
  拨打和接听电话。拨号由网关转发到 vocat 的通话接口，语音经 RTP/G.711 桥接到模组。

## 0.1.4 修复：服务端模式无法开启

`main.go` 从未注册 `/credentials` 路由——设置页「保存并连接」一直返回 404，服务端模式
实际上无法通过面板开启，SIP 网关因此永远无法启动。0.1.4 已修复并重新验证了完整链路
（登录 vocat → 启动网关 → UDP 监听）。如果你在 0.1.3 上遇到「网关无法启动」，升级即可。

## SIP 网关：让 iPhone 接入

前提：**服务端模式已开启**——网关必须能自己调用 vocat 的通话接口，没有凭据它不会启动。

在插件的「SIP 网关」页签配置：启用、填 SIP 用户名/密码、选择承载通话的设备、监听地址
（默认 `0.0.0.0:5060`，UDP）。保存后立即生效，无需重启插件。

iPhone 端（以 Linphone 为例）：

| 设置项 | 值 |
| --- | --- |
| SIP 服务器 / Domain | 运行插件的主机 IP（如 `192.168.1.10`） |
| 端口 | 监听地址里的端口（默认 `5060`） |
| 传输 | UDP |
| 用户名 / 密码 | 上面配置的 SIP 账号 |

注册成功后面板的「SIP 网关」页签会列出该设备。之后在软话机里拨任意号码即通过 SIM 外呼；
SIM 上有来电时所有已注册的软话机会同时振铃，先接的赢。

安全须知（和网关代码注释一致）：

- SIP 端口**不经过** vocat 的访问控制，鉴权由网关自己实现：digest 认证强制开启，
  另有来源白名单（`allowed_sources`，建议填你手机所在网段）和登录失败锁定。
- 监听 `0.0.0.0` 会暴露到所有网卡。公网暴露的 SIP 端口会在数小时内被扫描，
  被破解意味着别人可以用你的 SIM 打电话。只在内网使用，或把白名单收窄到单个 IP。
- 网关不发送 DTMF：vocat 没有拨号按键通道，SDP 里刻意不声明 `telephone-event`，
  话机会回落到带内音（对语音菜单类系统仍然有效）。

## 两种运行模式，必须先理解这一点

vocat 的插件反向代理会**主动剥掉 session cookie、CSRF token 和 Authorization 头**
（`internal/extensions/manager.go`）。所以插件后端拿不到任何凭据，默认情况下它无法自己
调用 `/calls/answer`。

**面板模式（默认）** — 规则由浏览器里的这个页面执行，用你自己的会话调 vocat 的接口。
关掉页面就失效。不需要任何凭据，风险最低。

**服务端模式（需显式开启）** — 你在「设置」里填 vocat 管理员账号密码，插件后端自己登录
vocat，从而在浏览器关闭时也能拒接、接听和录留言。

服务端模式是**真实的权限提升**：插件获得完整管理员权限。具体防护：

- 密码以 `0600` 权限存在插件数据目录，读取接口永远返回 `********`
- 客户端**强制只连 loopback**，填公网或内网地址会直接拒绝
- 一次登录缓存整个会话周期（vocat 的 bcrypt cost 是 12，每次登录约 200–500ms CPU）
- 遇到 401 自动重登录一次（vocat 在改密码或应用更新时会吊销全部会话）
- 遇到 429 记录 `Retry-After` 并停止尝试 —— vocat 的登录限流键是 **IP + 用户名**，
  和你本人共享，硬撞会把你自己锁在外面 10 分钟

**语音留言只在服务端模式下可用**，因为录音需要后端持有音频 WebSocket，而那需要一个
它在面板模式下没有的会话。面板模式下遇到 voicemail 规则会提示并改为放行。

## 安装

```bash
./build.sh
```

生成两个按架构分开的包：

- `dist/telephony-assistant-0.1.0-linux-arm64.zip` — 用这个，你的服务器是 aarch64
- `dist/telephony-assistant-0.1.0-linux-amd64.zip`

然后 **系统设置 → 插件 → 上传插件包**，可以把脚本打印的 SHA-256 一起填进去让服务端校验。
入口出现在**左侧导航「短信检测」下方**。

> 侧栏位置由清单里的 `contributions[].after` 决定，它必须**精确等于** vocat 某个导航项的
> 键名。原版 vocat 的键只有 `dashboard`、`devices`、`proxy`、`sms`、`automatic-tasks`、
> `logs`、`settings` 七个。写一个不存在的键（例如 `calls`）不会报错，插件条目会**静默消失** ——
> `AuthenticatedShell.tsx` 遍历导航项时一次都匹配不上。

前提：vocat 开启了开发者模式（`sudo vocat develop on` 后重启）。

vocat 不允许覆盖安装，升级要先卸载。卸载会删掉插件的 `data/`，也就是规则、联系人、
留言和凭据。

## 架构

```
浏览器面板 ──fetch──> /api/extensions/telephony-assistant/backend/*  ──> 插件后端
    │                (vocat 反代，剥掉凭据)                              │
    │                                                        服务端模式下自行登录
    └──fetch──> /api/devices/{id}/calls/answer|hangup  (面板模式，用你的会话)
```

## 目录

```
vocat-plugin.json        清单（必须在 ZIP 根目录）
main.go                  后端 HTTP 服务，15 个接口
internal/vocat/          vocat API 客户端：登录、会话、CSRF、401 重登录、限流退避
internal/rules/          来电规则引擎，有序匹配
internal/contacts/       联系人簿与号码归一化
internal/voicemail/      WS 音频桥接、提示音播放、WAV 读写、静音检测
internal/notify/         模板渲染 + webhook/Telegram/PushPlus
internal/store/          配置、留言索引、处理记录（JSON 文件，0600）
internal/engine/         轮询通话、执行规则、保号调度
web/panel.html           界面
web/panel.js             界面逻辑，含面板模式的规则执行
build.sh                 交叉编译并分架构打包
```

面板不用任何依赖：插件页面的 CSP 是 `default-src 'self'; connect-src 'self'`，
任何 CDN、外部字体或远程脚本都会被拦掉。

面板也**不使用 `window.confirm`**：vocat 用
`sandbox="allow-scripts allow-forms allow-same-origin"` 嵌入插件页，这个白名单没有
`allow-modals`，`confirm()` 会立即返回 false 且不弹窗。删除确认是行内按钮。

## 号码匹配

按**后 9 位有效数字**比较，所以 `+447700900123`、`447700900123`、`07700900123`、
`+44 7700 900123` 都视为同一人。短于 9 位的号码（服务号、短代码）整串精确匹配，
不会被长号码的后缀误命中。

## 通知占位符

`{{caller}}` `{{number}}` `{{contact}}` `{{display}}` `{{called}}` `{{device_id}}`
`{{device_name}}` `{{action}}` `{{rule}}` `{{duration}}` `{{recording}}` `{{result}}`
`{{time}}` `{{timestamp}}` `{{event}}`

写错的 `{{名字}}` 会原样保留，这样错误在收到的消息里看得见，而不是变成空白。

插件用自己的推送通道，不复用 vocat 的：vocat 唯一对插件开放的发送路径是设置页的
「测试」接口，正文是硬编码的，而 `GET /api/settings/notifications` 返回的每个密钥都是
`********`。

## vocat 缺失的能力，插件绕不过去

**1. 无法自定义拒接原因。** vocat 对响铃中来电的挂断硬编码为 **SIP 486 Busy Here**
（`internal/vowifi/ims/call_runtime.go:308`），没有 API 能发 603 Decline。

**2. 没有 DTMF。** vocat 全代码库零 DTMF 实现，SDP 里协商了 `telephone-event`
但没有发送路径。按键交互的 IVR 做不了。

**3. 没有语音合成。** 留言提示音只能是你上传的 **8000 Hz 单声道 16 位 WAV**，
放在插件数据目录里，在「语音留言」页填相对路径。格式不符会被拒绝，因为格式不对的
提示音在真实通话里会变成噪音。

**4. 只有 VoWiFi 通道能应用规则。** 蜂窝通道（`transport: "cellular"`）返回的是
AT 命令解析出的整数状态，没有稳定的 call id，规则无法可靠作用其上。

**5. 原版 vocat 没有通话记录页，也没有 `/api/calls/history`。** 插件的「处理记录」
只记录它自己做过的决定（谁打来、命中哪条规则、执行结果），不是 vocat 的通话明细。
留言列表同理，是插件自己的信箱。

插件运行只依赖原版就有的接口：`/api/auth/login`、`/api/auth/session`、`/api/devices`、
`/api/devices/{id}/calls`、`/calls/answer`、`/calls/hangup`、`/calls/media`、`/api/sms/send`。

## 与 vocat 内置自动任务的重叠

vocat 的「自动任务」已经支持按天的 per-ICCID 拨号和短信，并且会自动切 eSIM 配置文件、
强制 IMS 环境、失败重试、事后恢复（`internal/server/automatic_tasks.go`）。

这个插件的保号任务**只做它表达不了的部分**：小时级间隔，以及「线路空闲多久才执行」。
**需要切卡的保号请继续用 vocat 的自动任务**，插件没有重做那套逻辑。

## 测试

```bash
go test ./...
```

7 个包全绿。覆盖：号码归一化与跨格式匹配、规则有序匹配与设备限定、
匿名与陌生号码不重叠、fallback 默认放行、留言 WAV 读写往返与格式校验、
静音门限、模板占位符全替换与未知占位符保留、webhook SSRF 防护、
密码掩码与「保存掩码即保留原值」、留言配额与保留期清理、
凭据只允许 loopback、401 重登录、429 不重试。

后端接口也实测过：规则试算五种号码全部命中预期分支、配置越界值被正确 clamp、
未知 JSON 字段返回 400、方法守卫返回 405、状态文件权限 `0600`、
非 loopback 地址被拒绝且错误如实上报到面板。
