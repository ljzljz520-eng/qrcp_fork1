# 临时自签名 TLS + 二维码指纹确认 实施计划

## Repository Research

当前 qrcp 的传输与安全模型：

- **命令入口**：[send.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/cmd/send.go) / [receive.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/cmd/receive.go) 调 `config.New` → `server.New`，然后把 `srv.SendURL` / `srv.ReceiveURL` 直接用 [qr.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/qr/qr.go) 渲染成二维码。二维码内容就是纯 URL。
- **TLS 现状**：[server.go#L151-L175](file:///Users/kkcarrot/swe-project/qrcp_fork1/server/server.go#L151-L175) 仅依据 `cfg.Secure` 决定 `http/https`；启动时 `ServeTLS(listener, cfg.TlsCert, cfg.TlsKey)`（[server.go#L332-L343](file:///Users/kkcarrot/swe-project/qrcp_fork1/server/server.go#L332-L343)），必须由用户预先准备证书/私钥文件，否则启动即失败。
- **路由**：两个处理器直接注册在全局 `http.DefaultServeMux` 上：
  - `/send/<path>`：GET 直接 `http.ServeFile` 返回文件；用 cookie + `sync.WaitGroup` 把浏览器的并行分块请求关联到首个客户端，传输完成后自动关停。
  - `/receive/<path>`：GET 返回 [pages.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/pages/pages.go) 的 `Upload` 表单；POST 接收 multipart 文件。
- **配置**：[config.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/config/config.go) 的 `Config` 是扁平结构体，viper 读文件 + flag 覆盖；向导 `Wizard` 交互式提问；[config_test.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/config/config_test.go) 用 `reflect.DeepEqual` 全量比较 `Config`，新增零值布尔字段不会破坏现有用例（fixture 不设置即可）。
- **页面模板**：`pages.Upload`、`pages.Done` 两个 Go raw string 模板，经 [server/util.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/server/util.go) 的 `serveTemplate` 渲染。
- Go 版本 1.21（toolchain 1.24.1），标准库 `crypto/ed25519`、`crypto/x509`、`crypto/tls` 均原生支持 Ed25519 自签证书（TLS 1.3），无需新增第三方依赖。

## 总体设计

**身份密钥即证书密钥**：启动时生成一次性 Ed25519 密钥对，直接用它签发自签名 TLS 证书（TLS 1.3）。这样：

- 终端显示的「公钥指纹」= 证书 SubjectPublicKeyInfo 的 SHA-256；
- 二维码携带的「公钥摘要」是同一个值；
- 手机页面显示的短指纹也来自同一个值。

三方可比，终端与手机的指纹一致性即为 TOFU 确认依据；浏览器自身的自签证书警告界面（iOS「显示描述文件」等）也可核对同一证书。

**指纹格式**：

- 完整指纹：`hex(sha256(SPKI DER))`，64 个十六进制字符，放在 URL 查询参数 `fp` 中（二维码仍为普通 https URL，任意扫码器可打开）。
- 短指纹：取完整指纹前 8 字节，格式 `AB:CD:EF:12:34:56:78:90`，终端与手机页面均大字展示。
- 终端额外展示证书 DER 的 `SHA256:` 指纹（浏览器证书查看器同款），供进阶核对。

**确认流程**（仅临时证书模式启用；现有 http 与自带证书 https 行为完全不变）：

1. 扫码打开 `https://<host>/send|receive/<path>?fp=<完整指纹>`，因自签证书浏览器弹警告，用户选择继续（自签场景固有的一步）。
2. 服务端校验 query 中的 `fp` 与本次身份指纹一致：
   - 一致 → 返回确认页，大字显示短指纹 +「与终端核对一致后继续」按钮；
   - 不一致 → 返回红色警告页，不提供继续按钮。
3. 用户点确认 → POST `/confirm/<path>?fp=...`，服务端把该会话标记为已确认，303 重定向回原 URL。
4. 已确认会话：send 才真正下发文件；receive 才展示上传表单/接受 POST。未确认一律拦截。

**会话管理**：首次访问时下发随机 cookie（复用 [util.GetSessionID](file:///Users/kkcarrot/swe-project/qrcp_fork1/util/util.go#L93-L99)），Server 内用 `map[sessionToken]*sessionState{confirmed bool}` + `sync.Mutex` 记录确认状态，支持 `--keep-alive` 下多个手机先后使用。

**关停语义保持**：send 现有「首个 Mozilla 请求承接 WaitGroup 基线槽、并行请求 Add/Done」的机制保留，仅把「首个请求」改为「首个已确认的数据请求」（用 `sync.Once` 承接基线槽）；确认页/确认接口不触碰 WaitGroup，避免展示确认页即触发关停。

## 启用方式

- 新增 flag `--ephemeral`（短选项 `-e`）与配置项 `ephemeral`（环境变量 `QRCP_EPHEMERAL`）：启用一次性 Ed25519 身份 + 自签证书 + 指纹确认，隐含 HTTPS。
- 友好回退：`--secure` 但未提供 `--tls-cert/--tls-key` 时（当前必然启动失败），自动进入 ephemeral 模式并在终端提示。
- 显式提供证书/密钥时路径不变，兼容现有 [mkcert 教程](file:///Users/kkcarrot/swe-project/qrcp_fork1/docs/tutorials/secure-transfers-with-mkcert.md)。

## Files and Modules

- **新增 `identity/identity.go`**
  - `type Identity struct { Signer ed25519.PrivateKey; Public ed25519.PublicKey; Certificate tls.Certificate; CertDER []byte; PublicKeyFingerprint string; CertFingerprint string }`
  - `Generate() (*Identity, error)`：`ed25519.GenerateKey` → x509 模板（随机序列号、NotBefore=now-1h、NotAfter=now+24h、KeyUsageDigitalSignature、ExtKeyUsageServerAuth、CN=`qrcp-ephemeral`，SAN 含 localhost/127.0.0.1/::1 及 bind IP）→ `x509.CreateCertificate` 自签 → 组装 `tls.Certificate`。
  - `PublicKeyFingerprint = sha256(x509.MarshalPKIXPublicKey(pub))` 的 hex；`CertFingerprint = sha256(cert.Raw)` 的 hex。
  - `ShortFingerprint(fp string) string`：前 16 字符按 `XX:XX…` 8 组格式化。
- **新增 `identity/identity_test.go`**：密钥/证书生成成功；重算 SPKI 哈希与指纹一致；用该 `tls.Certificate` 起本地 TLS 握手（`InsecureSkipVerify`），对端证书公钥 SPKI 哈希等于指纹；短指纹格式断言。
- **修改 [pages/pages.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/pages/pages.go)**：新增 `Confirm` 模板（自包含轻量 HTML，不依赖外部资源）：指纹展示区、核对说明、`fp` 不一致时的红色警告且无表单、一致时 POST 表单（按钮文案按下载/上传区分）。
- **修改 [server/server.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/server/server.go)**（核心改动）：
  - `Server` 增加 `Ephemeral bool`、`PublicKeyFingerprint`、`CertFingerprint`、`ShortFingerprint()`，以及 `identity *identity.Identity`、会话表与 mutex、`transferOnce sync.Once`。
  - 路由从全局 `http.DefaultServeMux` 改为每实例 `http.NewServeMux()` 并赋给 `http.Server.Handler`（消除全局状态，顺带可测；`/qr`、`/send/`、`/receive/`、`/confirm/` 均注册其上），处理器行为保持等价。
  - ephemeral 判定后：`identity.Generate()`，证书注入 `TLSConfig.Certificates`；protocol 选 https；`ServeTLS` 在证书已内置时传空路径（Go 在 `len(config.Certificates)>0` 时跳过文件加载）。
  - `SendURL`/`ReceiveURL` 在 ephemeral 模式追加 `?fp=<完整指纹>`。
  - 新增会话辅助：首次访问下发 `Secure; HttpOnly; SameSite=Lax; Path=/` cookie；`isConfirmed(r)`。
  - `/send/<path>`：未确认返回确认页（不碰 WaitGroup）；已确认执行现有 ServeFile 逻辑，Mozilla 非 keep-alive 的计数改为「首个已确认请求经 `transferOnce` 承接基线槽，其余 Add/Done」。
  - `/receive/<path>`：GET 未确认→确认页，已确认→Upload 页；POST 未确认→403，已确认→现有上传逻辑。
  - `/confirm/<path>`：POST；校验会话 cookie 与表单/query 中的 `fp`，通过则置 confirmed 并 303 回原 URL；失败 400。
- **新增 `server/server_test.go`**：bind 127.0.0.1 起 ephemeral 实例，验证：①未带 cookie GET send 返回含短指纹的确认页；②fp 错误返回警告且无确认表单；③POST /confirm（带 cookie、正确 fp）得 303；④同 cookie 再 GET 得文件内容；⑤未确认 POST receive 被 403、确认后 GET 得到上传表单。
- **修改 [application/application.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/application/application.go)**：`Flags` 增加 `Ephemeral bool`。
- **修改 [cmd/qrcp.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/cmd/qrcp.go)**：注册 `--ephemeral`/`-e` 持久 flag。
- **修改 [config/config.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/config/config.go)**：
  - `Config` 增加 `Ephemeral bool`（yaml `ephemeral,omitempty`，零值不破坏 DeepEqual 测试）；
  - 读取 viper `ephemeral` 并接受 flag 覆盖；
  - 判定 `useEphemeral := cfg.Ephemeral || (cfg.Secure && TlsCert=="" && TlsKey=="")`（在 server.New 内统一计算，Config 只承载原始值；自动回退的提示由命令层打印）；
  - 向导 HTTPS 分支增加选择：「临时自签证书（推荐，开箱即用）」/「我自备证书与密钥」，后者走现有 cert/key 提问。
- **修改 [cmd/send.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/cmd/send.go) 与 [cmd/receive.go](file:///Users/kkcarrot/swe-project/qrcp_fork1/cmd/receive.go)**：渲染二维码前，若 ephemeral 则打印说明：已生成临时自签证书、证书 SHA256 指纹、需在手机上核对的短指纹、以及「浏览器可能提示证书不受信任，选择继续后再核对指纹」的提示。

## Implementation Steps

1. 新建 `identity` 包（生成器 + 指纹 + 短格式）及单元测试。
2. `application.Flags`、`config.Config` 增加 `Ephemeral`，完成读取/覆盖与向导选择。
3. `cmd/qrcp.go` 注册 `--ephemeral/-e`。
4. `pages.go` 增加 `Confirm` 模板。
5. 改造 `server/server.go`：实例级 mux → ephemeral 身份/证书装配与 URL 拼接 → 会话表与确认门禁 → `/confirm/` 路由 → send/receive 处理器门禁与 WaitGroup 语义调整。
6. 新增 `server/server_test.go` 端到端门禁测试。
7. `cmd/send.go`、`cmd/receive.go` 打印指纹与操作提示。
8. 全量验证（见下）。

## Dependencies and Considerations

- **零新增第三方依赖**：Ed25519、x509、TLS 1.3 全部使用 Go 标准库。
- **TLS 兼容性**：Ed25519 证书只能协商 TLS 1.3，现代手机（iOS 12+/Android 10+ 的 Safari/Chrome）均支持；现有 `tls.Config` 的 TLS1.2 专用项（CipherSuites 等）对 1.3 连接自动忽略，保持 `MinVersion: TLS1.2`。若需兼容极老客户端，未来可用 `GetCertificate` 按 ClientHello 回退 ECDSA 证书，本次不做。
- **自签证书的浏览器警告无法消除**：指纹确认是带外 TOFU 核对，不替代浏览器点击「继续」；终端提示中明确说明。
- **安全性边界**：指纹不是秘密，放入 URL/二维码可接受；二维码本身在可信屏幕上展示，构成带外信道。真正机密性仍由 TLS 提供，确认环节防止用户在错误的服务器上传输文件。
- **行为兼容**：http 模式与自备证书 https 模式的代码路径保持原样；`--keep-alive`、并行分块下载、cookie 关联、`--browser` 桌面二维码均保留。
- **全局 mux 重构风险**：借重构为实例 mux 消除「一个进程只能有一个 Server」的隐患；通过保持各处理器等价并新增测试覆盖降低回归风险。
- 证书 SAN 加入 bind IP（可解析时）与 localhost，证书有效期 24 小时（会话实际只有几分钟）。

## Validation

- `gofmt -l .` 无输出；`go vet ./...` 通过。
- `go build ./...` 通过；`go test ./...` 全部通过（含现有 config 测试、新增 identity/server 测试）。
- 手动端到端（curl 模拟，`-i lo0 --bind 127.0.0.1`）：
  1. `curl -k -c jar "<sendURL>"` 返回确认页且包含短指纹；
  2. `curl -k -b jar -c jar -X POST "<confirmURL>"` 返回 303；
  3. `curl -k -L -b jar "<sendURL>"` 收到文件内容；
  4. 错误 `fp` 返回警告页且无法确认；
  5. receive 流程：未确认 POST 为 403，确认后 GET 为上传表单。
- 终端目检：启动后打印证书指纹、短指纹与携带 `fp=` 参数的 https 二维码。

## Risks

- **老旧手机不支持 Ed25519 证书握手**：文档/终端提示 TLS 1.3 要求；后续可加 ECDSA 回退。
- **用户跳过指纹核对直接点继续**：与 SSH TOFU 同级的残余风险；UI 上把指纹做大做醒目，警告页禁止一键继续。
- **mux 重构引入回归**：实例 mux + 新增处理器测试 + 手动 curl 全流程验证；diff 中保持原有上传进度条、关停、cookie 逻辑不变。
- **`--secure` 无证书时的行为变化**：由「启动报错」变为「自动临时证书」，属于纯改进且终端有明确提示；显式配置 cert/key 不受影响。
