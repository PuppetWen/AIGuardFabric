# Agent 显式自更新

Agent 提供 `apply-update` 与 `recover-update`。普通 `run` 不会自动下载程序。受监督更新仅支持新 Agent 的 `run` 子命令，省略参数时默认 `run`；`mcp-proxy`、`collect` 等其他入口在任何下载或事务创建之前被拒绝。`check-update` 只输出未验签预览，签名字段非空不代表可信，也不能直接用于安装。

## 安装准备

操作员需独立配置可信 Ed25519 公钥、允许下载的 HTTPS 来源、已有安装目录、已注册的稳定 Agent ID 与资产清单中的当前版本。信任公钥不能从待安装发布清单获取。安装目录及其事务文件是操作员控制的持久化信任边界，其他普通用户不能获得写权限。

发布清单包括版本、灰度百分比与平台资产。每项资产包含 `platform`、`arch`、HTTPS `url`、`sha256` 和非零 `size`。发布工具使用 `release_signing_payload` 生成带域分隔前缀的签名字节，使用独立私钥签名，再将 `ed25519-v1:<key-id>:<base64-signature>` 放入 `signature`。下载器拒绝歧义平台资产、签名错误、未允许来源、重定向、异常编码、大小超限与摘要不符。

可信公钥文件格式：

```json
{"key_id":"release-production","public_key_hex":"<32字节公钥的64位十六进制字符串>"}
```

运行安装前，先通过该 Agent 的服务管理器停止旧进程。更新助手必须从安装目标之外的独立路径运行，不能替换自身。助手只会终止自己创建并持有句柄的新版本子进程，不能替操作员停止其他服务。

在操作员终端配置已有的 `AGF_AGENT_SERVER_URL`、注册凭据与受信任 TLS 配置；不要将凭据放入更新命令行。Windows 示例：

```powershell
& 'D:\OperatorTools\agf-agent-helper.exe' apply-update `
  --manifest 'D:\Release\manifest.json' `
  --trusted-key 'D:\OperatorKeys\release-public-key.json' `
  --install-root 'D:\Agent' --target-name 'agf-agent.exe' `
  --current '<已安装版本>' --agent-id '<稳定注册身份>' `
  --origin 'https://releases.example.com' `
  -- run --data-dir 'D:\Agent\data'
```

如下载源使用企业 CA，增加 `--ca <PEM文件>`。此选项用于发布资产下载；新 Agent 上报平台所需 CA 仍由 `AGF_AGENT_TLS_CA` 配置。发布下载不发送平台令牌或 Cookie，禁用自动代理及重定向。

## 健康确认与恢复

下载、备份和安装采用同一目录的独占更新锁。旧文件与候选程序在替换前逐一验证摘要；事务保存在安装根目录的 `.agf-updates/<transaction>/`，不要随测试缓存清理。

新 Agent 必须在原始 60 秒期限内，使用经过证书验证的 HTTPS 与注册令牌或 mTLS 身份成功发送本轮快照，并持久化队列提交，才能写入绑定事务、随机数与程序摘要的健康回执。空队列或只有本地采集结果不能确认健康。看门狗在初始化本地身份和队列之前启动；助手崩溃时，未确认健康的新进程也会按原始期限自行退出。

启动失败或健康超时后，助手从已校验备份恢复旧程序。损坏、超大或不可读取的健康文件只表示尚未确认健康，不能阻止原始期限届满后的回滚；安装根、权威事务日志和备份的归属校验错误仍硬拒绝。服务管理器需接管回滚后的旧版本启动。回滚目的文件被占用、备份损坏或目标被外部修改时，事务保留失败状态，不覆盖无法归属的文件。事务回执不输出私有随机数或下载地址。

保留原始事务 UUID 后执行恢复：

```powershell
& 'D:\OperatorTools\agf-agent-helper.exe' recover-update `
  --install-root 'D:\Agent' --target-name 'agf-agent.exe' `
  --transaction '<原始事务UUID>'
```

恢复不会再次下载、派发安装、延长原始健康期限或按查询到的 PID 终止进程。`awaiting_health` 与 `rollback_pending` 均表示尚未完成；不能据此开始下一次安装。

## 验证范围

阶段一本地回归覆盖签名及所有关键字段、灰度与 SemVer 排序、真实回环 TLS 下载、精确大小和摘要、并发锁、损坏备份、事务崩溃恢复、受控子进程健康超时，以及真实 Agent 的 TLS 成功、鉴权拒绝和未受信任证书场景。具体通过状态以当前源码对应的执行回执为准。

真实 Windows/Linux/macOS 服务管理器、发布私钥运维、终端批量灰度、系统重启和突然断电后的恢复属于阶段二验证；尚未执行时不得标记通过。该更新器不承诺抵御已控制安装目录或拥有管理员权限的攻击者。
