# 审计签名检查点协议

本变更仍是候选，尚待编译、严格 Clippy、普通回归和独占 SQL 验收，不表示整个项目或 WP9 已通过。

## 管理审计

服务端每 60 秒遍历已启用租户。工作线程取得既有管理审计追加事务锁，验证完整的已提交哈希链及全部签名检查点，然后使用已配置的 32 字节平台主密钥，为当前已提交前缀签名。没有默认密钥。HMAC-SHA256 封装绑定用途、租户、链、可选 Agent、检查点 ID、计数器、链尾、完整时间戳及前一个签名封装的哈希。

数据库检查点及前序连接先提交，外部见证随后推进。见证必须出现在通过校验的数据库检查点历史中；允许见证滞后的实例保留有效祖先，但此时 `fully_anchored=false`，直到见证覆盖当前检查点。曾被见证的数据库历史缺失时，校验和重新签名均被阻止。数据库事务未提交，见证绝不前移。若事务提交后见证写入失败，不返回成功确认；重试校验已提交的同一检查点并重试见证写入。

`GET /api/v1/audit/verify` 保留既有哈希链字段，并增加 `anchoring`。GET 不创建检查点。`initial_checkpoint_required`、`unsigned_legacy_checkpoints`、`checkpoints_checked`、`latest`、`valid`、`fully_anchored` 和 `durable` 区分历史未锚定状态与受保护前缀。旧无签名行不补签。首个检查点仅认证建立时的前缀，不能证明建立前发生过什么。结构有效但无签名的旧链可以保持 `passed=true`，同时明确 `fully_anchored=false`。

见证属于持久应用数据，位于 `AGF_DATA_DIR/audit-witnesses-v1`，具有精确归属标记、逐链系统锁、16 KiB JSON 大小上限、符号链接及重解析点拒绝、原子替换及文件同步保护。解锁后保留锁文件，避免不同 inode 上的锁竞态。Unix 权限为 0700/0600；Windows 继承运维方控制的数据目录 ACL。部署时须将该目录放在项目持久数据卷内，不能放在编译 target、测试缓存或一次性证据目录中。历史编译及测试清理必须排除生产见证。独占 SQL 夹具使用具有唯一归属的一次性数据目录，仅可清理该夹具的精确根目录。

此机制发现保留见证之后仅针对数据库的替换或删除，不声称抵御同时控制平台主密钥、数据库及受保护见证文件的攻击者。尚未写入见证的提交及崩溃窗口，以及允许的见证滞后，是明确的持久性边界；备份须共同保留数据库与见证。

## Agent MCP 链

`POST /api/v1/runtime/audit/anchors` 仅接受当前认证有效、由管理员绑定到已启用认证租户中真实 Agent 资产的 API Key，且要求 `policies:read`。JWT、未绑定 Key、请求头或正文中的身份提示不构成 Agent 身份。本地生成的 collector ID 不被当作资产 ID 信任。首次空请求从该 Key 的实际绑定初始化租户及 Agent 身份。

链追加锁等待结束后，API 在同一租户事务锁定治理域、当前租户、原已认证 Key、原绑定 Agent 和现有角色约束引用的配置/角色。重新使用生产 CIDR、当前 scopes 及治理交集校验，并在提交前再次核实有效期；不会回用入口 Principal 的旧权限。身份行及约束依赖的共享锁持续到提交，阻止并发吊销、停用、删除、换绑或收缩权限越过已获锁的提交边界。OpenAPI 公开追加请求、签名确认和兼容的管理校验响应，注明仅绑定 Key 的 `policies:read` 和管理读取的 `audit:read`。

已绑定 Agent 使用一条稳定审计链。每次追加最多包含 256 条连续的既有 `AuditLog` 记录，每条最多 16 KiB。平台校验身份、序号、前序签名、全部已存记录及全部检查点前缀，然后在租户事务内原子存储记录及下一个签名检查点。精确重试返回同一检查点；本地状态重置、改变批次、不同 Agent 或租户、断开的前序连接均不能推进审计链。TEXT 载荷保存既有哈希函数使用的 JSON 对象顺序。新表启用 RLS，运行凭据无权 UPDATE 或 DELETE 签名历史。

真实 `agf-agent mcp-proxy` 在 `AGF_DATA_DIR/mcp-audit-journals-v1` 使用有界、单写者持久日志。启动上游进程前先初始化或重放待确认记录。每个真实策略及门控结果均先记日志、上传、取得确认并保存，之后才可返回待转发帧。HTTP、响应格式和传输失败在已初始化日志可用时也记录本地拒绝门控结果。确认失败保留完全相同的待确认记录段，供重启及重试使用。记录仅包含规范 JSON 帧摘要及安全门控元数据，不复制提示词、凭据、工具参数或响应正文。策略允许结果不被描述为上游已执行的证明。

Agent 使用保留的见证校验确认身份、计数器、前序及精确的新链尾。HMAC 校验留在平台；Agent 不接收主密钥，也不自行构造可信公钥。通信信任通道是验证证书的 HTTPS，仅本地测试允许字面环回 HTTP。Agent 拒绝 `durable=false` 确认。离线平台 Mock 存储复用相同校验器及签名，但明确报告临时、非持久状态，不能授权要求持久确认的 Agent 转发。

既有 `agf-runtime` 租户环形缓冲区仍是有界诊断数据，与上述已认证、持久 Agent 决策链不同。不能把按 Agent 过滤共享环形缓冲区，或对缓冲区长度签名，描述成完整 Agent 链。独立进程准入候选在同一 `AssetTransaction` 提交脱敏 management audit，且仅在 `audit_committed=true` 后允许 spawn；集成及验证后，这些已提交记录可由管理工作线程锚定。该接线不使旧环形缓冲区变为持久数据。其他服务端 SDK 路径仍须分别验收，之后才可关闭全部运行时审计范围。

## 尚需完成的验收

普通入口包括 core 检查点模型、storage 签名及见证、API `audit_anchor`、Agent 库 `audit_anchor::tests`、Agent 二进制 `mcp_proxy::tests`。Agent 测试明确使用环回传输夹具；真实密码学由 storage 和实际认证 API 路由测试覆盖。

SQL 入口 `audit_anchor_database` 有九个 ignored 用例，每例必须使用独立的新数据库。精确契约为 `AGF_AUDIT_ANCHOR_DATABASE_OWNER="AIGuardFabric audit anchor SQL <32-lowerhex>"`，数据库名 `agf_requirements_test_anchor_<same-full-uuid>`，字面 `127.0.0.1:5432` URL，匹配的数据库 COMMENT 及 owner，正值且稳定的 OID，以及绝对路径 `AGF_AUDIT_ANCHOR_DATA_DIR`。目录中的 `.runner-owner` 必须包含精确 owner 字节。迁移前及应用连接池建立后分别校验这些条件。runner 或测试均无权使用生产数据库。

原四例覆盖管理首个检查点、重启及全链重算；保留见证时整段数据库审计历史被删除；Agent 记录与检查点一起回滚及新状态精确重放；跨租户 SQL 及 Agent 历史重算。后续 runner 必须绑定最终 Native PASS 和完整源码清单，并使用共享独占 SQL 锁。本候选尚未执行这些测试。

新增五例分别在证明真实路由等待本用例精确 Agent 链锁后，先提交 Key 吊销、租户停用、Agent 删除、绑定解除或 scopes 清空；解除锁后必须 403、零新 entry、原 checkpoint 与持久见证均保持不变。每例仍遵守独占库契约。

## 持久部署与恢复入口

两份Compose现有持久见证绑定、首次归属初始化及备份/恢复合同见 [审计见证部署、备份与恢复](audit-witness-backup-guide.md)。保留现场见证，不能以旧包覆盖；历史未锚定兼容必须明确表达，不能伪造可信检查点。真实备份/恢复及部署验收尚待执行。
