# MSE 专用配置发布操作指南 / Dedicated MSE configuration publication

入口：阿里云接入 → MSE 专用配置发布（`/alicloud?tab=mse-config`）。本指南对应专用发布面板；现有“操作与回执”的原始参数执行器不是此工作流。

## 准备目标

查看、本地 GET 和明确只读观察需要 `alicloud:read`、`policies:read`。生成预览、发送、明确本地恢复及归档另需要 `alicloud:write`。无需 `assets:write`。

先在 MSE 连接配置维护凭据、账号来源与实际网络入口。真实启用连接更换 engine origin 时，在连接配置同次填写新地址和适用的新凭据，或先明确停用后修改；旧凭据不能沿用到新目标，不会自动切换 Mock 或停用。源、目标、模式、填写或清除凭据会清旧 upsert 授权；保存后在专用面板展开“专用 Data ID 目标绑定”重新确认：

1. 提供独立 Nacos engine HTTPS origin，例如自己实例的引擎 origin；不要复制 OpenAPI endpoint、控制台页面或带凭据/路径的 URL。HTTP 只可用于服务端明确授权的字面 loopback 测试 origin。
2. 明确填写地域、实例 ID、Group 和专用 JSON Data ID。不会自动采用 `cn-hangzhou` 或推断引擎地址；原值不会被静默 trim。
3. 明确选择默认 namespace（保存 `namespace_id: ""`），或者填写真实 namespace ID。缺失、空与显示名 `public` 不是同一个概念。
4. 明确确认管理该 Data ID 的内容 MD5 upsert。upsert 允许重建观察后被删除的配置，不保证 update-only。目标、模式、账号来源或凭据变化后重新确认。
5. 保存使用当前连接的 `expected_version`，保留原 OpenAPI endpoint 与其它设置。只有保持目标时保留已存凭据；换 origin 须按前文填写适用新凭据或先明确停用。409 保留草稿与旧版本；“读取最新配置比较”只 GET，只有明确采用才替换草稿和保存版本。

## 隔离 Mock 示例（不代表实云目标）

Mock 只接受以下明确的固定目标。请在隔离环境手工启用连接、勾选 Mock，填写下面字段，明确选择默认 namespace，再确认管理 upsert 并保存。不会自动填表、种数据或请求；首次点明确观察才初始化隔离 Mock 内容。其它目标不会被 Mock 当作存在，真实云须使用自己的 origin 和实例。

```json
{
  "engine_origin": "https://mse-agf-demo.invalid",
  "region_id": "cn-hangzhou",
  "instance_id": "inst-demo",
  "namespace_id": "",
  "config_group": "AGF",
  "config_data_id": "agf-policies.json",
  "config_dialect": "nacos-http-v2-cas"
}
```

若清单没有可选政策，需要另有 `policies:write` 权限：在策略中心 `/policies` 新建独立名称，填写有效条件或代码，明确启用并手工保存。服务端校验、签名后，回发布面板刷新真实政策清单，选择实际版本。隔离试用可使用“告警 / Alert”（服务端 `audit` 动作）与 dry-run；保存已启用政策会影响平台后续请求，不能据此称消费者已加载。政策依赖若缺失先修正，不会使用示例或默认政策代替。

## 观察、预览与一次发布

1. 核对服务端显示的来源摘要、实际 Mock/Live/loopback-test 模式和完整目标。来源摘要是配置身份，不证明已验证实际 RAM 账号或管理员资格。
2. 点“明确读取当前云内容”。Live 先勾选真实只读观察。观察开始与完成时间、MD5、SHA256 和字节数分别显示；0 字节是空内容证据，不代表目标不存在。观察有效 5 分钟。
3. 选择最多 20 条实际已启用、有签名、版本明确的政策。刷新政策清单不会改变已选版本；政策变版后明确取消并重新选择。服务端验证真实签名、编译、配额、模型及 Agent 依赖。合并 Agent 超过 500 或实际依赖 guard 超限直接拒绝，不截断。
4. 点“生成可信预览”。预览不写云，显示确切来源版本、基线 MD5/SHA256/字节、期望包 SHA256/字节，有效 120 秒。首期不返回云原始正文；可另到策略中心查看源政策。
5. 分别确认目标与摘要、MD5 upsert；Live 再确认真实云写。未知旧写还需单独风险确认。点一次新发布，立即保留其 UUID。

预览尝试领取后不能再次发送，即使 HTTP 超时或连接中断也不能证明未被消费。读取原 UUID 回执；需要新写时明确新观察、新预览、新 UUID。没有自动补传或假取消功能。

409 不换草稿基线或自动更新政策版本。先读取原回执，“刷新本地状态比较”只 GET，不查询云。若确实选择最新观察，点“采用最新观察基线”并明确确认后，再准备新的预览。

## 判读回执与恢复

回执保留原目标、来源、配置版本与政策来源，分三个阶段：云写、回读、本地审计发布。只有 `accepted + matched + published + complete` 才验证成功。当前内容匹配不能把原 `unknown` 云写变成成功。

`pending_audit` 表示加密云端证据已暂存，本地审计尚未提交。点“明确本地恢复”并确认，仅完成原本地终态与审计，不取凭据、不调用云端、不重新执行原写。失败保留旧回执。当前配置停用、版本变化、旧调用者过期或原政策变版也不妨碍有权限的当前用户核查与本地恢复。

“原来源仍为当前版本”与原发布完成是两回事。旧来源恢复不能宣称当前策略已经生效。消费者加载始终未知；本功能没有外部 consumer 回执、热加载或策略解释器证明。

输入原 UUID 后明确 GET，或用 `publication_request_id` 页面参数预填 UUID。参数不会自动请求。同租户会话重新打开保留编号，实际切换租户或会话会清旧编号和该参数，其它页面参数保留。原目标只读观察使用服务端提供的当前同目标恢复版本；跨目标、模式或来源不会猜测恢复资格。

## 未知旧写与独立新写

没有已知终态时，先保留原编号并观察，不盲重发。若不接受旧远端请求可能迟到的风险，保持阻断。

若旧本地事实未完成，先按服务端允许动作明确本地恢复；过租约且无 pending 的 started 也可仅记录固定 Unknown 终态与审计，不调用云端。若接受风险，再等待原租约到期，随后获取可信新观察，开始和完成时间都必须晚于到期。明确承认那个未知原编号，再生成独立新预览；发送前再次确认重叠风险。旧远端请求仍可能迟到完成，这不是安全重试，也不能保证旧请求已停止。原 `unknown` 不变为成功，归档也不消除风险事实。

## 可信回滚与明确归档

从同目标、服务端验证成功且保有正文的历史选择回滚来源。前端仅传历史编号，由服务端核验加密正文、目标、hash 和签名。回滚仍是新观察、新预览、新 UUID、新内容 CAS；不降低平台注册表政策版本。原来源可以是旧版，但当前同 ID 政策仍须启用且依赖有效。

最多保留 128 条详细操作或 64 MiB 加密正文，任一达到会拒绝新写。勾选服务端允许归档的终态，核对数量与归档代次，再明确确认。归档会移除所选记录的详细正文和回滚正文，失去这些回滚来源；不改变当前云内容、其它历史或永久原编号。停用连接后仍可本地归档。旧 UUID 的墓碑只读，不会重新派发。409 后重新读取并复核，不能自动换代次重发。

## 验收边界

阶段一提供持久 Mock 和部署授权的 loopback HTTP 验收。Live 实例协议、RAM、网络及消费者加载属于独立验收，不能以 Mock 成功代替。配置了数据库后事实跨实例持久；无数据库模式只限当前进程，不能承诺重启幂等。本功能不提供任意云正文编辑、云删除、APIG 发布、自动补传或 consumer reload。

## English steps

Open Alibaba Cloud → MSE dedicated configuration publication (`/alicloud?tab=mse-config`). Viewing and explicit read-only observation require `alicloud:read` and `policies:read`; preparation, sending, local recovery and archive additionally require `alicloud:write`, without `assets:write`.

1. Maintain credentials and account source in the existing MSE connection configuration. When retargeting an enabled Live engine, save the new origin with appropriate new credentials together, or explicitly disable first. Old credentials are not retained for a new target; no automatic Mock or disable switch occurs. Source, target, mode, supplied or cleared credentials remove old upsert authorization. Then bind the explicit region/instance, namespace, group and dedicated JSON Data ID and reconfirm. The OpenAPI URL is not an engine origin. Explicit default namespace sends an empty string; missing is not default. Save with the current configuration version.
2. Explicitly observe cloud content, confirming Live read-only access when applicable. A zero-byte result is valid empty content, not proof of absence. Observations last five minutes. A local GET refresh does not call the cloud.
3. Select actual enabled, signed policy revisions and prepare a trusted preview. The server validates signatures, compilation and all dependencies. Limits reject excess selections or aggregate Agent IDs without truncation. Compare hashes, bytes and source revisions; raw cloud content is not exposed.
4. Confirm publication and MD5 upsert separately, plus a Live cloud write where required, then send once. Preserve its UUID. An attempted preview cannot be replayed after a lost response. Read the original receipt, then explicitly obtain a new observation and preview for any new write.
5. On HTTP 409, retain the draft, selected revisions and original baseline. GET comparison does not adopt revisions. Explicitly adopt a reviewed observation and reselect changed policy revisions before preparing again.
6. Read the three stages independently: cloud write, readback and local audit publication. Verification requires accepted, matched, published and complete. A matched readback cannot turn an unknown original write into accepted. Consumer loading remains unknown.
7. For pending audit, explicitly recover only local completion and audit. This does not fetch credentials, call the cloud or re-execute the write. Disabled or changed configuration still permits authorized receipt reads, local recovery and archive. Failures retain the old receipt and original source; completion of an old source does not prove current-policy effectiveness.
8. Unknown old writes may finish late. Explicitly recover an incomplete old local fact first when allowed; an expired started fact without pending evidence becomes only a fixed Unknown local terminal state and audit, without a cloud call. To accept an independent new write, then wait for the old lease, obtain an observation that both starts and completes later, acknowledge the old UUID and separately confirm overlap risk at apply. This is not a safe retry and cannot stop the old request.
9. Roll back only retained trusted same-target history. The server uses its original content; the browser supplies only its publication ID. Rollback is a new publication and UUID, not a platform registry downgrade.
10. Explicitly archive reviewed terminal records to free detail capacity. Confirm the count and loss of those rollback contents. The current cloud content, other history, permanent IDs and unknown-risk facts remain. Capture the reviewed archive generation; a conflict requires fresh review rather than automatic retry.

For isolated Mock only, use the exact JSON fields above: origin `https://mse-agf-demo.invalid`, region `cn-hangzhou`, instance `inst-demo`, explicit empty default namespace, group `AGF`, Data ID `agf-policies.json`, dialect `nacos-http-v2-cas`. Manually enable and select Mock, fill the fields, confirm managed upsert and save. This does not auto-fill, seed or request; only explicit observation initializes isolated Mock content. Other targets are not assumed to exist. Use your own actual target for Live.

If there are no selectable policies, a user with the additional `policies:write` permission creates a unique policy at `/policies`, enters valid conditions or code, explicitly enables it and saves manually. The server validates and signs it. Refresh the actual policy list and select its real revision. Use Alert (server action: `audit`) and dry-run for isolated practice; enabled policy saves affect subsequent platform requests without proving consumer loading. Missing dependencies must be fixed rather than replaced by example policies. Existing credentials are retained only while keeping the target; retargeting an origin follows the new-credential/disable steps above.

Use the original UUID or `publication_request_id` URL parameter to prefill recovery; it never queries automatically. Reopening within the same tenant session retains it. Actual tenant or session changes clear the old ID and its parameter while preserving other query parameters. Stage one acceptance covers persistent Mock and authorized loopback tests. Live protocol, RAM, networking and consumer behavior require separate acceptance. Durable cross-instance facts require a configured database; in-memory mode is limited to the current process. No automatic replay, raw cloud editing/deletion or consumer hot loading is promised.
