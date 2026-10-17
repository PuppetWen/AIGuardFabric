# 策略中心操作指南 / Policy center guide

入口：`/policies`，展开“策略发布、冲突与恢复指南”。查看、比较、模拟需要 `policies:read`，发布和恢复需要 `policies:write`，删除另外需要 `policies:delete`。

配额处置 `quota` 与限流 `throttle` 为不同动作；仅修改说明等元数据不会转换原动作。人工审批 `approval`、熔断 `circuit-break` 可正常编辑。服务端未知动作显示原值并阻止保存、采纳和恢复，请先核对客户端与服务端版本。

1. 新建时使用当前租户唯一名称，选择条件、动作、优先级和生效拦截点，先检查代码。新建同名返回409，保留草稿，不覆盖已有策略；要编辑已有策略，请从列表打开它。
2. 编辑已有策略时名称不可改。保存以当前核对的真实版本为条件。服务端完成校验、签名和审计后创建新版本。保存已启用策略会在平台后续实际请求中生效；dry-run只观察匹配，不执行处置。
3. 保存、删除或恢复遇409时，复制需要保留的草稿，点击“读取最新版本并比较”。这个GET只展示最新内容，不修改草稿或保存版本。明确确认“采纳最新策略”后替换整个本地草稿，再重新编辑并手动保存。不会自动换版本或重发。
4. 400（非法条件）或404（当前策略已不可读）也保留输入。先检查问题原因；不要通过反复发布同名或假定版本1来绕过冲突。切换租户或重新登录会清理旧草稿和模拟结果，旧请求迟到不会操作新页面。
5. “版本 / Versions”显示可信历史，可展开源码。“模拟当前策略”使用服务端当前策略，不会发布当前样本，也不是验证未保存草稿。核对样本后读取模拟结果。
6. “恢复为新版本”会以当前版本为条件，从所选可信历史复制内容、重新签名并发布一个新版本。历史的启用状态会保留；启用时在平台生效。确认前检查所选历史和当前版本。恢复不是只读预览，旧版本记录不会被抹掉。
7. “删除当前策略”需要独立删除权限和明确确认，版本仍匹配时才移除当前平台策略。冲突不会删除任何新版本。历史列表本身不保证已删除策略还能恢复。

本页操作的是 AIGuardFabric 平台策略。成功保存或恢复不证明云 MSE、云 API 网关、外部代理或调用方已热加载；它们的接入、部署和配置刷新需在对应平台单独核查。

## English

Open `/policies` and expand **Policy publication, conflict and recovery guide**. Reading, comparison and simulation need `policies:read`; publication and restore need `policies:write`; deletion separately needs `policies:delete`.

Quota enforcement (`quota`) and throttling (`throttle`) are distinct actions; metadata-only edits preserve the original action. Manual approval (`approval`) and circuit break (`circuit-break`) are supported. Unknown server actions show their original value and block save, adoption and restore; verify client and server versions first.

1. Create a unique tenant-local name. Select conditions, action, priority and interception points, then check the code. A duplicate name returns HTTP 409 and keeps the draft without overwriting an existing policy. Open an existing row to edit it.
2. Existing names cannot change. Saving uses the reviewed real server revision and creates a new validated, signed and audited revision. An enabled policy affects subsequent actual platform requests; dry-run only observes matches without enforcement.
3. On HTTP 409 from save, delete or restore, copy needed draft changes and **Load latest revision to compare**. This GET does not change the draft or save revision. Explicitly confirm **Adopt latest policy explicitly**, edit the replaced local draft and save manually. No automatic revision change or retry occurs.
4. HTTP 400 and 404 also preserve inputs. Inspect the reason rather than repeatedly publishing the same name or inventing revision 1. A tenant switch or new sign-in clears old drafts and simulation results; late old responses cannot act on the new page.
5. Open **Versions** to expand historical source. **Simulate current policy** evaluates the current server policy, without publishing the sample or validating an unsaved draft.
6. **Restore as new revision** conditionally copies trusted selected history, signs and publishes a new revision, retaining its enabled setting. Enabled content becomes active on the platform. Review both the historical and current revisions before confirming. Restore publishes; old history stays intact.
7. **Delete current policy** needs its separate permission and confirmation. It removes the current platform policy only if the revision still matches. A conflict never deletes a newer revision; history alone does not guarantee restoration of a deleted policy.

These operations manage AIGuardFabric platform policies. Success does not prove cloud MSE, cloud API gateways, external proxies or consumers reloaded them. Verify their integrations, deployments and configuration refresh separately.
