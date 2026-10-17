# 解析模板配置与版本冲突恢复

入口：**接入管理 → 解析器 → 管理解析模板 / 新增解析模板**，控制台地址 `/ingest`。读取模板、预览和历史需要 `parsers:read`；验证、保存、恢复或删除需要 `parsers:write`。接口仍会检查当前租户权限；页面报权限不足时，请向管理员申请所需权限。

## 新建和验证

1. 新增模板，或打开内置系统模板创建副本。系统模板不能直接覆盖，副本使用新 `key`；租户模板创建后不能更改 `key`。
2. 填写 JSON 定义与脱敏样本。选择实际支持的解析引擎、协议、必需字段和映射。可用“生成草案”：离线推断不调用模型；选择模型时样本会经模型网关发送，受数据分级、规则与配额约束。生成草案不是验证成功。
3. 设置优先级与启停状态。数字越小越先匹配；启停只影响当前租户。点击“验证模板”，检查实际输出字段和未命中原因。
4. 核对后点击“创建模板”或“保存新版本”。保存仍会进行真实解析校验；失败时输入保留，不会自动重发。成功后采集与回放使用新版本。在日志源配置选择对应解析器，再用一条新日志核对结果。

## 多人编辑发生 409 冲突

1. 保存、恢复或删除返回版本冲突时，当前输入和原编辑版本保留。再次直接保存仍使用原版本号，不会强制覆盖他人的修改。
2. 点击“加载最新版本进行比较”。这个按钮只读取服务器快照，**不保存、不替换输入，也不修改保存所用版本号**。页面展示定义、样本、优先级和启停状态；左侧完整草稿可选中复制。
3. 比较两侧内容，复制需要保留的本地修改。点击“采用最新内容重新编辑”并确认，才会用服务器快照替换当前输入和编辑基线。之后自行合并需要的改动，重新验证并明确保存。确认替换本身不提交配置。
4. 服务器在比较后仍可能发生变化；下一次保存再次检查版本。若仍冲突，重新读取比较，不要绕过版本条件。
5. 最新模板已删除或暂不可读时，读取失败仍保留草稿，不会自动新建或复活旧模板。复制必要输入，核查权限和模板状态；需要新模板时，关闭当前编辑器，明确新增并选择未占用的新 `key`。

当前草稿只存在本次浏览器编辑中，关闭编辑器或切换组织、退出/重新登录会清空。请先复制需要保留的内容；旧组织、旧登录的延迟请求不会把旧结果显示到新编辑器。

## 历史与删除

“最近 20 个版本”显示已保存的历史。恢复某个旧版本会创建新版本，仍要求当前编辑基线与服务器一致。恢复成功不撤销此前采集的事件。删除会使绑定该模板的日志源停止解析，先把这些源改为有效解析器。

PostgreSQL 模式下，成功的配置变更与审计记录一起提交；审计无法写入时不发布新配置。内存演示模式不能提供重启后的持久配置。历史与审计是已提交变更的证据，不能把页面验证通过当成已经保存。

## English steps

Open **Ingest → Parsers → Manage parser template / New parser template** at `/ingest`. Reading requires `parsers:read`; validation, saving, restoring and deletion require `parsers:write`.

Paste the JSON definition and a redacted sample, set priority and enablement, then validate the actual output. Offline inference makes no model call. Model inference sends the redacted sample through the gateway and does not prove that the resulting draft parses correctly. Explicitly save after reviewing the result; failed saves keep your input.

After HTTP 409, select **Load latest revision to compare**. This is a read only: your draft and its save revision stay unchanged. Copy the edits you need from **Current draft (copyable)**, compare the server definition, sample, priority and enablement, then choose **Adopt latest content and edit again**. Confirming replaces the inputs and editing baseline but saves nothing. Merge your changes, validate again and explicitly save. Further concurrent changes can cause another conflict.

A failed latest read preserves the draft and never recreates a deleted template. Closing the editor or changing organization/sign-in clears this editing session; copy anything you need first. Historical restoration creates a new revision. Rebind sources before deleting a template. In PostgreSQL mode, configuration changes and their success audit commit together; audit failure does not publish the change.
