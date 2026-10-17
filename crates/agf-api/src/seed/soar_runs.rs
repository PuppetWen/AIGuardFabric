//! SOAR 剧本执行灌入（自 seed.rs 拆出，逻辑未变）。

use super::*;

// ===========================================================================
// 案件剧本执行（真实 PlaybookEngine）
// ===========================================================================

/// 演示剧本定义（YAML，**合成定义**）。
///
/// 仓库里没有 playbook fixtures（`redteam/playbooks/` 是空目录），因此定义内联在本模块；
/// 但**解析与执行都走 `agf_correlate::playbook` 的真实实现**：
/// `parse_playbooks_yaml` → `PlaybookEngine::validate` → `PlaybookEngine::run`。
/// 动作/通知/审批分别注入该 crate 自带的 `MockActionExecutor` / `MockNotifySink` /
/// `MockApprovalGate`（`TODO(correlate-playbook-actions)`：真实 EDR/IAM/WAF 动作尚未接入）。
const DEMO_PLAYBOOK_YAML: &str = r"
key: demo-contain-high-risk
name: 演示-高危案件自动处置
description: 演示剧本（合成定义）：确认等级 → 隔离 Agent → 通知责任人 → 人工审批 → 打标归档
trigger:
  min_severity: high
steps:
  - name: 确认高危等级
    params:
      condition: 'input.severity_weight >= 8'
  - name: 隔离 Agent
    action: isolate-agent
  - name: 通知责任人
    notify_channel: dingtalk
  - name: 人工审批（不可逆动作前）
    params:
      require_approval: true
  - name: 打标归档
    action: archive
";

/// 对台账里已灌入的案件**真实执行一次演示剧本**，把引擎产出的轨迹存入 [`ApiStore`]。
///
/// ## 真实在哪里
/// - 剧本定义经 `parse_playbooks_yaml` 解析并 `validate`（步骤形态/超时静态校验）；
/// - 执行用 `PlaybookEngine::run`：条件步骤走真实 CEL 求值，动作/通知/审批走注入实现，
///   逐步 `StepTrace`（含 `attempts`/`note`/`error`）由引擎生成；
/// - 存进 `ApiStore` 的是引擎返回的 `PlaybookRun` **原对象**（[`SoarRunRecord::run`]），
///   本函数只补 `id` 与 `started_at` 两个引擎没有的字段。
///
/// ## 降级
/// 没有案件 / 剧本解析失败 / 触发条件不匹配 / 引擎未在一次轮询内就绪 —— 一律 `warn` + 记
/// `skipped`（**不写任何运行记录**），绝不阻断启动、绝不伪造轨迹。
pub(super) fn seed_soar_runs(store: &ApiStore, tenant: TenantId, report: &mut SeedReport) -> DomainResult<()> {
    let owned_runtime = if tokio::runtime::Handle::try_current().is_err() {
        Some(
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .map_err(|error| DomainError::Internal(format!("演示剧本计时器初始化失败：{error}")))?,
        )
    } else {
        None
    };
    let cases = store.case_list(tenant)?;
    if cases.is_empty() {
        skip_soar_runs(report, "台账没有案件，跳过剧本执行（不伪造运行记录）");
        return Ok(());
    }
    let book = match parse_playbooks_yaml(DEMO_PLAYBOOK_YAML) {
        Ok(mut books) if !books.is_empty() => books.remove(0),
        Ok(_) => {
            skip_soar_runs(report, "剧本集为空，跳过剧本执行");
            return Ok(());
        }
        Err(error) => {
            skip_soar_runs(report, &format!("演示剧本解析/校验失败：{error}"));
            return Ok(());
        }
    };

    for case in &cases {
        let run_id = deterministic_id(NS_RUNTIME, &format!("soar-run:{}", case.id));
        if store.soar_run_list(tenant, case.id)?.iter().any(|record| record.id == run_id) {
            report.stat(DS_SOAR_RUNS, SYNTHETIC_SOURCE).skipped += 1;
            continue;
        }
        let trigger = TriggerInput::new(case.severity);
        if !trigger.matches(&book) {
            warn!(dataset = DS_SOAR_RUNS, case = %case.id, severity = case.severity.as_str(), "案件等级低于剧本触发门槛，跳过");
            report.stat(DS_SOAR_RUNS, SYNTHETIC_SOURCE).skipped += 1;
            continue;
        }
        let mut engine = PlaybookEngine::new()
            .with_action_executor(Box::new(MockActionExecutor::new()))
            .with_notifier(Box::new(MockNotifySink::new()))
            .with_approval(Box::new(MockApprovalGate::approved()));
        let domain = case
            .finding_ids
            .iter()
            .filter_map(|id| store.finding_get(tenant, *id).ok().flatten())
            .map(|finding| finding.domain.as_str().to_string())
            .next()
            .unwrap_or_default();
        let ctx = RunContext::new(tenant, case.severity).with_case(case.id).with_domain(domain);
        let started_at = Timestamp::now();
        // Mock steps complete immediately. Synchronous startup tests still need a timer reactor
        // for the engine's execution deadline; never create a nested runtime inside the server.
        let pending = engine.run(&book, &trigger, &ctx, Timestamp::now());
        let result = if let Some(runtime) = &owned_runtime {
            runtime.block_on(pending)
        } else {
            futures::executor::block_on(pending)
        };
        match result {
            Ok(run) => {
                let record = SoarRunRecord { id: run_id, tenant_id: tenant, case_id: case.id, started_at, run };
                let stat = report.stat(DS_SOAR_RUNS, SYNTHETIC_SOURCE);
                settle(store.soar_run_insert(record), DS_SOAR_RUNS, "soar_run_insert", stat)?;
            }
            Err(error) => {
                warn!(dataset = DS_SOAR_RUNS, case = %case.id, error = %error, "演示剧本执行失败，已跳过该案件（降级）");
                report.stat(DS_SOAR_RUNS, SYNTHETIC_SOURCE).errors += 1;
            }
        }
    }
    let stat = report.stat(DS_SOAR_RUNS, SYNTHETIC_SOURCE);
    stat.note = format!(
        "真实执行（agf_correlate::playbook::PlaybookEngine + Mock 动作/通知/审批）：剧本 {} v{}，逐案件轨迹由引擎 StepTrace 投影",
        book.key, book.version
    );
    Ok(())
}

/// 记录一次"剧本执行被跳过"。
fn skip_soar_runs(report: &mut SeedReport, reason: &str) {
    warn!(dataset = DS_SOAR_RUNS, reason, "演示剧本执行已跳过（降级）");
    report.warnings.push(format!("{DS_SOAR_RUNS}：{reason}"));
    let stat = report.stat(DS_SOAR_RUNS, SYNTHETIC_SOURCE);
    stat.skipped += 1;
    stat.note = reason.to_string();
}
