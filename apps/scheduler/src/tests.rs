//! 由 `main.rs` 拆分：`registry_has_the_eight_catalogued_tasks` 等 6 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn registry_has_the_eight_catalogued_tasks() {
    let registry = Registry::new();
    assert_eq!(registry.tasks.len(), 8);
    let names: Vec<&str> = registry.tasks.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, tasks::TASK_NAMES.to_vec());
    for name in tasks::TASK_NAMES {
        assert!(registry.state(name).is_some(), "{name} 必须在注册表里");
    }
}

#[test]
pub(crate) fn tasks_value_marks_every_task_implemented_without_todo_field() {
    let registry = Registry::new();
    let value = tasks_value(&registry);
    let items = value["tasks"].as_array().expect("tasks 必须是数组");
    assert_eq!(items.len(), 8);
    assert_eq!(value["todo"], 0);
    for item in items {
        assert_eq!(item["status"], "implemented", "{item} 必须标记为 implemented");
        assert!(item.get("todo").is_none(), "不得再暴露 todo 字段：{item}");
        assert!(item["note"].as_str().unwrap_or_default().len() > 10, "note 必须写清做了什么：{item}");
        assert!(!item["requirement"].as_str().unwrap_or_default().is_empty());
    }
}

#[test]
pub(crate) fn metrics_text_covers_every_task_for_both_counters() {
    let registry = Registry::new();
    let (status, headers, body) = metrics_text(Arc::new(registry));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[0].1, "text/plain; version=0.0.4");
    for name in tasks::TASK_NAMES {
        assert!(body.contains(&format!("agf_scheduler_task_runs_total{{task=\"{name}\"}}")), "缺 runs: {name}");
        assert!(body.contains(&format!("agf_scheduler_task_failures_total{{task=\"{name}\"}}")), "缺 failures: {name}");
        assert!(body.contains(&format!("agf_scheduler_task_last_millis{{task=\"{name}\"}}")), "缺 last: {name}");
    }
    assert!(body.contains("# TYPE agf_scheduler_task_runs_total counter"));
}

#[test]
pub(crate) fn metrics_text_reflects_recorded_runs_and_failures() {
    let registry = Registry::new();
    registry.record("cold-archive", true, 12);
    registry.record("cold-archive", false, 34);
    let (_, _, body) = metrics_text(Arc::new(registry));
    assert!(body.contains("agf_scheduler_task_runs_total{task=\"cold-archive\"} 2"));
    assert!(body.contains("agf_scheduler_task_failures_total{task=\"cold-archive\"} 1"));
    assert!(body.contains("agf_scheduler_task_last_millis{task=\"cold-archive\"} 34"));
    // 未执行的任务必须是 0，而不是"缺行"。
    assert!(body.contains("agf_scheduler_task_runs_total{task=\"log-pull\"} 0"));
}

#[test]
pub(crate) fn task_env_helpers_derive_per_task_keys() {
    assert_eq!(task_env_prefix("cold-archive"), "COLD_ARCHIVE");
    assert_eq!(task_env_prefix("alicloud-cms-push"), "ALICLOUD_CMS_PUSH");
    // 未设置环境变量时：默认启用 + 默认间隔（且下限 5s）。
    assert!(task_enabled("rules-regression"));
    assert_eq!(task_period("rules-regression", 15), Duration::from_secs(15));
    assert_eq!(task_period("rules-regression", 1), Duration::from_secs(5));
}

#[test]
pub(crate) fn registry_snapshot_carries_real_counters() {
    let registry = Registry::new();
    registry.record("cold-archive", true, 7);
    registry.record("report-generate", false, 9);
    let snapshot = registry.snapshot();
    assert_eq!(snapshot.len(), 8);
    let cold = snapshot.iter().find(|t| t.name == "cold-archive").expect("cold-archive");
    assert_eq!((cold.runs, cold.failures, cold.last_millis), (1, 0, 7));
    let report = snapshot.iter().find(|t| t.name == "report-generate").expect("report-generate");
    assert_eq!((report.runs, report.failures, report.last_millis), (1, 1, 9));
    assert!(registry.redteam_rate().is_none());
    registry.set_redteam_rate(0.5);
    assert_eq!(registry.redteam_rate(), Some(0.5));
    assert_eq!(registry.rules_count(), None);
    registry.set_rules_count(12);
    assert_eq!(registry.rules_count(), Some(12));
}
