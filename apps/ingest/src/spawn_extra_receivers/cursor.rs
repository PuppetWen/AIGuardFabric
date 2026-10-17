//! 游标文件只读校验段（由 `spawn_extra_receivers.rs` 按块拆分，纯搬移、逻辑不变）。
use super::*;

impl ExtraReceiverCtx<'_> {
    /// 游标文件只读校验：把"上次拉到哪里"如实写进 notes（运维排障用，缺失不报错）。
    pub(super) fn report_cursor_files(&mut self) {
        let listeners = &mut *self.listeners;
        for (label, path) in [
            ("对象存储", env_or("AGF_INGEST_OBJECT_PULL_STATE", "data/ingest/object-pull-cursor.json")),
            ("SQL 拉取", env_or("AGF_INGEST_SQL_CURSOR_PATH", "data/ingest/sql-pull-cursor.json")),
            ("Kafka", env_or("AGF_INGEST_KAFKA_CURSOR_PATH", "data/ingest/kafka-cursor.json")),
            ("Pulsar（KoP）", env_or("AGF_INGEST_PULSAR_CURSOR_PATH", "data/ingest/pulsar-cursor.json")),
        ] {
            let path_ref = std::path::Path::new(&path);
            if path_ref.exists() {
                tracing::info!(cursor = %path, "{label} 游标文件存在（进程重启不重复拉取）");
            }
        }
        if let Some(path) = std::env::var("AGF_INGEST_SQL_CURSOR_PATH").ok().filter(|p| !p.trim().is_empty()) {
            if let Some(cursor) = SqlCursorFile::load(std::path::Path::new(&path)) {
                listeners.note(format!("SQL 拉取游标：{cursor}"));
            }
        }
    }
}
