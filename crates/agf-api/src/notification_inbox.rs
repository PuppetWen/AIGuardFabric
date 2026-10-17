//! Recent tenant notifications with resource permissions and durable personal read markers.
use crate::{middleware::Principal, state::AppState};
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, deterministic_id},
    rbac::SubjectKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const READS: &str = "notification-inbox-reads";
const GROUPS: [&str; 6] = ["alerts", "cases", "findings", "assets", "reports", "settings"];
#[derive(Debug, Default, Serialize, Deserialize)]
struct ReadMarkers {
    ids: Vec<Id>,
}

fn subject_group(subject: &str) -> &str {
    match subject {
        "alert" => "alerts",
        "case" => "cases",
        "finding" => "findings",
        "asset" => "assets",
        "report" => "reports",
        value if value.starts_with("alert-escalation:") => "alerts",
        _ => "settings",
    }
}
fn read_key(p: &Principal) -> DomainResult<Id> {
    if p.subject_kind != SubjectKind::User {
        return Err(DomainError::Forbidden("已读标记需要个人账号".into()));
    }
    let user = p.subject_id.ok_or_else(|| DomainError::Forbidden("个人账号缺少身份".into()))?;
    Ok(deterministic_id(READS, &format!("{}:{}:{user}", p.tenant, p.identity_tenant)))
}
pub(crate) fn can_mark(p: &Principal) -> bool {
    read_key(p).is_ok()
}

pub(crate) async fn list(state: &AppState, p: &Principal) -> DomainResult<Vec<Value>> {
    let groups: Vec<_> = GROUPS.into_iter().filter(|group| p.require(state, group, "read").is_ok()).collect();
    if groups.is_empty() {
        p.require(state, "alerts", "read").map_err(|e| e.error)?;
    }
    let mut rows: Vec<Value> = if let Some(database) = state.store.database() {
        let mut tx = database.db().begin_tenant(p.tenant).await?;
        let values = sqlx::query_scalar("SELECT payload || jsonb_build_object('id',id) FROM console_configurations
            WHERE kind='notification-inbox' AND deleted_at IS NULL AND
            (CASE WHEN payload->>'subject_kind'='alert' OR starts_with(payload->>'subject_kind','alert-escalation:') THEN 'alerts'
              WHEN payload->>'subject_kind'='case' THEN 'cases' WHEN payload->>'subject_kind'='finding' THEN 'findings'
              WHEN payload->>'subject_kind'='asset' THEN 'assets' WHEN payload->>'subject_kind'='report' THEN 'reports'
              ELSE 'settings' END)=ANY($1) ORDER BY created_at DESC,id DESC LIMIT 100")
            .bind(&groups).fetch_all(&mut *tx).await.map_err(|e|agf_storage::map_sqlx_err("notification_inbox",&e))?;
        tx.commit().await?;
        values
    } else {
        let mut values = state.configurations.list::<Value>(p.tenant, "notification-inbox").await?;
        values.retain(|row| groups.contains(&subject_group(row["subject_kind"].as_str().unwrap_or_default())));
        values.sort_by(|a, b| b["at"].as_str().cmp(&a["at"].as_str()));
        values.truncate(100);
        for row in &mut values {
            row["id"] =
                json!(deterministic_id("agf.notification-inbox", row["dedup_key"].as_str().unwrap_or_default()));
        }
        values
    };
    let read: ReadMarkers = match read_key(p) {
        Ok(id) => state.configurations.get(p.tenant, READS, id).await?.unwrap_or_default(),
        Err(_) => ReadMarkers::default(),
    };
    for row in &mut rows {
        row["read"] = json!(read.ids.iter().any(|id| row["id"] == id.to_string()));
        row["can_mark"] = json!(can_mark(p));
    }
    Ok(rows)
}

pub(crate) async fn mark(state: &AppState, p: &Principal, ids: Vec<Id>) -> DomainResult<usize> {
    let key = read_key(p)?;
    if ids.is_empty() || ids.len() > 100 {
        return Err(DomainError::Validation("每次须标记 1..100 条站内消息".into()));
    }
    let visible = list(state, p).await?;
    if ids.iter().any(|id| !visible.iter().any(|row| row["id"] == id.to_string())) {
        return Err(DomainError::NotFound {
            entity: "notification",
            id: "消息不在当前可读的最近 100 条中；请刷新".into(),
        });
    }
    let mut count = 0;
    state
        .configurations
        .mutate::<ReadMarkers, _>(p.tenant, READS, key, |markers| {
            for id in ids {
                if !markers.ids.contains(&id) {
                    markers.ids.push(id);
                    count += 1;
                }
            }
            if markers.ids.len() > 4096 {
                markers.ids.drain(..markers.ids.len() - 4096);
            }
            Ok(())
        })
        .await?;
    Ok(count)
}
