//! Tenant-owned parser definitions, samples and bounded immutable revision history.
use crate::state::AppState;
use agf_core::{
    error::{DomainError, DomainResult},
    ids::{Id, TenantId},
    parser::{Parser, ParserDefinition, ParserEngine},
    secret::content_hash,
    time::Timestamp,
};
use agf_ingest::registry::ParserRegistry;
use serde::{Deserialize, Serialize};

pub const KIND: &str = "parser-template";

mod audited;
pub use audited::{delete_audited, save_audited};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub parser: Parser,
    pub sample: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Record {
    pub current: Option<Revision>,
    pub history: Vec<Revision>,
    pub deleted: bool,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub definition: ParserDefinition,
    pub sample: String,
    #[serde(default = "priority")]
    pub priority: u32,
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Required when replacing an existing template, preventing lost edits.
    pub expected_version: Option<u32>,
}
fn priority() -> u32 {
    50
}
fn enabled() -> bool {
    true
}

pub async fn records(state: &AppState, tenant: TenantId) -> DomainResult<Vec<Record>> {
    state.configurations.list(tenant, KIND).await
}
pub async fn registry(state: &AppState, tenant: TenantId) -> DomainResult<ParserRegistry> {
    let mut registry = (*state.parsers).clone();
    for row in records(state, tenant).await? {
        if !row.deleted {
            if let Some(current) = row.current {
                registry.upsert(current.parser)?;
            }
        }
    }
    Ok(registry)
}
pub async fn find(state: &AppState, tenant: TenantId, key: &str) -> DomainResult<Parser> {
    let registry = registry(state, tenant).await?;
    registry
        .find_key(key)
        .or_else(|| Id::parse(key).ok().and_then(|id| registry.find_id(id)))
        .cloned()
        .ok_or_else(|| missing(key))
}
pub fn missing(id: impl ToString) -> DomainError {
    DomainError::NotFound { entity: "parser", id: id.to_string() }
}
pub async fn custom(state: &AppState, tenant: TenantId, id: Id) -> DomainResult<Record> {
    state
        .configurations
        .get::<Record>(tenant, KIND, id)
        .await?
        .filter(|row| !row.deleted && row.current.is_some())
        .ok_or_else(|| missing(id))
}

/// Validate and dry-run before writing. Native plugins remain an operator-installed extension.
pub fn validate(input: &mut Input) -> DomainResult<()> {
    let key = &input.definition.key;
    if key.is_empty() || key.len() > 100 || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(DomainError::Validation("模板 key 须为 1–100 个字母、数字、短横线或下划线".into()));
    }
    if input.sample.is_empty()
        || input.sample.len() > 65_536
        || serde_json::to_vec(&input.definition)?.len() > 65_536
        || input.definition.name.len() > 200
        || input.priority > 100_000
    {
        return Err(DomainError::Validation("定义和样本各限 64 KiB；名称限 200 字节，优先级限 0–100000".into()));
    }
    if matches!(input.definition.engine, ParserEngine::Plugin | ParserEngine::Cel | ParserEngine::AiInferred) {
        return Err(DomainError::Validation("请选择可直接执行的解析引擎；原生插件由管理员在采集器安装".into()));
    }
    input.definition.builtin = false;
    input.definition.sample_fixture.clear();
    input.definition.validate().map_err(|errors| DomainError::Validation(errors.join("; ")))?;
    agf_ingest::engine::validate_pattern(&input.definition).map_err(DomainError::Validation)?;
    let outcome = agf_ingest::engine::parse_with(&input.definition, &input.sample);
    if !outcome.matched || !outcome.derived_errors.is_empty() {
        return Err(DomainError::Validation(format!(
            "样本未通过解析：{}",
            outcome.error.unwrap_or_else(|| outcome.derived_errors.join("; "))
        )));
    }
    Ok(())
}

pub async fn save(state: &AppState, tenant: TenantId, id: Option<Id>, input: Input) -> DomainResult<Record> {
    let (stable_id, input) = prepare(state, id, input).await?;
    state.configurations.mutate(tenant, KIND, stable_id, |row| revise(row, tenant, id, stable_id, input)).await
}

async fn prepare(state: &AppState, id: Option<Id>, mut input: Input) -> DomainResult<(Id, Input)> {
    // Definitions shipped with the application are read-only. Copy under a new key to customize.
    if state.parsers.find_key(&input.definition.key).is_some() {
        return Err(DomainError::Conflict("系统模板只读；请使用新的 key 保存副本".into()));
    }
    input = tokio::task::spawn_blocking(move || {
        validate(&mut input)?;
        Ok::<_, DomainError>(input)
    })
    .await
    .map_err(|_| DomainError::Internal("模板验证任务失败".into()))??;
    let stable_id = agf_ingest::normalize::parser_id_for(&input.definition.key);
    if id.is_some_and(|id| id != stable_id) {
        return Err(DomainError::Validation("模板 key 不可修改；请保存为新模板".into()));
    }
    Ok((stable_id, input))
}

fn revise(row: &mut Record, tenant: TenantId, id: Option<Id>, stable_id: Id, mut input: Input) -> DomainResult<()> {
    if id.is_none() && row.current.is_some() {
        return Err(DomainError::Conflict("模板 key 已存在，请编辑现有模板或使用新 key".into()));
    }
    if id.is_some() && (row.deleted || row.current.is_none()) {
        return Err(missing(stable_id));
    }
    let now = Timestamp::now();
    let version = if let Some(previous) = &row.current {
        if input.expected_version != Some(previous.parser.definition.version) {
            return Err(DomainError::Conflict("模板已被其他操作更新，请重新加载后编辑".into()));
        }
        previous
            .parser
            .definition
            .version
            .checked_add(1)
            .ok_or_else(|| DomainError::Validation("模板版本超出范围".into()))?
    } else {
        1
    };
    input.definition.version = version;
    let parser = Parser {
        id: stable_id,
        tenant_id: tenant,
        content_hash: content_hash(&serde_json::to_string(&input.definition)?),
        definition: input.definition,
        enabled: input.enabled,
        priority: input.priority,
        success_count: 0,
        failure_count: 0,
        last_used_at: None,
        created_at: row.current.as_ref().map_or(now, |r| r.parser.created_at),
        updated_at: now,
    };
    row.history.push(Revision { parser: parser.clone(), sample: input.sample.clone() });
    if row.history.len() > 20 {
        row.history.remove(0);
    }
    row.current = Some(Revision { parser, sample: input.sample });
    row.deleted = false;
    Ok(())
}
