use super::*;
use agf_alicloud::agentteams::orchestration::{DefinitionDirection, DefinitionDocument, validate_definition};

fn difference(old: Option<&DefinitionDocument>, desired: &DefinitionDocument) -> DomainResult<model::Difference> {
    let old = old
        .map(|doc| {
            doc.nodes
                .iter()
                .map(|node| Ok((node.node_id.clone(), hash(node)?)))
                .collect::<DomainResult<BTreeMap<_, _>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let new = desired
        .nodes
        .iter()
        .map(|node| Ok((node.node_id.clone(), hash(node)?)))
        .collect::<DomainResult<BTreeMap<_, _>>>()?;
    Ok(model::Difference {
        added: new.keys().filter(|id| !old.contains_key(*id)).cloned().collect(),
        removed: old.keys().filter(|id| !new.contains_key(*id)).cloned().collect(),
        changed: new
            .iter()
            .filter(|(id, value)| old.get(*id).is_some_and(|old| old != *value))
            .map(|(id, _)| id.clone())
            .collect(),
    })
}
pub(super) fn replay(
    rows: &model::Registry,
    actor: Id,
    team: &str,
    input: &model::Input,
) -> DomainResult<Option<model::Intent>> {
    let Some(fact) = rows.intents.get(&input.request_id) else {
        return Ok(None);
    };
    if fact.actor_id != actor || fact.team_name != team || fact.body_hash != hash(&(team, input))? {
        return Err(DomainError::Conflict("原编号已绑定其他主体、Team、动作或正文；请核查原回执".into()));
    }
    Ok(Some(fact.clone()))
}
pub(super) fn prepare(
    rows: &model::Registry,
    current: &source::Current,
    input: &model::Input,
) -> DomainResult<(model::Record, model::Difference)> {
    if rows.tenant.is_some_and(|tenant| tenant != current.source.tenant) || current.source.tenant.as_uuid().is_nil() {
        return Err(invalid());
    }
    let previous = rows.records.get(&current.team.cloud_team_id);
    if input.request_id.is_nil()
        || input.expected_version != previous.map_or(0, |row| row.version)
        || input.configuration_version != current.source.configuration_version
        || input.inventory_fingerprint != current.source.inventory_fingerprint
    {
        return Err(DomainError::Conflict("定义、配置或库存版本已改变；保留草稿，GET 比较后明确采用".into()));
    }
    let changed_source = previous.is_some_and(|row| row.source != current.source);
    if changed_source
        && (!input.confirm_source_change || !matches!(&input.change, model::Change::SaveDefinition { .. }))
    {
        return Err(DomainError::PreconditionFailed(
            "来源已改变；必须明确提交新来源声明并清空旧 Mock 接收侧，不能同步旧定义".into(),
        ));
    }
    let mut record = previous.cloned().unwrap_or_else(|| model::Record {
        team_name: current.team.cloud_team_id.clone(),
        version: 0,
        source: current.source.clone(),
        local: None,
        receiver: None,
        updated_at: Timestamp::now(),
    });
    if changed_source {
        record.receiver = None;
    }
    let (desired, old) = match &input.change {
        model::Change::SaveDefinition { definition } => (definition.clone(), record.local.as_ref()),
        model::Change::Sync { direction: DefinitionDirection::Pull } => (
            record
                .receiver
                .clone()
                .ok_or_else(|| DomainError::PreconditionFailed("Mock 接收侧声明未知；不能把未知当作空图拉取".into()))?,
            record.local.as_ref(),
        ),
        model::Change::Sync { .. } => (
            record
                .local
                .clone()
                .ok_or_else(|| DomainError::PreconditionFailed("请先明确保存应用提供的本地声明".into()))?,
            record.receiver.as_ref(),
        ),
    };
    validate_definition(&desired, &current.team)?;
    let diff = difference(old, &desired)?;
    match &input.change {
        model::Change::SaveDefinition { .. } | model::Change::Sync { direction: DefinitionDirection::Pull } => {
            record.local = Some(desired);
        }
        model::Change::Sync { .. } => {
            record.local = Some(desired.clone());
            record.receiver = Some(desired);
        }
    }
    record.version = input.expected_version.checked_add(1).ok_or_else(invalid)?;
    record.source = current.source.clone();
    record.updated_at = Timestamp::now();
    Ok((record, diff))
}
pub(super) fn commit(
    rows: &mut model::Registry,
    current: &source::Current,
    actor: Id,
    input: &model::Input,
) -> DomainResult<model::Intent> {
    if !input.confirm_application_owned
        || (matches!(&input.change, model::Change::Sync { .. }) && !input.confirm_mock_sync)
    {
        return Err(invalid());
    }
    if rows.intents.len() >= MAX_INTENTS
        || (!rows.records.contains_key(&current.team.cloud_team_id) && rows.records.len() >= MAX_RECORDS)
    {
        return Err(invalid());
    }
    let (record, difference) = prepare(rows, current, input)?;
    let (action, direction) = match &input.change {
        model::Change::SaveDefinition { .. } => ("save_definition", None),
        model::Change::Sync { direction } => ("sync", Some(*direction)),
    };
    let fact = model::Intent {
        tenant: current.source.tenant,
        actor_id: actor,
        request_id: input.request_id,
        team_name: record.team_name.clone(),
        body_hash: hash(&(record.team_name.as_str(), input))?,
        version: record.version,
        source: current.source.clone(),
        action: action.into(),
        direction,
        local_hash: record.local.as_ref().map(hash).transpose()?,
        receiver_hash: record.receiver.as_ref().map(hash).transpose()?,
        local_node_count: record.local.as_ref().map(|doc| doc.nodes.len()),
        receiver_node_count: record.receiver.as_ref().map(|doc| doc.nodes.len()),
        difference,
        committed_at: record.updated_at,
    };
    rows.generation = rows.generation.checked_add(1).ok_or_else(invalid)?;
    rows.records.insert(record.team_name.clone(), record);
    rows.intents.insert(input.request_id, fact.clone());
    Ok(fact)
}
