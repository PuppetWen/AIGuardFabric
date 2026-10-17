//! A native ingest batch stores raw evidence and normalized events in one tenant transaction.
use super::*;

/// One prepared input and its optional normalized event (absent for a deduplicated input).
#[derive(Debug, Clone)]
pub struct IngestWrite {
    /// Raw evidence with its final parser status and event reference.
    pub raw: RawLog,
    /// Event to store alongside the raw record.
    pub event: Option<Event>,
}

pub(super) fn validate(items: &[IngestWrite]) -> DomainResult<()> {
    let Some(first) = items.first() else { return Ok(()) };
    for item in items {
        if item.raw.tenant_id != first.raw.tenant_id
            || item.event.as_ref().is_some_and(|event| {
                event.tenant_id != item.raw.tenant_id
                    || event.source_id != item.raw.source_id
                    || Some(event.id) != item.raw.event_id
            })
        {
            return Err(DomainError::Validation(
                "Ingest batch has inconsistent tenant, source or event identity".into(),
            ));
        }
    }
    Ok(())
}

pub(super) async fn persist_sql(
    store: &agf_storage::Store,
    items: &[IngestWrite],
    outbox: bool,
) -> DomainResult<usize> {
    validate(items)?;
    let Some(first) = items.first() else { return Ok(0) };
    let tenant = first.raw.tenant_id;
    let items = items.to_vec();
    store
        .with_tenant(tenant, move |tx| {
            Box::pin(async move {
                let (raws, events): (Vec<_>, Vec<_>) = items.into_iter().map(|item| (item.raw, item.event)).unzip();
                let events: Vec<_> = events.into_iter().flatten().collect();
                agf_storage::repository::EventRepo::insert_raw_batch(tx, &raws).await?;
                let count = agf_storage::repository::EventRepo::insert_batch(tx, &events).await?;
                if outbox {
                    // Three binds per row; match the repository's bounded chunk size.
                    for chunk in events.chunks(512) {
                        let payloads: Vec<_> = chunk.iter().map(serde_json::to_value).collect::<Result<_, _>>()?;
                        let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                            "INSERT INTO event_delivery_outbox (tenant_id,event_id,payload) ",
                        );
                        query.push_values(chunk.iter().zip(payloads), |mut row, (event, payload)| {
                            row.push_bind(event.tenant_id.as_uuid()).push_bind(event.id.as_uuid()).push_bind(payload);
                        });
                        query.push(" ON CONFLICT (tenant_id,event_id) DO NOTHING");
                        query
                            .build()
                            .execute(&mut **tx)
                            .await
                            .map_err(|error| agf_storage::map_sqlx_err("enqueue_events", &error))?;
                    }
                }
                Ok(count)
            })
        })
        .await
}
