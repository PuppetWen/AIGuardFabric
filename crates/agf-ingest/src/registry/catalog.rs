//! Validated catalog overlays preserve tenant metadata and runtime counters.
use super::*;

impl ParserRegistry {
    /// Insert a validated parser entity without losing its tenant or enable state.
    ///
    /// # Errors
    /// Invalid definition or expression.
    pub fn upsert(&mut self, parser: Parser) -> DomainResult<()> {
        parser.definition.validate().map_err(|errors| DomainError::Validation(errors.join("; ")))?;
        engine::validate_pattern(&parser.definition).map_err(DomainError::Validation)?;
        self.entries.retain(|old| old.id != parser.id);
        self.entries.push(parser);
        Ok(())
    }

    /// Atomically refresh a previously validated catalog while retaining this process's statistics.
    pub fn refresh_catalog(&mut self, catalog: &Self) {
        let entries = catalog
            .entries
            .iter()
            .cloned()
            .map(|mut next| {
                if let Some(previous) = self.find_id(next.id) {
                    next.success_count = previous.success_count;
                    next.failure_count = previous.failure_count;
                    next.last_used_at = previous.last_used_at;
                }
                next
            })
            .collect();
        self.entries = entries;
        self.invalid.clone_from(&catalog.invalid);
    }
}
