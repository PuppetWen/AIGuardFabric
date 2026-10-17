/**
 * AIGuardFabric domain model — the single source of truth for every type the
 * console renders. Field names mirror the Rust gateway DTOs (`crates/agf-api`)
 * so that swapping the demo dataset for live `/api` responses is a no-op.
 *
 * The declarations live in `./domain/*` and are re-exported here, so every
 * `import type { … } from '@/types/domain'` keeps working unchanged.
 */

export * from './domain/common';
export * from './domain/identity';
export * from './domain/assets';
export * from './domain/governance';
export * from './domain/operations';
