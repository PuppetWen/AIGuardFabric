//! Assemble the unchanged 0001 SQL bytes before the regular embedded migrations.
//! Splitting its source keeps each reviewed SQL file under 500 lines without changing
//! the SHA-384 checksum already stored by SQLx in existing databases.
use std::{borrow::Cow, sync::LazyLock};

use sqlx::migrate::{Migration, MigrationType, Migrator};

const INITIAL_PARTS: [&str; 4] = [
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/sql/migration_parts/0001_init_01.sql")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/sql/migration_parts/0001_init_02.sql")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/sql/migration_parts/0001_init_03.sql")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/sql/migration_parts/0001_init_04.sql")),
];

/// All migrations, including the byte-identical historical initialization SQL.
pub static MIGRATOR: LazyLock<Migrator> = LazyLock::new(|| {
    let later = sqlx::migrate!("../../deploy/sql/migrations");
    let initial = Migration::new(1, "init".into(), MigrationType::Simple, INITIAL_PARTS.concat().into(), false);
    let mut migrations = Vec::with_capacity(later.iter().count() + 1);
    migrations.push(initial);
    migrations.extend(later.iter().cloned());
    Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: later.ignore_missing,
        locking: later.locking,
        no_tx: later.no_tx,
    }
});
