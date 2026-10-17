// New migrations must trigger sqlx::migrate! again on stable Rust.
fn main() {
    println!("cargo:rerun-if-changed=../../deploy/sql/migrations");
    println!("cargo:rerun-if-changed=../../deploy/sql/migration_parts");
}
