//! Offline export check using the same encoder as the report download API.
//! cargo run -p agf-api --example export_report -- input.md output.pdf
use agf_core::{
    ids::TenantId,
    report::{ReportFormat, ReportKind},
    time::TimeRange,
};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    anyhow::ensure!(args.len() == 2, "Usage: export_report input.md output.pdf");
    let input = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    anyhow::ensure!(std::fs::metadata(&input)?.len() <= 2 * 1024 * 1024, "Input exceeds 2 MiB");
    let body = std::fs::read_to_string(input)?;
    let mut report = agf_api::store::new_report(
        TenantId::default_tenant(),
        ReportKind::Custom,
        "Offline export",
        TimeRange::last_day(),
        body,
        None,
    );
    report.format = ReportFormat::Pdf;
    let (bytes, _) = agf_api::report_artifact::encode(&report)?;
    OpenOptions::new().write(true).create_new(true).open(&output)?.write_all(&bytes)?;
    writeln!(std::io::stdout().lock(), "Exported {} bytes to {}", bytes.len(), output.display())?;
    Ok(())
}
