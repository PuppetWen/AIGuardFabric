//! agfctl 入口：解析 → 执行 → 退出码。
//!
//! 本文件只做「进程外壳」该做的事：clap 解析、`.env` 加载、退出码映射。
//! 所有业务逻辑在 `agf_cli` 库里，因此可以被集成测试直接调用而不必起子进程。
//!
//! 退出码契约见 [`agf_cli::exit`]：0 成功 / 1 判定失败 / 2 外部依赖不可用。
//!
//! ```text
//! agfctl healthcheck --url http://127.0.0.1:8080/healthz
//! agfctl rules verify --dir rules
//! agfctl redteam verify --dir redteam --min-cases 200
//! agfctl db check-schema [--url postgres://...]
//! agfctl migrate [--url postgres://...] [--dir deploy/sql/migrations]
//! agfctl genkey --kind jwt|field|admin-password [--out <文件>]
//! agfctl backup --out data/backup/20260101-000000
//! agfctl restore --in data/backup/20260101-000000 --force
//! agfctl airgap bundle --out data/airgap
//! agfctl airgap verify --dir data/airgap
//! agfctl version
//! ```
//!
//! 全局 `--json` 给出机器可读输出；失败信息一律走 stderr。

#![forbid(unsafe_code)]
// 二进制入口的职责就是写 stdout/stderr（这也是唯一允许 `print_*` 的层）
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::io::Write;

use agf_cli::{AppError, Cli};
use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = agf_cli::load_dotenv() {
        let _ = writeln!(std::io::stderr(), "警告: {e}");
    }
    match agf_cli::run(cli).await {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            report(&e);
            std::process::exit(i32::from(e.exit_code()));
        }
    }
}

/// 打印失败原因：结论型错误只打印一句话，意外错误额外给一行归因提示。
fn report(error: &AppError) {
    let mut err = std::io::stderr();
    let _ = writeln!(err, "agfctl: {error}");
    if let AppError::Fatal(inner) = error {
        let mut source: Option<&(dyn std::error::Error + 'static)> = inner.source();
        while let Some(cause) = source {
            let _ = writeln!(err, "  原因: {cause}");
            source = cause.source();
        }
    }
    let _ = err.flush();
}
