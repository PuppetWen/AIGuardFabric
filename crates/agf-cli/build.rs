//! `agfctl` 的构建脚本：把"编译期已知"的构建元数据注入二进制。
//!
//! ## 为什么需要它
//!
//! `agfctl version` 要回答排障第一问："哪个二进制、哪个目标平台、哪个源码版本"。
//! 此前只有 CI 注入 `AGF_BUILD_GIT_SHA` / `AGF_BUILD_TIME` 时才有值，本地构建一律
//! 显示 `unknown`（见 `docs/pending-verification.md` PV-023）。这里在**构建期**补齐：
//!
//! | 注入变量 | 来源 | 取不到时 |
//! |---|---|---|
//! | `TARGET` | Cargo 传给 build script 的 `TARGET`（crate 本身读不到，必须由这里转注） | `unknown` |
//! | `AGF_BUILD_GIT_SHA` | 已设置的**环境变量优先**（CI 可覆盖），否则 `git rev-parse --short HEAD`（脏工作区追加 `-dirty`） | `unknown` |
//! | `AGF_BUILD_TIME` | 已设置的**环境变量优先**，否则构建时刻（UTC，ISO 8601 秒级） | `unknown` |
//!
//! ## 纪律
//!
//! - **构建期**取值，运行期零外部依赖：`agfctl` 在气隙环境里也不会去调 `git`、不会读时钟。
//! - 任何一步失败都**降级成 `unknown`**，绝不让构建失败（源码包/无 git 环境必须能编）。
//! - 不引入额外 crate：UTC 格式化用手写的 civil-from-days 算法（Howard Hinnant 的经典公式）。

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // `TARGET` 由 Cargo 提供给 build script；crate 源码里 `option_env!("TARGET")` 需要它。
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=TARGET={target}");

    // git 提交：环境变量优先（CI 常见做法），否则问本地 git。
    let git_sha = match std::env::var("AGF_BUILD_GIT_SHA") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => detect_git_sha(),
    };
    println!("cargo:rustc-env=AGF_BUILD_GIT_SHA={git_sha}");

    // 构建时间：环境变量优先，否则用构建时刻（可复现构建时由 CI 注入固定值）。
    let build_time = match std::env::var("AGF_BUILD_TIME") {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => format_utc(SystemTime::now()),
    };
    println!("cargo:rustc-env=AGF_BUILD_TIME={build_time}");

    // 提交号变化后要重新编译，否则版本信息会停在旧提交上。
    // 路径不存在时 Cargo 只是忽略，不影响构建（源码包场景）。
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
}

/// 读取 `git rev-parse --short HEAD`；工作区脏则追加 `-dirty`。
///
/// 任何失败（没装 git、不在仓库里、输出非 UTF-8）都返回 `unknown`。
fn detect_git_sha() -> String {
    let head = match Command::new("git").args(["rev-parse", "--short", "HEAD"]).output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => return "unknown".to_string(),
    };
    if head.is_empty() {
        return "unknown".to_string();
    }
    // 脏标记：有未提交改动时标注，避免拿"提交号"误判产物与源码一致。
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map(|out| out.status.success() && !out.stdout.is_empty())
        .unwrap_or(false);
    if dirty { format!("{head}-dirty") } else { head }
}

/// 把系统时间格式化成 UTC 的 `YYYY-MM-DDTHH:MM:SSZ`。
///
/// 早于 Unix 纪元（系统时钟异常）时返回 `unknown`。
fn format_utc(now: SystemTime) -> String {
    let Ok(since_epoch) = now.duration_since(UNIX_EPOCH) else {
        return "unknown".to_string();
    };
    let secs = since_epoch.as_secs();

    // 手写 civil-from-days：days 自 1970-01-01 起算 → (year, month, day)。
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let secs_of_day = secs % 86_400;
    let (hour, minute, second) = (secs_of_day / 3_600, (secs_of_day % 3_600) / 60, secs_of_day % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}
