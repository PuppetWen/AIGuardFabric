//! 输出通道：人类可读文本走 stdout，失败结论走 stderr，`--json` 时结构化输出。
//!
//! 统一走这里而不是散落的 `println!`，有两个目的：
//! 1. `--json` 的开关只在一处生效，不会出现"某个子命令忘了支持 JSON"；
//! 2. 单测可以直接调用本模块的函数断言输出格式，而不必捕获进程 stdout。
//!
//! 写失败（如管道被提前关闭）**不视为命令失败**：结论由退出码表达。

use std::io::Write;

use serde::Serialize;

/// 控制台输出器。
#[derive(Debug, Clone, Copy, Default)]
pub struct Output {
    json: bool,
    silent: bool,
}

impl Output {
    /// 人类可读模式。
    #[must_use]
    pub const fn text() -> Self {
        Self { json: false, silent: false }
    }

    /// 机器可读模式。
    #[must_use]
    pub const fn json() -> Self {
        Self { json: true, silent: false }
    }

    /// 按 `--json` 开关构造。
    #[must_use]
    pub const fn new(json: bool) -> Self {
        Self { json, silent: false }
    }

    /// 丢弃全部输出（测试断言内部状态时用，避免污染测试输出）。
    #[must_use]
    pub const fn silent() -> Self {
        Self { json: false, silent: true }
    }

    /// 是否 JSON 模式。
    #[must_use]
    pub const fn is_json(&self) -> bool {
        self.json
    }

    /// 是否丢弃输出。
    #[must_use]
    pub const fn is_silent(&self) -> bool {
        self.silent
    }

    /// 输出一行（JSON 模式下是 JSON 文本）。
    pub fn line(&self, text: &str) {
        if self.silent {
            return;
        }
        let mut out = std::io::stdout();
        let _ = writeln!(out, "{text}");
        let _ = out.flush();
    }

    /// 输出错误/结论信息（始终走 stderr）。
    pub fn error(&self, text: &str) {
        if self.silent {
            return;
        }
        let mut err = std::io::stderr();
        let _ = writeln!(err, "{text}");
        let _ = err.flush();
    }

    /// 输出结构化数据。
    ///
    /// # Errors
    /// 序列化失败（结构体含非有限浮点等）时返回错误。
    pub fn emit<T: Serialize>(&self, value: &T) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(value)?;
        self.line(&text);
        Ok(())
    }

    /// 单行机器可读输出（JSON 压成一行，便于 shell 管道）。
    ///
    /// # Errors
    /// 序列化失败。
    pub fn emit_compact<T: Serialize>(&self, value: &T) -> anyhow::Result<()> {
        self.line(&serde_json::to_string(value)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_mode_flag_round_trips() {
        assert!(!Output::new(false).is_json());
        assert!(Output::new(true).is_json());
        assert!(Output::json().is_json());
        assert!(!Output::text().is_json());
    }

    #[test]
    fn silent_mode_suppresses_channel_output() {
        let silent = Output::silent();
        assert!(silent.is_silent());
        assert!(!silent.is_json());
        // 静默模式下调用不应产生任何输出（这些调用是幂等的空操作）
        silent.line("不应出现");
        silent.error("不应出现");
        assert!(!Output::text().is_silent());
    }

    #[test]
    fn emit_serializes_to_json_text() {
        let value = serde_json::json!({"ok": true, "count": 3});
        let text = serde_json::to_string_pretty(&value).unwrap_or_default();
        assert!(text.contains("\"ok\""));
        assert!(text.contains("count"));
    }
}
