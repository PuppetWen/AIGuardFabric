//! 解析引擎的公共底座：内置 Grok 模式表、ECS 前缀与 CEF/LEEF 键表、Grok→Regex 展开、模板校验与解析分发打分。

use super::*;

/// 样本打分阈值：低于该分值认为模板不匹配该样本。
pub const MATCH_THRESHOLD: f32 = 0.5;

/// 内置 Grok pattern 表（覆盖常见厂商日志用到的字段）。
///
/// 策略是"够用且不引依赖"：只实现日志解析真正需要的 pattern，
/// 而不是把 Logstash 全量 pattern 搬进来（那会带来几百个用不上的正则）。
const GROK_PATTERNS: &[(&str, &str)] = &[
    ("WORD", r"\b\w+\b"),
    ("NOTSPACE", r"\S+"),
    ("SPACE", r"\s*"),
    ("DATA", r".*?"),
    ("GREEDYDATA", r".*"),
    ("QS", r#""(?:[^"\\]|\\.)*""#),
    ("INT", r"[+-]?\d+"),
    ("NUMBER", r"[+-]?\d+(?:\.\d+)?"),
    ("BASE10NUM", r"[+-]?\d+(?:\.\d+)?"),
    ("POSINT", r"\d+"),
    ("IP", r"(?:\d{1,3}\.){3}\d{1,3}"),
    ("IPV4", r"(?:\d{1,3}\.){3}\d{1,3}"),
    ("IPV6", r"[0-9A-Fa-f:]{2,39}"),
    ("IPORHOST", r"(?:(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9_.\-]+)"),
    ("HOSTNAME", r"\b[A-Za-z0-9][A-Za-z0-9_\-\.]{0,254}\b"),
    ("HOST", r"\b[A-Za-z0-9][A-Za-z0-9_\-\.]{0,254}\b"),
    ("MAC", r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"),
    ("PORT", r"\d{1,5}"),
    ("USER", r"[A-Za-z0-9._\-\\@]+"),
    ("USERNAME", r"[A-Za-z0-9._\-\\@]+"),
    ("EMAILADDRESS", r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    ("URIPATH", r"(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+"),
    ("URI", r"\b(?:[A-Za-z][A-Za-z0-9+\-.]*://)?[A-Za-z0-9.\-]+(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)?\b"),
    ("URIPARAM", r"\?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_\-]*"),
    ("UUID", r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"),
    ("SYSLOGTIMESTAMP", r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
    ("TIMESTAMP_ISO8601", r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    ("HTTPDATE", r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}"),
    ("DATESTAMP", r"\d{4}-\d{2}-\d{2}"),
    ("TIME", r"\d{2}:\d{2}:\d{2}"),
    ("LOGLEVEL", r"(?i)TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|NOTICE"),
    ("SYSLOGPROG", r"[A-Za-z0-9_\-\./]+(?:\[\d+\])?"),
    ("CISCOFW", r"%[A-Z0-9_]+-\d+-[A-Z0-9_]+"),
    ("PROG", r"[\w\-\./]+"),
    ("YEAR", r"\d{4}"),
    ("MONTH", r"\d{1,2}"),
    ("DAY", r"\d{1,2}"),
    ("TIMEZONE", r"[A-Za-z]{3,5}|[+-]\d{2}:?\d{2}"),
    (
        "HTTPD_COMMONLOG",
        r#"(?:\S+) (?:\S+) (?:\S+) \[[^\]]+\] "(?:[^"]*)" \d{3} (?:\d+|-) "?(?:[^"]*)"? "?(?:[^"]*)?"?"#,
    ),
];

/// AGF-ECS 路径前缀（引擎直出的键若命中这些前缀，视为已归一化字段）。
const ECS_PREFIXES: &[&str] = &[
    "event.",
    "host.",
    "user.",
    "source.",
    "destination.",
    "network.",
    "url.",
    "file.",
    "process.",
    "cloud.",
    "log.",
    "rule.",
    "threat.",
    "observer.",
    "trace.",
    "http.",
    "dns.",
    "user_agent.",
    "ai.",
    "syslog.",
    "registry.",
    "service.",
    "tls.",
    "email.",
    "vulnerability.",
    "device.",
    "agent.",
    "container.",
    "orchestrator.",
    "error.",
    "client.",
    "server.",
    "geo.",
];

/// CEF/LEEF 标准键 → AGF-ECS 路径（引擎直出，模板无需再映射）。
pub(super) const CEF_LEEF_KEYS: &[(&str, &str)] = &[
    ("src", "source.ip"),
    ("dst", "destination.ip"),
    ("spt", "source.port"),
    ("dpt", "destination.port"),
    ("proto", "network.transport"),
    ("cat", "event.category_raw"),
    ("msg", "message"),
    ("suser", "user.name"),
    ("duser", "destination.user.name"),
    ("shost", "host.name"),
    ("dhost", "destination.host.name"),
    ("fname", "file.name"),
    ("fpath", "file.path"),
    ("fsize", "file.size"),
    ("deviceExternalId", "observer.serial_number"),
];

/// 判断键名是否已经是 AGF-ECS 路径。
#[must_use]
pub fn is_ecs_path(key: &str) -> bool {
    ECS_PREFIXES.iter().any(|p| key.starts_with(p)) || matches!(key, "message" | "tags" | "vendor" | "product")
}

/// 把 Grok 表达式展开为命名捕获正则。
///
/// 支持 `%{PATTERN}` 与 `%{PATTERN:name}`；未识别的 pattern 展开为 `\S+`
/// 并记入返回值的警告列表（而不是直接失败，避免一个未知 pattern 让整个模板不可用）。
#[must_use]
pub fn grok_to_regex(expression: &str) -> (String, Vec<String>) {
    let mut out = String::with_capacity(expression.len() * 2);
    let mut warnings = Vec::new();
    let mut rest = expression;
    let mut counter = 0_usize;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        };
        let inner = &after[..close];
        let (name, field) = match inner.split_once(':') {
            Some((p, f)) => (p.trim(), Some(f.trim())),
            None => (inner.trim(), None),
        };
        let body = GROK_PATTERNS.iter().find(|(k, _)| *k == name).map_or_else(
            || {
                warnings.push(format!("未知 Grok pattern `{name}`，已退化为 \\S+"));
                r"\S+".to_string()
            },
            |(_, v)| (*v).to_string(),
        );
        let group_name = field.map_or_else(
            || {
                counter += 1;
                format!("g{counter}")
            },
            ToString::to_string,
        );
        out.push_str("(?P<");
        out.push_str(&group_name);
        out.push('>');
        out.push_str(&body);
        out.push(')');
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    (out, warnings)
}

/// 校验模板的正则可编译性（加载期调用，坏模板不进入注册表）。
///
/// # Errors
/// 返回人类可读的原因。
pub fn validate_pattern(def: &ParserDefinition) -> Result<(), String> {
    match def.engine {
        ParserEngine::Regex => {
            if def.pattern.trim().is_empty() {
                return Err("Regex 引擎需要 pattern".to_string());
            }
            Regex::new(&def.pattern).map(|_| ()).map_err(|e| format!("正则非法: {e}"))
        }
        ParserEngine::Grok => {
            if def.pattern.trim().is_empty() {
                return Err("Grok 引擎需要 pattern".to_string());
            }
            let (regex, _) = grok_to_regex(&def.pattern);
            Regex::new(&regex).map(|_| ()).map_err(|e| format!("Grok 展开后的正则非法: {e}"))
        }
        ParserEngine::JsonPath => validate_jsonpath(&def.pattern),
        ParserEngine::Jq => {
            if def.pattern.trim().is_empty() {
                return Err("JQ 引擎需要 pattern（JQ 程序）".to_string());
            }
            compile_jq(&def.pattern).map(|_| ())
        }
        ParserEngine::Cel => {
            // CEL **已实现**，但它是模板 `derived` 段的派生字段求值，不是独立抽取引擎：
            // 拿它当主引擎时给准确原因（原先写"尚未实现"与事实不符）。
            Err("`engine: cel` 不是独立抽取引擎：CEL 是模板 `derived` 段的派生字段求值，主引擎请用 Grok/Regex/…"
                .to_string())
        }
        ParserEngine::Plugin => crate::engine::plugin::parse_plugin_spec(&def.pattern).map(|_| ()),
        ParserEngine::Csv => {
            if def.pattern.trim().is_empty() {
                return Err("CSV 引擎需要 pattern（表头，逗号分隔）".to_string());
            }
            Ok(())
        }
        ParserEngine::Syslog
        | ParserEngine::Cef
        | ParserEngine::Leef
        | ParserEngine::Gelf
        | ParserEngine::Kv
        | ParserEngine::AiInferred => Ok(()),
    }
}

/// `required_fields` 是否齐备——**映射前扁平字段名**口径。
///
/// 模板里的 `required_fields` 写的是**源字段名**（引擎直出的扁平键，如 `rule_id`、
/// `id.orig_h`），不是映射后的 AGF-ECS 路径（`rule.id`）。判定（[`parse_with`]）
/// 与打分（[`sample_match_score`]）**必须**共用本函数：
///
/// * 判定按本口径 ⇒ 缺字段的载荷不会被接受；
/// * 打分若改用映射后的 `fields`/`extra` 去查，带 `required_fields` 的模板会被系统性
///   腰斩成 `base * 0.5`（得分上限 0.495 < [`MATCH_THRESHOLD`]），第 4 步"样本打分"
///   对这类模板**彻底失效**（历史缺陷，两个口径分叉的直接后果）。
#[must_use]
pub(super) fn required_fields_satisfied(required: &[String], flat: &BTreeMap<String, Value>) -> bool {
    required.iter().all(|f| flat.contains_key(f.as_str()))
}

/// 解析内核：[`parse_with`] 与 [`sample_match_score`] 的**唯一**实现路径。
///
/// 返回（**映射前**的扁平字段，解析结果）；`flat` 为 `None` ⟺ 主模式与全部
/// `fallback_patterns` 都未命中，或未满足 `required_fields`。
///
/// 把"取字段"与"校验必需字段"放在同一处，是"判定口径 = 打分数口径"的结构保证：
/// 调用方拿到的 `flat` 就是判定时用的那张表，不可能再分叉。
#[must_use]
fn parse_core(def: &ParserDefinition, raw: &str) -> (Option<BTreeMap<String, Value>>, ParseOutcome) {
    let start = std::time::Instant::now();
    let mut attempts: Vec<&str> = vec![def.pattern.as_str()];
    attempts.extend(def.fallback_patterns.iter().map(String::as_str));

    let mut last_error: Option<String> = None;
    for pattern in attempts {
        // 注意：CEF/LEEF/GELF/KV/Syslog 等引擎**不需要** pattern，
        // 空 pattern 是合法输入，不能在这里被跳过（否则这些模板永远匹配不上）。
        match run_engine(def, pattern, raw) {
            Ok(flat) => {
                if flat.is_empty() {
                    last_error = Some("解析成功但未提取到任何字段".to_string());
                    continue;
                }
                if !required_fields_satisfied(&def.required_fields, &flat) {
                    last_error = Some(format!("缺少必需字段: {}", def.required_fields.join(",")));
                    continue;
                }
                let mut outcome = apply_mapping(def, &flat);
                outcome.parser_key = Some(def.key.clone());
                outcome.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                return (Some(flat), outcome);
            }
            Err(e) => last_error = Some(e),
        }
    }
    let mut outcome = ParseOutcome::miss(last_error.unwrap_or_else(|| "没有可用模式".to_string()));
    outcome.elapsed_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    (None, outcome)
}

/// 执行一次解析。
///
/// 先按主模式解析，失败则依次尝试 `fallback_patterns`；成功则把扁平字段交给
/// [`apply_mapping`] 归一化。`required_fields` 按**映射前**字段名校验
/// （见 [`required_fields_satisfied`]）。
#[must_use]
pub fn parse_with(def: &ParserDefinition, raw: &str) -> ParseOutcome {
    parse_core(def, raw).1
}

/// 在给定样本上的匹配得分（0.0-1.0），用于模板自动选择（注册表第 4 步"样本打分"）。
///
/// 口径（与 [`parse_with`] **同源同口径**，由 [`parse_core`] 结构保证）：
///
/// 1. **未命中即 0 分**：主模式 + `fallback_patterns` 全失败，或 `required_fields`
///    缺一个字段（[`required_fields_satisfied`]）——缺字段的模板不会被"打折接受"；
/// 2. **字段数取映射前的扁平键数**：那是引擎**真正抽到**的字段数。映射后的
///    `fields`/`extra` 含 `mapping.defaults` 凭声明补出来的字段，会让"模板写得多"
///    而不是"抽到得多"得分更高；
/// 3. 得分 = `n / (n + 2)`（n = 抽取字段数）：抽到 1 个字段只有 1/3，
///    要 ≥ [`MATCH_THRESHOLD`] 至少要抽到 2 个字段——避免"一个字段撞上就算命中"。
///
/// **`Plugin` 引擎恒 0 分**（不参与打分）：插件调用本身就是"是否命中"的判定途径，
/// 拿它再打分只会**重复调用插件**（重复副作用、重复失败计数），而且插件是外部自定义逻辑，
/// "抽到的字段数"不代表它对这条载荷的置信度。插件模板因此只在严格趟/放宽趟/显式指定里被调用。
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn sample_match_score(def: &ParserDefinition, raw: &str) -> f32 {
    if def.engine == ParserEngine::Plugin {
        return 0.0;
    }
    let (flat, outcome) = parse_core(def, raw);
    if !outcome.matched {
        return 0.0;
    }
    // 不变量：`matched` ⇒ 内核给出了映射前的扁平字段表（`None` 只可能来自未命中）
    let Some(flat) = flat else {
        return 0.0;
    };
    let n = flat.len();
    n as f32 / (n as f32 + 2.0)
}

// ---------------------------------------------------------------------------
// syslog 信封
// ---------------------------------------------------------------------------
