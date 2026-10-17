//! Syslog 信封剥离（RFC3164/5424 头）与 Regex / Grok / Syslog 三种引擎的执行入口。

use super::*;

/// 从行首提取的 syslog 信封（RFC3164 风格）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyslogEnvelope {
    /// 主机名。
    pub host: Option<String>,
    /// 应用名（`sshd[2311]:` → `sshd`）。
    pub app: Option<String>,
    /// 进程号。
    pub proc_id: Option<String>,
    /// 时间戳（RFC3164 无年份，按接入年份补全）。
    pub timestamp: Option<Timestamp>,
}

/// `<PRI>` + `Mmm dd HH:MM:SS` + `host` + `app[pid]:` 的信封正则（编译一次）。
fn envelope_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?:<\d{1,3}>)?\s*([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(?:([\w\-\./]+)(?:\[(\d+)\])?:\s+)?",
        )
        .ok()
    })
    .as_ref()
}

/// 剥离可选的 syslog 信封，返回（信封字段，剩余正文）。
///
/// 没有信封时返回空信封与原样正文（不报错）；这使同一引擎既能吃"纯日志行"，
/// 也能吃"syslog 信封 + 厂商负载"。
#[must_use]
pub fn strip_syslog_envelope(raw: &str) -> (SyslogEnvelope, String) {
    let Some(re) = envelope_regex() else {
        return (SyslogEnvelope::default(), raw.to_string());
    };
    let Some(caps) = re.captures(raw) else {
        return (SyslogEnvelope::default(), raw.to_string());
    };
    let Some(whole) = caps.get(0) else {
        return (SyslogEnvelope::default(), raw.to_string());
    };
    let mut env = SyslogEnvelope {
        host: caps.get(2).map(|m| m.as_str().to_string()),
        app: caps.get(3).map(|m| m.as_str().to_string()),
        proc_id: caps.get(4).map(|m| m.as_str().to_string()),
        timestamp: caps.get(1).and_then(|m| parse_time_value(m.as_str(), None)),
    };
    // `CEF:` / `LEEF:` / `GELF:` 会被误认成 `app:`，这里丢弃该字段
    // （正文不还原也无妨：CEF/LEEF 引擎直接按标记在原始行里定位）
    if matches!(env.app.as_deref(), Some("CEF" | "LEEF" | "GELF")) {
        env.app = None;
        env.proc_id = None;
    }
    (env, raw[whole.end()..].to_string())
}

/// 信封 → 字段表。
pub(super) fn envelope_fields(env: &SyslogEnvelope) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    if let Some(h) = &env.host {
        out.insert("host.name".to_string(), Value::from(h.clone()));
    }
    if let Some(a) = &env.app {
        out.insert("process.name".to_string(), Value::from(a.clone()));
    }
    if let Some(p) = &env.proc_id {
        out.insert("process.pid".to_string(), Value::from(p.clone()));
    }
    if let Some(t) = env.timestamp {
        out.insert("event.time".to_string(), Value::from(t.to_rfc3339()));
    }
    out
}

// ---------------------------------------------------------------------------
// 引擎分派
// ---------------------------------------------------------------------------

/// 各引擎的扁平字段提取（映射前）。
pub(super) fn run_engine(def: &ParserDefinition, pattern: &str, raw: &str) -> Result<BTreeMap<String, Value>, String> {
    match def.engine {
        ParserEngine::Regex => parse_regex(pattern, raw),
        ParserEngine::Grok => parse_grok(pattern, raw),
        ParserEngine::JsonPath => parse_jsonpath(pattern, raw),
        ParserEngine::Jq => parse_jq(pattern, raw),
        ParserEngine::Syslog => parse_syslog(raw),
        ParserEngine::Cef => parse_cef(raw),
        ParserEngine::Leef => parse_leef(raw),
        ParserEngine::Gelf => parse_gelf(raw),
        ParserEngine::Csv => parse_csv(pattern, raw),
        ParserEngine::Kv => Ok(parse_kv_engine(raw)),
        ParserEngine::Cel => Err("`engine: cel` 不能作主抽取引擎（CEL 是模板 `derived` 段的派生字段求值）".to_string()),
        // 插件引擎：`pattern` 是插件规格（`plugin=<name> [entry=normalize] [ctx=raw|envelope]`），
        // 原始日志行**原样**传给插件（行式引擎的 syslog 信封剥离不适用于插件：
        // 插件自己决定怎么看待原始载荷）。返回值是 AGF-ECS JSON ⇒ 扁平化后走既有映射路径。
        ParserEngine::Plugin => crate::engine::plugin::run_plugin_engine(pattern, raw),
        ParserEngine::AiInferred => {
            if raw.trim_start().starts_with('{') {
                parse_jsonpath(pattern, raw)
            } else if raw.contains('=') {
                Ok(parse_kv_engine(raw))
            } else if raw.contains('\t') || raw.contains(',') {
                let count = raw.split(['\t', ',']).count();
                let keys: Vec<String> = (0..count).map(|i| format!("f{i}")).collect();
                parse_csv(&keys.join(","), raw)
            } else {
                Ok(parse_kv_engine(raw))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 行式引擎（Regex / Grok）
// ---------------------------------------------------------------------------

fn parse_regex(pattern: &str, raw: &str) -> Result<BTreeMap<String, Value>, String> {
    let re = Regex::new(pattern).map_err(|e| format!("正则非法: {e}"))?;
    let (env, body) = strip_syslog_envelope(raw);
    let mut out = envelope_fields(&env);
    let caps = re.captures(&body).ok_or_else(|| "正则未匹配".to_string())?;
    let mut named = 0_usize;
    for name in re.capture_names().flatten() {
        if let Some(m) = caps.name(name) {
            out.insert(name.to_string(), Value::from(m.as_str().to_string()));
            named += 1;
        }
    }
    // 无命名组时退化为位置组 g1..gn（模板可显式声明）
    if named == 0 {
        for (i, m) in caps.iter().enumerate().skip(1) {
            if let Some(m) = m {
                out.insert(format!("g{i}"), Value::from(m.as_str().to_string()));
            }
        }
    }
    Ok(out)
}

fn parse_grok(pattern: &str, raw: &str) -> Result<BTreeMap<String, Value>, String> {
    let (regex, warnings) = grok_to_regex(pattern);
    for w in &warnings {
        debug!(warning = %w, "Grok 展开警告");
    }
    parse_regex(&regex, raw)
}

// ---------------------------------------------------------------------------
// JSONPath / JQ
// ---------------------------------------------------------------------------
fn parse_syslog(raw: &str) -> Result<BTreeMap<String, Value>, String> {
    let parsed = crate::syslog::parse_auto(raw).map_err(|e| e.message())?;
    Ok(parsed.to_fields())
}
