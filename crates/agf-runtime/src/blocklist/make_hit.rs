//! 由 `blocklist.rs` 拆分：`make_hit` 等 4 个函数（纯搬移，逻辑不变）。
use super::*;

/// 构造命中结果。
pub(crate) fn make_hit(compiled: &CompiledRule, text: &str) -> RuleHit {
    RuleHit {
        rule_id: compiled.rule.id.clone(),
        kind: compiled.rule.kind,
        matched_text: text.to_string(),
        pattern: compiled.rule.pattern.clone(),
        action: compiled.rule.action,
        reason: compiled.rule.reason.clone(),
        domain: compiled.rule.domain,
        severity: compiled.rule.severity,
    }
}

/// 按类别统计规则数。
pub(crate) fn count_by_kind(rules: &[CompiledRule]) -> BTreeMap<String, usize> {
    let mut map: BTreeMap<String, usize> = BTreeMap::new();
    for r in rules {
        *map.entry(r.rule.kind.as_str().to_string()).or_insert(0) += 1;
    }
    map
}

/// 供哈希规则匹配的文本：把载荷中的字符串拼成可搜索文本。
pub(crate) fn searchable_hash_text(ctx: &PolicyContext) -> Option<String> {
    fn walk(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(items) => items.iter().for_each(|i| walk(i, out)),
            serde_json::Value::Object(map) => map.values().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut parts = Vec::new();
    walk(&ctx.payload, &mut parts);
    if let Some(cmd) = ctx.command.as_ref() {
        parts.push(cmd.clone());
    }
    if parts.is_empty() { None } else { Some(parts.join("\n")) }
}

/// 内置默认黑名单（**发布契约**，见模块文档与交付报告中的规则表）。
///
/// 覆盖 §4.3 要求的三类分级：
/// - 命令级黑名单：破坏性命令、管道执行远程脚本、编码绕过、反弹 shell、权限放开、凭证外带；
/// - 域名出网管控：粘贴站 / 内网穿透 / 临时文件host / webhook 收集器 / 文件分享；
/// - 敏感路径：系统口令文件、SSH/GPG/AWS/GCloud/Azure/Docker/npm/PyPI/K8s/浏览器凭据。
#[must_use]
pub fn default_rules() -> Vec<RuleRule> {
    let mut rules: Vec<RuleRule> = Vec::new();

    // ---- 命令级黑名单（13 条）----
    let cmd = |id: &str, pattern: &str, reason: &str| {
        RuleRule::deny(id, RuleKind::Command, pattern, reason, RiskDomain::ToolAbuse, Severity::Critical)
    };
    rules.push(cmd(
        "cmd.rm-rf-root",
        r"re:(^|[;&|]\s*|sudo\s+)rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*|-[rR]\s+-f|-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*)\s+/(\s|$|\*)",
        "递归强制删除根目录，将造成系统不可恢复损坏",
    ));
    rules.push(cmd(
        "cmd.rm-rf-var",
        r"re:(^|[;&|]\s*|sudo\s+)rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*|-[rR]\s+-f|-[rR]\s+--force)(\s|$)",
        "递归强制删除（rm -rf/-fr/-R -f）属高危破坏性操作",
    ));
    rules.push(cmd("cmd.mkfs", "mkfs", "格式化文件系统将导致数据全部丢失"));
    // 注意不能写成子串 `dd if=`：`echo "add if=x"` 会误命中（"add if=" 含 "dd if="）
    rules.push(cmd("cmd.dd-if", r"re:(^|[;&|]\s*|sudo\s+)dd\s+if=", "直接读写块设备，可覆写磁盘与分区表"));
    rules.push(cmd("cmd.fork-bomb", ":(){:|:&};:", "shell fork 炸弹，会耗尽进程表导致主机不可用"));
    rules.push(cmd(
        "cmd.curl-pipe-sh",
        "re:(curl|wget)[^|\\n]*\\|\\s*(sudo\\s+)?(ba|z|k|d)?sh",
        "下载远程脚本并直接交给 shell 执行（curl/wget | sh），典型无文件落地攻击链",
    ));
    rules.push(cmd(
        "cmd.powershell-enc",
        "re:powershell(\\.exe)?\\s[^\\n]*-(e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\\b",
        "PowerShell 编码命令（-EncodedCommand）常被用于隐藏恶意载荷",
    ));
    rules.push(cmd(
        "cmd.certutil-urlcache",
        "certutil -urlcache",
        "certutil -urlcache 是 Windows 上常用的 LOLBin 下载器",
    ));
    rules.push(cmd(
        "cmd.nc-e",
        "re:(^|[;&|]\\s*|sudo\\s+)nc(\\.exe)?\\s+[^\\n]*?\\s*-[a-zA-Z]*e\\b",
        "netcat -e 将 shell 绑定到网络连接（反弹/正向 shell）",
    ));
    rules.push(cmd("cmd.chmod-777-root", "chmod 777 /", "把根目录权限放开为全局可写，违反最小权限原则"));
    rules.push(cmd(
        "cmd.base64-pipe-sh",
        "re:base64\\s+(-d|--decode)[^|\\n]*\\|\\s*(sudo\\s+)?(ba|z|k)?sh",
        "base64 解码后管道给 shell，用于绕过静态检测",
    ));
    rules.push(cmd("cmd.iptables-flush", "iptables -F", "清空防火墙规则，常作为横向移动前的准备动作"));
    rules.push(cmd(
        "cmd.security-dump",
        "re:(mimikatz|procdump[^\\n]*lsass|reg\\s+save\\s+hklm\\\\sam)",
        "尝试转储系统凭证（LSASS/SAM），属凭证窃取行为",
    ));

    // ---- 域名出网管控（8 条）----
    let dom = |id: &str, pattern: &str, reason: &str| {
        RuleRule::deny(id, RuleKind::Domain, pattern, reason, RiskDomain::ModelData, Severity::High)
    };
    rules.push(dom("domain.pastebin", "*.pastebin.com", "粘贴站常用于中转外泄数据与托管恶意脚本"));
    rules.push(dom("domain.ngrok", "*.ngrok.io", "内网穿透域名，可把内网服务直接暴露到公网"));
    rules.push(dom("domain.ngrok-free", "*.ngrok-free.app", "内网穿透域名，可把内网服务直接暴露到公网"));
    rules.push(dom("domain.trycloudflare", "*.trycloudflare.com", "临时隧道域名，常用于隐蔽外联"));
    rules.push(dom("domain.webhook-site", "webhook.site", "Webhook 收集器，可静默接收被外泄的数据"));
    rules.push(dom("domain.requestbin", "*.requestbin.net", "请求收集器，可静默接收被外泄的数据"));
    rules.push(dom("domain.transfer-sh", "transfer.sh", "临时文件中转站，常用于外带数据"));
    rules.push(dom("domain.file-io", "file.io", "一次性文件分享站，常用于外带数据"));

    // ---- 敏感路径（13 条）----
    let p = |id: &str, pattern: &str, reason: &str| {
        RuleRule::deny(id, RuleKind::Path, pattern, reason, RiskDomain::CredentialLeak, Severity::High)
    };
    rules.push(p("path.etc-shadow", "/etc/shadow", "Linux 口令哈希文件，读取即等同获取系统账户凭证"));
    rules.push(p("path.etc-passwd", "/etc/passwd", "系统账户枚举文件，常作为提权第一步"));
    rules.push(p("path.ssh-id-rsa", "id_rsa", "SSH 私钥文件，泄露即获得目标主机登录能力"));
    rules.push(p("path.ssh-dir", ".ssh", "SSH 目录含私钥与 known_hosts，属高敏感目录"));
    rules.push(p("path.aws-credentials", r"%USERPROFILE%\.aws\credentials", "AWS 长期凭证文件（AK/SK）"));
    rules.push(p("path.gcloud", r"%APPDATA%\gcloud", "gcloud 凭证与配置目录"));
    rules.push(p("path.azure", r"%USERPROFILE%\.azure", "Azure CLI 凭证目录"));
    rules.push(p("path.docker-config", ".docker/config.json", "Docker registry 凭证（含 base64 认证串）"));
    rules.push(p("path.npmrc", ".npmrc", "npm registry token，可用于供应链投毒"));
    rules.push(p("path.pypirc", ".pypirc", "PyPI 上传凭证，可用于供应链投毒"));
    rules.push(p("path.kubeconfig", "kubeconfig", "Kubernetes 集群凭证，泄露即等同集群权限"));
    rules.push(p("path.gnupg", ".gnupg", "GPG 私钥目录"));
    rules.push(p("path.browser-login-data", "Login Data", "浏览器保存的登录凭据数据库，属凭证窃取目标"));

    // ---- 工具级（1 条，可由租户白名单覆盖）----
    rules.push(RuleRule::deny(
        "tool.shell-write",
        RuleKind::Tool,
        "re:^(shell|exec|execute|run_command|terminal|bash|powershell)$",
        "具备任意命令执行能力的工具需纳入白名单后才可调用",
        RiskDomain::ToolAbuse,
        Severity::Medium,
    ));

    // ---- 哈希（1 条）----
    rules.push(RuleRule::deny(
        "hash.eicar-test",
        RuleKind::Hash,
        KNOWN_BAD_HASHES[0],
        "命中已知恶意样本摘要（EICAR 测试样本，用于验证黑名单链路）",
        RiskDomain::ModelData,
        Severity::High,
    ));

    rules
}
