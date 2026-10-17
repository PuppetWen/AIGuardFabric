//! SNMP v3 USM（RFC3414）：安全级别、认证协议、USM 统计与 `usm_prometheus` 指标渲染。

// -----------------------------------------------------------------------
// SNMP v3 / USM
// -----------------------------------------------------------------------

// ---------------------------------------------------------------------------
// SNMP v3 / USM（RFC3414）
// ---------------------------------------------------------------------------

use super::*;

/// USM 时限窗口（RFC3414 §3.2 步骤 7.1：默认 150 秒）。
pub const USM_TIME_WINDOW_SECS: i64 = 150;

/// USM 认证摘要长度：HMAC-MD5-96 与 HMAC-SHA-96 都是 96 bit = 12 字节。
pub const USM_DIGEST_LEN: usize = 12;

/// v3 安全级别（`msgFlags` 的低两位：bit0 = auth，bit1 = priv）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum V3SecurityLevel {
    /// 不认证不加密（`msgFlags=0x00`）。
    #[default]
    NoAuthNoPriv,
    /// 认证不加密（`msgFlags=0x01`）。
    AuthNoPriv,
    /// 认证且加密（`msgFlags=0x03`）——DES 与 AES 两种隐私协议都已落地（见 [`super::PrivProtocol`]）。
    AuthPriv,
}

impl V3SecurityLevel {
    /// 解析文本（不区分大小写与下划线/连字符）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized: String = text.trim().to_ascii_lowercase().chars().filter(|c| *c != '_' && *c != '-').collect();
        match normalized.as_str() {
            "noauthnopriv" | "noauth" | "none" => Some(Self::NoAuthNoPriv),
            "authnopriv" | "auth" => Some(Self::AuthNoPriv),
            "authpriv" | "priv" => Some(Self::AuthPriv),
            _ => None,
        }
    }

    /// 稳定名称（与 RFC 一致的大小写）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAuthNoPriv => "noAuthNoPriv",
            Self::AuthNoPriv => "authNoPriv",
            Self::AuthPriv => "authPriv",
        }
    }

    /// `msgFlags` 字节（bit2 的 reportable 由调用方决定，这里只给安全位）。
    #[must_use]
    pub const fn msg_flags(self) -> u8 {
        match self {
            Self::NoAuthNoPriv => 0x00,
            Self::AuthNoPriv => 0x01,
            Self::AuthPriv => 0x03,
        }
    }

    /// 由 `msgFlags` 反解（忽略 reportable 位）。
    #[must_use]
    pub const fn from_msg_flags(flags: u8) -> Option<Self> {
        match flags & 0x03 {
            0x00 => Some(Self::NoAuthNoPriv),
            0x01 => Some(Self::AuthNoPriv),
            0x03 => Some(Self::AuthPriv),
            _ => None,
        }
    }

    /// 本实现是否支持（三种安全级别都已落地：`authPriv` 支持 CBC-DES 与 CFB128-AES-128）。
    #[must_use]
    pub const fn is_implemented(self) -> bool {
        true
    }
}

/// v3 USM 认证协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthProtocol {
    /// `usmHMACMD5AuthProtocol`（HMAC-MD5-96）。
    #[default]
    Md5,
    /// `usmHMACSHAAuthProtocol`（HMAC-SHA-96）。
    Sha1,
}

impl AuthProtocol {
    /// 解析文本（`md5` / `sha` / `sha1` / 完整协议名）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized: String = text.trim().to_ascii_lowercase().chars().filter(char::is_ascii_alphanumeric).collect();
        match normalized.as_str() {
            "md5" | "hmacmd5" | "hmacmd596" | "usmhmacmd5authprotocol" => Some(Self::Md5),
            "sha" | "sha1" | "hmacsha" | "hmacsha96" | "usmhmacshaauthprotocol" => Some(Self::Sha1),
            _ => None,
        }
    }

    /// 稳定名称。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
        }
    }

    /// `usmUserAuthProtocol` 的 OID（RFC3414 §5）。
    #[must_use]
    pub const fn oid(self) -> &'static str {
        match self {
            Self::Md5 => "1.3.6.1.6.3.10.1.1.1",
            Self::Sha1 => "1.3.6.1.6.3.10.1.1.2",
        }
    }

    /// 摘要截断长度（96 bit）。
    #[must_use]
    pub const fn digest_len(self) -> usize {
        USM_DIGEST_LEN
    }

    /// 口令本地化（RFC3414 §2.6 / 附录 A.2）：
    ///
    /// `Ku = H(口令重复至 1 MiB)`；`Kul = H(Ku ‖ engineID ‖ Ku)`。
    ///
    /// 返回 `None` 只可能在口令为空时发生。
    #[must_use]
    pub fn localize_key(self, password: &str, engine_id: &[u8]) -> Option<Vec<u8>> {
        let key = self.password_to_key(password.as_bytes())?;
        let mut buf = Vec::with_capacity(key.len().saturating_mul(2).saturating_add(engine_id.len()));
        buf.extend_from_slice(&key);
        buf.extend_from_slice(engine_id);
        buf.extend_from_slice(&key);
        Some(self.hash(&buf))
    }

    /// 口令 → Ku（重复口令至 1 MiB 后取一次摘要）。
    ///
    /// # Errors 语义：空口令返回 `None`（无密钥可用）。
    #[must_use]
    pub fn password_to_key(self, password: &[u8]) -> Option<Vec<u8>> {
        if password.is_empty() {
            return None;
        }
        // RFC3414 A.2.1：把口令重复填满 1048576 字节，再取一次摘要
        let mut buf = Vec::with_capacity(1_048_576);
        while buf.len() < 1_048_576 {
            let remain = 1_048_576 - buf.len();
            let take = remain.min(password.len());
            buf.extend_from_slice(password.get(..take)?);
        }
        Some(self.hash(&buf))
    }

    /// 原始摘要（Ku / Kul 用）。
    fn hash(self, data: &[u8]) -> Vec<u8> {
        use md5::Digest as _;
        match self {
            Self::Md5 => md5::Md5::digest(data).to_vec(),
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
        }
    }

    /// HMAC 摘要（截断 96 bit）。
    fn hmac_digest(self, key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        use hmac::{Hmac, Mac};
        match self {
            Self::Md5 => {
                let mut mac = Hmac::<md5::Md5>::new_from_slice(key).ok()?;
                mac.update(data);
                Some(mac.finalize().into_bytes().get(..USM_DIGEST_LEN)?.to_vec())
            }
            Self::Sha1 => {
                let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).ok()?;
                mac.update(data);
                Some(mac.finalize().into_bytes().get(..USM_DIGEST_LEN)?.to_vec())
            }
        }
    }

    /// 计算整条报文的认证摘要（RFC3414 §6.3.1）：
    /// `msgAuthenticationParameters` 段**置为 `auth_len` 个 0 字节**后用本地化密钥做 HMAC，截断 96 bit。
    ///
    /// 返回 `None` 表示偏移越界（报文被截断）或 HMAC 密钥非法。
    #[must_use]
    pub fn authenticate(self, key: &[u8], message: &[u8], auth_offset: usize, auth_len: usize) -> Option<Vec<u8>> {
        let end = auth_offset.checked_add(auth_len)?;
        let mut masked = message.to_vec();
        for byte in masked.get_mut(auth_offset..end)? {
            *byte = 0;
        }
        self.hmac_digest(key, &masked)
    }
}

/// usmStats 计数器种类（RFC3414 §5 的 6 个对象）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsmStatsKind {
    /// `usmStatsUnsupportedSecLevels`：安全级别不被支持（配置与报文不一致等）。
    UnsupportedSecLevels,
    /// `usmStatsNotInTimeWindows`：超出 150s 时限窗口。
    NotInTimeWindows,
    /// `usmStatsUnknownUserNames`：用户名未知。
    UnknownUserNames,
    /// `usmStatsUnknownEngineIDs`：引擎 ID 未知（本接收器接受首个 engineID，故一般不计）。
    UnknownEngineIds,
    /// `usmStatsWrongDigests`：摘要校验失败（口令错误/报文被篡改）。
    WrongDigests,
    /// `usmStatsDecryptionErrors`：解密失败（密文长度非法/CBC 解出非 BER 载荷/缺 priv 凭据）。
    DecryptionErrors,
}

impl UsmStatsKind {
    /// RFC3414 §5 的对象 OID。
    #[must_use]
    pub const fn oid(self) -> &'static str {
        match self {
            Self::UnsupportedSecLevels => "1.3.6.1.6.3.15.1.1.1.0",
            Self::NotInTimeWindows => "1.3.6.1.6.3.15.1.1.2.0",
            Self::UnknownUserNames => "1.3.6.1.6.3.15.1.1.3.0",
            Self::UnknownEngineIds => "1.3.6.1.6.3.15.1.1.4.0",
            Self::WrongDigests => "1.3.6.1.6.3.15.1.1.5.0",
            Self::DecryptionErrors => "1.3.6.1.6.3.15.1.1.6.0",
        }
    }

    /// Prometheus 指标名。
    #[must_use]
    pub const fn metric(self) -> &'static str {
        match self {
            Self::UnsupportedSecLevels => "agf_ingest_snmp_usm_unsupported_sec_levels_total",
            Self::NotInTimeWindows => "agf_ingest_snmp_usm_not_in_time_windows_total",
            Self::UnknownUserNames => "agf_ingest_snmp_usm_unknown_user_names_total",
            Self::UnknownEngineIds => "agf_ingest_snmp_usm_unknown_engine_ids_total",
            Self::WrongDigests => "agf_ingest_snmp_usm_wrong_digests_total",
            Self::DecryptionErrors => "agf_ingest_snmp_usm_decryption_errors_total",
        }
    }

    /// 全部种类（渲染顺序固定）。
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::UnsupportedSecLevels,
            Self::NotInTimeWindows,
            Self::UnknownUserNames,
            Self::UnknownEngineIds,
            Self::WrongDigests,
            Self::DecryptionErrors,
        ]
    }
}

/// `usmStats` 计数器组（**认证/解密失败必须分类计数**，不合并成"未知错误"）。
///
/// 前 6 个是 RFC3414 §5 的标准对象；其余是 authPriv 落地后的**运行态细分计数**
/// （解密成功 / 补齐校验 / 短明文），它们不是 RFC 对象，指标名前缀统一为
/// `agf_ingest_snmp_usm_priv_*`，与 usmStats 严格区分。
#[derive(Debug, Default)]
pub struct UsmStats {
    counters: [AtomicU64; 6],
    accepted_auth: AtomicU64,
    accepted_noauth: AtomicU64,
    accepted_priv: AtomicU64,
    priv_decrypt_ok: AtomicU64,
    priv_padding_errors: AtomicU64,
    priv_short_plaintext: AtomicU64,
    reports_received: AtomicU64,
}

/// [`UsmStats`] 的只读快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsmStatsSnapshot {
    /// `usmStatsUnsupportedSecLevels`。
    pub unsupported_sec_levels: u64,
    /// `usmStatsNotInTimeWindows`。
    pub not_in_time_windows: u64,
    /// `usmStatsUnknownUserNames`。
    pub unknown_user_names: u64,
    /// `usmStatsUnknownEngineIDs`。
    pub unknown_engine_ids: u64,
    /// `usmStatsWrongDigests`。
    pub wrong_digests: u64,
    /// `usmStatsDecryptionErrors`。
    pub decryption_errors: u64,
    /// 认证通过（`authNoPriv`）的报文数。
    pub accepted_auth: u64,
    /// 免认证（`noAuthNoPriv`）通过的报文数。
    pub accepted_noauth: u64,
    /// 认证 + 解密全通过（`authPriv`）的报文数。
    pub accepted_priv: u64,
    /// 解密成功并**还原出合法 ScopedPDU** 的次数（块密码跑通但解出乱码不算成功）。
    pub priv_decrypt_ok: u64,
    /// 解密成功但**补齐不合法**（解出的明文不是合法 BER ScopedPDU）的次数。
    pub priv_padding_errors: u64,
    /// 解密结果**短于最小 ScopedPDU**（空/截断）的次数。
    pub priv_short_plaintext: u64,
    /// 收到的 Report PDU 数（对端在报告 usmStats）。
    pub reports_received: u64,
}

impl UsmStats {
    /// 新建（全零）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 计数某一类 USM 错误。
    pub fn bump(&self, kind: UsmStatsKind) {
        let index = UsmStatsKind::all().iter().position(|k| *k == kind).unwrap_or(0);
        if let Some(counter) = self.counters.get(index) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 计数一次认证通过（`authNoPriv`）。
    pub fn accept_auth(&self) {
        self.accepted_auth.fetch_add(1, Ordering::Relaxed);
    }

    /// 计数一次免认证通过（`noAuthNoPriv`）。
    pub fn accept_noauth(&self) {
        self.accepted_noauth.fetch_add(1, Ordering::Relaxed);
    }

    /// 计数一次 `authPriv` 全通过（认证 + 解密 + ScopedPDU 解析成功）。
    pub fn accept_priv(&self) {
        self.accepted_priv.fetch_add(1, Ordering::Relaxed);
    }

    /// 计数一次解密成功（**还原出合法 ScopedPDU 之后**才计；剥掉的补齐字节数由调用方记日志）。
    pub fn record_priv_decrypt(&self) {
        self.priv_decrypt_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// 计数一次"解密成功但补齐/明文结构非法"。
    pub fn record_priv_padding_error(&self) {
        self.priv_padding_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// 计数一次"解密结果过短"（空或不足最小 ScopedPDU）。
    pub fn record_priv_short_plaintext(&self) {
        self.priv_short_plaintext.fetch_add(1, Ordering::Relaxed);
    }

    /// 计数一次 Report PDU。
    pub fn record_report(&self) {
        self.reports_received.fetch_add(1, Ordering::Relaxed);
    }

    /// 快照。
    #[must_use]
    pub fn snapshot(&self) -> UsmStatsSnapshot {
        let get = |kind: UsmStatsKind| -> u64 {
            let index = UsmStatsKind::all().iter().position(|k| *k == kind).unwrap_or(0);
            self.counters.get(index).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0)
        };
        UsmStatsSnapshot {
            unsupported_sec_levels: get(UsmStatsKind::UnsupportedSecLevels),
            not_in_time_windows: get(UsmStatsKind::NotInTimeWindows),
            unknown_user_names: get(UsmStatsKind::UnknownUserNames),
            unknown_engine_ids: get(UsmStatsKind::UnknownEngineIds),
            wrong_digests: get(UsmStatsKind::WrongDigests),
            decryption_errors: get(UsmStatsKind::DecryptionErrors),
            accepted_auth: self.accepted_auth.load(Ordering::Relaxed),
            accepted_noauth: self.accepted_noauth.load(Ordering::Relaxed),
            accepted_priv: self.accepted_priv.load(Ordering::Relaxed),
            priv_decrypt_ok: self.priv_decrypt_ok.load(Ordering::Relaxed),
            priv_padding_errors: self.priv_padding_errors.load(Ordering::Relaxed),
            priv_short_plaintext: self.priv_short_plaintext.load(Ordering::Relaxed),
            reports_received: self.reports_received.load(Ordering::Relaxed),
        }
    }

    /// Prometheus 文本（每个 usmStats 对象一个 counter + 通过/解密计数）。
    #[must_use]
    pub fn prometheus(&self, receiver: &str) -> String {
        let mut out = String::new();
        for kind in UsmStatsKind::all() {
            let index = UsmStatsKind::all().iter().position(|k| *k == kind).unwrap_or(0);
            let value = self.counters.get(index).map(|c| c.load(Ordering::Relaxed)).unwrap_or(0);
            out.push_str(&format!(
                "# HELP {name} usmStats {oid}（USM 错误分类计数）\n# TYPE {name} counter\n{name}{{receiver=\"{receiver}\"}} {value}\n",
                name = kind.metric(),
                oid = kind.oid(),
            ));
        }
        for (name, help, value) in [
            (
                "agf_ingest_snmp_usm_accepted_auth_total",
                "v3 authNoPriv 认证通过条数",
                self.accepted_auth.load(Ordering::Relaxed),
            ),
            (
                "agf_ingest_snmp_usm_accepted_noauth_total",
                "v3 noAuthNoPriv 通过条数",
                self.accepted_noauth.load(Ordering::Relaxed),
            ),
            (
                "agf_ingest_snmp_usm_accepted_priv_total",
                "v3 authPriv（DES/AES）认证+解密全通过条数",
                self.accepted_priv.load(Ordering::Relaxed),
            ),
            (
                "agf_ingest_snmp_usm_priv_decrypt_ok_total",
                "v3 authPriv 解密成功并还原出合法 ScopedPDU 的次数（RFC3414 §8 / RFC3826 §3）",
                self.priv_decrypt_ok.load(Ordering::Relaxed),
            ),
            (
                "agf_ingest_snmp_usm_priv_padding_errors_total",
                "v3 authPriv 解密后补齐/明文结构非法次数",
                self.priv_padding_errors.load(Ordering::Relaxed),
            ),
            (
                "agf_ingest_snmp_usm_priv_short_plaintext_total",
                "v3 authPriv 解密结果过短（空/截断）次数",
                self.priv_short_plaintext.load(Ordering::Relaxed),
            ),
            (
                "agf_ingest_snmp_usm_reports_received_total",
                "v3 Report PDU 收到条数",
                self.reports_received.load(Ordering::Relaxed),
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name}{{receiver=\"{receiver}\"}} {value}\n"
            ));
        }
        out
    }
}

/// SNMP Trap 接收器在指标上的 `receiver` 标签（与 `apps/ingest` 的 `metrics.counters("snmp-trap")` 一致）。
const SNMP_METRIC_RECEIVER: &str = "snmp-trap";

/// 进程级 USM 计数器槽位（`/metrics` 用，详见 [`usm_prometheus`]）。
static PROCESS_USM_STATS: Mutex<Option<Arc<UsmStats>>> = Mutex::new(None);

/// 登记进程级 USM 计数器（接收器构造时调用；锁中毒 ⇒ 照常写入，绝不影响接收器）。
pub(super) fn register_process_usm_stats(stats: &Arc<UsmStats>) {
    let mut slot = match PROCESS_USM_STATS.lock() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    };
    *slot = Some(Arc::clone(stats));
}

/// 渲染进程级 SNMP USM 指标的 Prometheus 文本（挂在 `/metrics`）。
///
/// 与 [`crate::mqtt::link_prometheus`] 同一套路：接收器构造时把自己的 USM 计数器登记进
/// [`PROCESS_USM_STATS`]（进程内只有一个 SNMP Trap 接收器，重复构造时后登记的生效）。
/// **未登记时渲染全零序列**——未配置 SNMP 时 usmStats 这一族指标仍然存在（值为 0），
/// 而不是"有数据才出现"。
#[must_use]
pub fn usm_prometheus() -> String {
    let stats = {
        let slot = match PROCESS_USM_STATS.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        slot.clone()
    };
    match stats {
        Some(stats) => stats.prometheus(SNMP_METRIC_RECEIVER),
        None => UsmStats::new().prometheus(SNMP_METRIC_RECEIVER),
    }
}
