//! SNMP v3 隐私协议（authPriv）：**RFC3414 §8 CBC-DES** 与 **RFC3826 CFB128-AES-128**。
//!
//! ## 密钥与 IV（逐条对齐 RFC 原文，不臆造）
//!
//! | 项 | DES（RFC3414 §8.1.1.1） | AES（RFC3826 §3.1.2.1） |
//! |---|---|---|
//! | 隐私密钥 `privKey` | 本地化口令 `Kul` 的**前 16 字节**（前 8 = DES key，后 8 = pre-IV） | `Kul` 的**前 16 字节**（前 128 bit = AES-128 key） |
//! | `msgPrivacyParameters`（salt） | 8 字节：`engineBoots(4, BE) ‖ 本地计数器(4, BE)` | 8 字节：（伪随机初始化的）本地 64-bit 整数（BE） |
//! | IV | `pre-IV XOR salt`（各 8 字节） | `engineBoots(4, BE) ‖ engineTime(4, BE) ‖ salt(8)` |
//! | 模式 | CBC，**明文补齐到 8 的整数倍**（补齐值无关；解密侧**忽略补齐**） | CFB（S=128），流式，**无补齐** |
//!
//! `Kul` 由认证协议给出（RFC3414 §2.6：`Kul = H(H(口令重复至 1 MiB) ‖ engineID ‖ Ku)`），
//! 因此 UUID 的本地化口径与认证侧**共用同一份实现**（[`AuthProtocol::localize_key`]），
//! RFC3414 §A.3 的 `kul` 向量直接复用为隐私密钥向量的证明。
//!
//! ## 模式实现说明（为什么手写 CBC/CFB 而不引 `cbc`/`cfb-mode`）
//!
//! 只用分组密码本身（`aes` / `des` 两个 RustCrypto crate，`aes` 本就在 `aes-gcm` 的依赖树里），
//! CBC 与 CFB128 各十几行按规范直接写；两组**官方测试向量**（NIST SP800-38A 的 AES-CFB128、
//! FIPS 46 的 DES）落在单测里，模式实现正确性有独立证据，而不是"库说它对"。
//! 另一个必须手写的原因：RFC3414 §8.1.1.3 明确要求**解密侧忽略补齐**（不是 PKCS#7），
//! `decrypt_padded_*` 那类 API 的语义与协议不符。
//!
//! ## 凭据纪律
//!
//! 本模块**不打印也不返回**任何口令；[`PrivProtocol`] 的 `Debug` 只含协议名。
//! 密钥字节只在函数内流转，错误文本只说"解密失败/长度非法"这类分类信息。

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::Des;

use super::*;

/// 隐私密钥长度（DES 与 AES 都取 `Kul` 的前 16 字节）。
pub const PRIV_KEY_LEN: usize = 16;

/// `msgPrivacyParameters`（salt）长度：DES 与 AES 都是 8 字节。
pub const PRIV_SALT_LEN: usize = 8;

/// DES 分组长度。
pub const DES_BLOCK_LEN: usize = 8;

/// AES 分组长度（CFB128 的反馈段长）。
pub const AES_BLOCK_LEN: usize = 16;

/// USM 隐私协议（`usmPrivProtocol`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivProtocol {
    /// `usmAesCfb128Protocol`（RFC3826 §3.1.2）：CFB128-AES-128，**默认**（推荐，无补齐开销）。
    #[default]
    Aes,
    /// `usmDESPrivProtocol`（RFC3414 §8）：CBC-DES（56 bit 有效密钥，遗留设备仍常见）。
    Des,
}

impl PrivProtocol {
    /// 解析文本（`des` / `aes` / `aes128` / `cfb128-aes-128` / 完整协议名）。
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let normalized: String = text.trim().to_ascii_lowercase().chars().filter(char::is_ascii_alphanumeric).collect();
        match normalized.as_str() {
            "des" | "cbcdes" | "descbc" | "usmdesprivprotocol" => Some(Self::Des),
            "aes" | "aes128" | "cfb128aes128" | "aescfb128" | "usmaescfb128protocol" => Some(Self::Aes),
            _ => None,
        }
    }

    /// 稳定名称（配置文本，`AGF_INGEST_SNMP_V3_PRIV_PROTOCOL` 的取值）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aes => "aes",
            Self::Des => "des",
        }
    }

    /// RFC3414 §5 / RFC3826 §4 的 `snmpPrivProtocols` OID。
    #[must_use]
    pub const fn oid(self) -> &'static str {
        match self {
            Self::Des => "1.3.6.1.6.3.10.1.2.2",
            Self::Aes => "1.3.6.1.6.3.10.1.2.4",
        }
    }

    /// 分组/反馈段长度（DES 8，AES 16）。
    #[must_use]
    pub const fn block_len(self) -> usize {
        match self {
            Self::Des => DES_BLOCK_LEN,
            Self::Aes => AES_BLOCK_LEN,
        }
    }

    /// 是否需要补齐明文（只有 CBC-DES 需要；CFB 是流模式）。
    #[must_use]
    pub const fn needs_padding(self) -> bool {
        matches!(self, Self::Des)
    }

    /// RFC 文档出处（文档/指标注释用）。
    #[must_use]
    pub const fn reference(self) -> &'static str {
        match self {
            Self::Des => "RFC3414 §8（CBC-DES）",
            Self::Aes => "RFC3826 §3（CFB128-AES-128）",
        }
    }

    /// 本实现是否支持（DES 与 AES 都已落地）。
    #[must_use]
    pub const fn is_implemented(self) -> bool {
        true
    }
}

/// 本地化隐私密钥：`privKey = Kul 前 16 字节`。
///
/// 返回 `None` 只可能在口令为空或 `Kul` 短于 16 字节时发生（MD5 给 16、SHA-1 给 20，都够）。
#[must_use]
pub fn localized_priv_key(auth: AuthProtocol, password: &str, engine_id: &[u8]) -> Option<Vec<u8>> {
    let kul = auth.localize_key(password, engine_id)?;
    if kul.len() < PRIV_KEY_LEN {
        return None;
    }
    kul.get(..PRIV_KEY_LEN).map(<[u8]>::to_vec)
}

/// 隐私 IV（按协议分别推导；返回长度 = [`PrivProtocol::block_len`]）。
///
/// # Errors
/// `salt` 不是 8 字节、`privKey` 短于 16 字节，或 `engineBoots` / `engineTime` 超出 32 bit。
pub fn privacy_iv(
    protocol: PrivProtocol,
    priv_key: &[u8],
    salt: &[u8],
    engine_boots: i64,
    engine_time: i64,
) -> DomainResult<Vec<u8>> {
    if salt.len() != PRIV_SALT_LEN {
        return Err(DomainError::Parse(format!(
            "SNMP v3 msgPrivacyParameters 必须是 {PRIV_SALT_LEN} 字节，实际 {}",
            salt.len()
        )));
    }
    if priv_key.len() < PRIV_KEY_LEN {
        return Err(DomainError::Internal(format!("SNMP v3 隐私密钥短于 {PRIV_KEY_LEN} 字节（本地化口令异常）")));
    }
    match protocol {
        // RFC3826 §3.1.2.1：IV = engineBoots(4,BE) ‖ engineTime(4,BE) ‖ salt(8)
        PrivProtocol::Aes => {
            let mut iv = Vec::with_capacity(AES_BLOCK_LEN);
            iv.extend_from_slice(&u32_be(engine_boots, "engineBoots")?);
            iv.extend_from_slice(&u32_be(engine_time, "engineTime")?);
            iv.extend_from_slice(salt);
            Ok(iv)
        }
        // RFC3414 §8.1.1.1：pre-IV = privKey[8..16]；IV = pre-IV XOR salt
        PrivProtocol::Des => {
            let pre_iv = priv_key
                .get(8..PRIV_KEY_LEN)
                .ok_or_else(|| DomainError::Internal("SNMP v3 DES pre-IV 取值失败（隐私密钥长度不足）".to_string()))?;
            Ok(pre_iv.iter().zip(salt.iter()).map(|(left, right)| left ^ right).collect())
        }
    }
}

/// 加密明文（发送侧：单测/模拟器/审计复现用）。
///
/// DES 走 CBC 并补齐到 8 的整数倍（补齐值 0x00，RFC 允许任意值）；AES 走 CFB128 原样输出。
///
/// # Errors
/// 密钥/salt/IV 推导失败，或明文为空（空的 ScopedPDU 不合法，宁可显式报错）。
pub fn encrypt(
    protocol: PrivProtocol,
    priv_key: &[u8],
    salt: &[u8],
    engine_boots: i64,
    engine_time: i64,
    plaintext: &[u8],
) -> DomainResult<Vec<u8>> {
    if plaintext.is_empty() {
        return Err(DomainError::Validation("SNMP v3 待加密的 ScopedPDU 为空".to_string()));
    }
    let iv = privacy_iv(protocol, priv_key, salt, engine_boots, engine_time)?;
    match protocol {
        PrivProtocol::Aes => {
            aes_cfb128(&fixed16(priv_key, "密钥")?, &fixed16(&iv, "IV")?, plaintext, CfbDirection::Encrypt)
        }
        PrivProtocol::Des => {
            let mut padded = plaintext.to_vec();
            if !padded.len().is_multiple_of(DES_BLOCK_LEN) {
                let pad = DES_BLOCK_LEN - (padded.len() % DES_BLOCK_LEN);
                padded.extend(std::iter::repeat_n(0_u8, pad));
            }
            des_cbc_encrypt(fixed8(priv_key, "密钥")?, fixed8(&iv, "IV")?, &padded)
        }
    }
}

/// 解密密文（接收侧主路径）。
///
/// # Errors
/// `engineBoots`/`engineTime` 越界、密钥/salt 长度非法、密文为空或长度不是分组整数倍（DES）。
pub fn decrypt(
    protocol: PrivProtocol,
    priv_key: &[u8],
    salt: &[u8],
    engine_boots: i64,
    engine_time: i64,
    ciphertext: &[u8],
) -> DomainResult<Vec<u8>> {
    if ciphertext.is_empty() {
        return Err(DomainError::Parse("SNMP v3 加密 ScopedPDU 为空".to_string()));
    }
    let iv = privacy_iv(protocol, priv_key, salt, engine_boots, engine_time)?;
    match protocol {
        PrivProtocol::Aes => {
            aes_cfb128(&fixed16(priv_key, "密钥")?, &fixed16(&iv, "IV")?, ciphertext, CfbDirection::Decrypt)
        }
        PrivProtocol::Des => {
            if !ciphertext.len().is_multiple_of(DES_BLOCK_LEN) {
                // RFC3414 §8.1.1.3：长度不是 8 的整数倍 ⇒ 直接判解密失败（不补齐、不猜）
                return Err(DomainError::Parse(format!(
                    "SNMP v3 DES 密文长度 {} 不是 {DES_BLOCK_LEN} 的整数倍（RFC3414 §8.1.1.3）",
                    ciphertext.len()
                )));
            }
            des_cbc_decrypt(fixed8(priv_key, "密钥")?, fixed8(&iv, "IV")?, ciphertext)
        }
    }
}

/// 按 BER TLV 自身长度剥掉 DES 补齐字节，返回 `(ScopedPDU TLV, 补齐字节数)`。
///
/// RFC3414 §8.1.1.3：「解密时补齐被忽略」——即**靠明文里 TLV 的 length 字段**确定真实边界，
/// 而不是按补齐规则反推。因此这里解析 TLV 头（不解析内容），用其声明长度切出真实明文。
///
/// # Errors
/// 明文不是合法 TLV、声明长度越过缓冲区（说明解密失败/密钥错误）。
pub fn strip_padding(plaintext: &[u8]) -> DomainResult<(&[u8], usize)> {
    let mut reader = ber::Reader::new(plaintext);
    let (tag, body, body_offset) = reader.read_tlv_at()?;
    if tag != ber::TAG_SEQUENCE {
        return Err(DomainError::Parse(format!(
            "SNMP v3 解密后的 ScopedPDU 必须是 SEQUENCE，实际 0x{tag:02x}（密钥错误或报文被篡改）"
        )));
    }
    let consumed = body_offset.saturating_add(body.len());
    if consumed > plaintext.len() {
        return Err(DomainError::Parse("SNMP v3 解密后 ScopedPDU 长度越界".to_string()));
    }
    let padding = plaintext.len().saturating_sub(consumed);
    Ok((plaintext.get(..consumed).unwrap_or(plaintext), padding))
}

/// `salt` 生成器：DES 用 `engineBoots ‖ 计数器`，AES 用伪随机初始的 64 bit 计数器（RFC 推荐）。
///
/// 唯一性由"单调递增计数器"保证（同一密钥下不重复 IV）；计数器初值取当前纳秒时间，
/// 避免进程重启后与上一次会话撞车（RFC 要求"绝不为同一密钥生成重复 IV"）。
#[derive(Debug)]
pub struct SaltGenerator {
    counter: AtomicU64,
}

impl SaltGenerator {
    /// 以当前时间为伪随机初值构造。
    #[must_use]
    pub fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|delta| delta.as_nanos())
            .unwrap_or(0);
        Self { counter: AtomicU64::new(u64::try_from(seed & 0xffff_ffff_ffff_ffff).unwrap_or(0)) }
    }

    /// 取下一个 salt（DES：`engineBoots(4,BE) ‖ 计数器低 32 位(4,BE)`；AES：计数器 64 bit BE）。
    ///
    /// # Errors
    /// DES 的 `engineBoots` 超出 32 bit。
    pub fn next_salt(&self, protocol: PrivProtocol, engine_boots: i64) -> DomainResult<Vec<u8>> {
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        match protocol {
            PrivProtocol::Aes => Ok(counter.to_be_bytes().to_vec()),
            PrivProtocol::Des => {
                let mut salt = u32_be(engine_boots, "engineBoots")?.to_vec();
                salt.extend_from_slice(&u32::try_from(counter & 0xffff_ffff).unwrap_or(0).to_be_bytes());
                Ok(salt)
            }
        }
    }
}

impl Default for SaltGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 分组密码：CBC-DES / CFB128-AES（模式按规范显式实现）
// ---------------------------------------------------------------------------

/// `i64` → 32 bit 大端（USM 的 `engineBoots` / `engineTime` 都是 32 bit）。
fn u32_be(value: i64, field: &str) -> DomainResult<[u8; 4]> {
    u32::try_from(value)
        .map(u32::to_be_bytes)
        .map_err(|_| DomainError::Parse(format!("SNMP v3 {field}={value} 超出 32 bit 范围")))
}

/// 取 `N` 字节定长值（密钥 / IV）；长度不足 ⇒ `None`（由调用方给出分类错误）。
fn fixed<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.get(..N).and_then(|slice| <[u8; N]>::try_from(slice).ok())
}

/// 取 8 字节定长值（DES 密钥 / IV）。
fn fixed8(bytes: &[u8], what: &str) -> DomainResult<[u8; 8]> {
    fixed::<DES_BLOCK_LEN>(bytes)
        .ok_or_else(|| DomainError::Internal(format!("SNMP v3 DES {what} 长度不足 {DES_BLOCK_LEN} 字节")))
}

/// 取 16 字节定长值（AES 密钥 / IV）。
fn fixed16(bytes: &[u8], what: &str) -> DomainResult<[u8; 16]> {
    fixed::<AES_BLOCK_LEN>(bytes)
        .ok_or_else(|| DomainError::Internal(format!("SNMP v3 AES {what} 长度不足 {AES_BLOCK_LEN} 字节")))
}

/// CBC 加密（调用方保证 `data.len()` 是 8 的整数倍；密钥/IV 按值传——都是 8 字节定长小值）。
fn des_cbc_encrypt(key: [u8; 8], iv: [u8; 8], data: &[u8]) -> DomainResult<Vec<u8>> {
    let cipher = Des::new_from_slice(&key).map_err(|e| DomainError::Internal(format!("DES 密钥非法: {e}")))?;
    let mut out = data.to_vec();
    let mut previous = iv;
    for chunk in out.chunks_exact_mut(DES_BLOCK_LEN) {
        for (byte, mask) in chunk.iter_mut().zip(previous.iter()) {
            *byte ^= mask;
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        previous.copy_from_slice(chunk);
    }
    Ok(out)
}

/// CBC 解密（调用方保证 `data.len()` 是 8 的整数倍；不剥补齐——按 RFC 交 [`strip_padding`]）。
fn des_cbc_decrypt(key: [u8; 8], iv: [u8; 8], data: &[u8]) -> DomainResult<Vec<u8>> {
    let cipher = Des::new_from_slice(&key).map_err(|e| DomainError::Internal(format!("DES 密钥非法: {e}")))?;
    let mut out = data.to_vec();
    let mut previous = iv;
    for chunk in out.chunks_exact_mut(DES_BLOCK_LEN) {
        let ciphertext: [u8; 8] =
            chunk.try_into().map_err(|_| DomainError::Internal("DES 分组长度异常".to_string()))?;
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
        for (byte, mask) in chunk.iter_mut().zip(previous.iter()) {
            *byte ^= mask;
        }
        previous = ciphertext;
    }
    Ok(out)
}

/// CFB 的运算方向：**反馈值取哪一侧**是加密与解密的唯一差别。
///
/// CFB 的密钥流都来自 `E(feedback)`，而反馈块恒为**密文块**：
/// 加密时密文是输出（取输出），解密时密文是输入（取输入）。混淆这一点的典型 bug 是
/// "首块对、第二块起错"——单测里的 NIST 向量（4 个块）就是为了钉死这个差异。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CfbDirection {
    /// 加密：`C = P XOR E(feedback)`，反馈取刚产出的密文块。
    Encrypt,
    /// 解密：`P = C XOR E(feedback)`，反馈取刚读入的密文块。
    Decrypt,
}

/// CFB128（S=128）加解密：密钥流 `E(feedback)`，逐段 XOR。
///
/// 末段不足 16 字节时只输出对应字节数（NIST SP800-38A 对 CFB 的定义），无需再反馈。
fn aes_cfb128(key: &[u8; 16], iv: &[u8; 16], data: &[u8], direction: CfbDirection) -> DomainResult<Vec<u8>> {
    let cipher = Aes128::new_from_slice(key).map_err(|e| DomainError::Internal(format!("AES 密钥非法: {e}")))?;
    let mut out = Vec::with_capacity(data.len());
    let mut feedback = *iv;
    for chunk in data.chunks(AES_BLOCK_LEN) {
        let mut keystream = feedback;
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut keystream));
        let mut produced = [0_u8; AES_BLOCK_LEN];
        for (index, byte) in chunk.iter().enumerate() {
            if let (Some(slot), Some(mask)) = (produced.get_mut(index), keystream.get(index)) {
                *slot = byte ^ mask;
            }
        }
        if chunk.len() == AES_BLOCK_LEN {
            // 反馈块 = 密文块：加密取输出、解密取输入
            let mut next = [0_u8; AES_BLOCK_LEN];
            let source: &[u8] = match direction {
                CfbDirection::Encrypt => &produced,
                CfbDirection::Decrypt => chunk,
            };
            next.copy_from_slice(source.get(..AES_BLOCK_LEN).unwrap_or(source));
            feedback = next;
        }
        out.extend_from_slice(produced.get(..chunk.len()).unwrap_or(&produced));
    }
    Ok(out)
}
