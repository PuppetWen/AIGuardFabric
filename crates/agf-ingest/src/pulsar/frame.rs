//! Pulsar 帧编解码：长度前缀 + MAGIC `0x0e01` + CRC32C（**纯函数**，无 IO、可离线单测）。
//!
//! ## 线路格式（与 `Commands.java` 的 `serialize*WithSize` 逐字节对应）
//!
//! ```text
//! 命令帧   : [TOTAL_SIZE u32 BE][CMD_SIZE u32 BE][BaseCommand]
//! 消息帧   : [TOTAL_SIZE u32 BE][CMD_SIZE u32 BE][BaseCommand]
//!            [MAGIC u16 BE = 0x0e01][CHECKSUM u32 BE][METADATA_SIZE u32 BE]
//!            [MessageMetadata][PAYLOAD]
//! ```
//!
//! * `TOTAL_SIZE` = **其后所有字节数**（不含自己那 4 字节）：
//!   命令帧 `= 4 + CMD_SIZE`；消息帧 `= 4 + CMD_SIZE + 6 + 4 + METADATA_SIZE + PAYLOAD_SIZE`；
//! * `CHECKSUM` = CRC32C(Castagnoli)，覆盖 `METADATA_SIZE` 字段 4 字节 + `MessageMetadata`
//!   + `PAYLOAD`（**不含** MAGIC 与 CHECKSUM 自身）；
//! * 消息帧可能先出现 **broker entry metadata**（`Commands.addBrokerEntryMetadata`，
//!   MAGIC `0x0e02` + `u32` 长度 + 正文）；默认配置下没有，但本解码器**容忍并跳过**它，
//!   否则一旦运维开了 `brokerEntryMetadataInterceptors` 就会整条解不出来。
//!
//! CRC32C 用 `crc32c` crate（标准 Castagnoli，与 Go 客户端
//! `crc32.MakeTable(crc32.Castagnoli)` 同级）；`ChecksumType::Crc32c` 是 Pulsar 默认，
//! 因此校验失败**必须**按 `CommandAck.validation_error = ChecksumMismatch`
//! 显式回执并计数（见 [`super::receiver`]）。

use prost::Message as _;

use super::proto::{BaseCommand, CommandMessage, MessageMetadata, command_type, compression_type};

/// 消息帧的 MAGIC（`Commands.magicCrc32c`）。
pub const MAGIC_CRC32C: u16 = 0x0e01;

/// broker entry metadata 的 MAGIC（`Commands.magicBrokerEntryMetadata`）。
pub const MAGIC_BROKER_ENTRY_METADATA: u16 = 0x0e02;

/// 单帧上限（Pulsar broker 默认 `maxMessageSize` 5 MiB + 帧头余量）。
///
/// 超过即**拒绝并把连接判为不可信**（与 `PulsarDecoder` 的 `TooLongFrameException` 同义）：
/// 静默截断会让后续帧全部错位。
pub const MAX_FRAME_BYTES: usize = 5 * 1024 * 1024 + 64 * 1024;

/// 帧解析错误（**分类**，供重连/ack 决策使用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// `TOTAL_SIZE` 超过 [`MAX_FRAME_BYTES`]。
    TooLarge {
        /// 声明的大小。
        size: usize,
        /// 上限。
        max: usize,
    },
    /// 帧不完整（流式读取时属于"再等等"，非致命）。
    Truncated {
        /// 需要多少字节。
        need: usize,
        /// 实际有多少。
        have: usize,
    },
    /// protobuf 解码失败（`BaseCommand` / `MessageMetadata`）。
    Decode(String),
    /// 消息帧魔数不对（不是 `0x0e01`）。
    BadMagic(u16),
    /// 消息帧缺少 `METADATA_SIZE` 字段。
    MissingMetadataSize,
    /// `METADATA_SIZE` 超出帧内剩余字节。
    MetadataOutOfRange {
        /// 声明的 metadata 长度。
        metadata_size: usize,
        /// 帧内剩余字节。
        remaining: usize,
    },
    /// CRC32C 校验失败（**不是**"没有 checksum"——缺 checksum 属合法老客户端行为）。
    ChecksumMismatch {
        /// broker 写入的校验和。
        expected: u32,
        /// 本地重算值。
        actual: u32,
    },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { size, max } => write!(f, "Pulsar 帧过大：{size} > {max}"),
            Self::Truncated { need, have } => write!(f, "Pulsar 帧不完整：需要 {need} 字节，只有 {have}"),
            Self::Decode(reason) => write!(f, "Pulsar protobuf 解码失败：{reason}"),
            Self::BadMagic(magic) => {
                write!(f, "Pulsar 消息帧魔数错误：0x{magic:04x}（应为 0x{MAGIC_CRC32C:04x}）")
            }
            Self::MissingMetadataSize => write!(f, "Pulsar 消息帧缺少 METADATA_SIZE"),
            Self::MetadataOutOfRange { metadata_size, remaining } => {
                write!(f, "Pulsar METADATA_SIZE={metadata_size} 超出帧内剩余 {remaining} 字节")
            }
            Self::ChecksumMismatch { expected, actual } => {
                write!(f, "Pulsar CRC32C 校验失败：broker=0x{expected:08x} 本地=0x{actual:08x}")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// 一帧的解码结果。
///
/// `payload` **借用**输入切片（大消息不复制）；调用方需要保留时自行 `to_vec()`。
/// 两个变体都装箱：`BaseCommand` 与 `MessageMetadata` 都比"命令/消息裸结构"大一个数量级，
/// 不装箱会让整个枚举（以及每一条命令的栈占用）跟着膨胀。
#[derive(Debug)]
pub enum DecodedFrame<'a> {
    /// 纯命令帧（CONNECTED / SUCCESS / ERROR / FLOW / PING / CLOSE_CONSUMER…）。
    Command(Box<BaseCommand>),
    /// 消息帧：命令 + 元数据 + 载荷。
    Message {
        /// `CommandMessage`（consumer_id / message_id / redelivery_count）。
        command: CommandMessage,
        /// `MessageMetadata`（装箱：它比其它变体大一个数量级，避免枚举整体膨胀）。
        metadata: Box<MessageMetadata>,
        /// 原始载荷（未解压、未拆 batch；见 [`super::batch`]）。
        payload: &'a [u8],
        /// 该帧是否带 CRC32C（`false` = 对端用 `ChecksumType.None`，属合法）。
        checksummed: bool,
    },
}

/// 计算 Pulsar 的 CRC32C：覆盖 `METADATA_SIZE` 字段 + metadata + payload。
#[must_use]
pub fn checksum_of(metadata_size_field: &[u8], metadata: &[u8], payload: &[u8]) -> u32 {
    let mut hasher = crc32c::crc32c_append(0, metadata_size_field);
    hasher = crc32c::crc32c_append(hasher, metadata);
    crc32c::crc32c_append(hasher, payload)
}

/// 编码一个**命令帧**（无 metadata / payload）。
#[must_use]
pub fn encode_command_frame(command: &BaseCommand) -> Vec<u8> {
    let cmd_size = command.encoded_len();
    let total_size = 4 + cmd_size;
    let mut out = Vec::with_capacity(4 + total_size);
    out.extend_from_slice(&u32::try_from(total_size).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(&u32::try_from(cmd_size).unwrap_or(u32::MAX).to_be_bytes());
    command.encode(&mut out).ok();
    out
}

/// 编码一个**消息帧**（供单测与模拟 producer 使用；生产路径只解码）。
///
/// `with_checksum = false` 时省略 `[MAGIC][CHECKSUM]` 共 6 字节
/// （等价于 `ChecksumType.None`，用于验证"对端不发校验和"这条分支）。
///
/// # Errors
/// `cmd_size` / `metadata_size` / `total_size` 超出 `u32`（现实中不可能，仍如实返回错误）。
pub fn encode_message_frame(
    command: &BaseCommand,
    metadata: &MessageMetadata,
    payload: &[u8],
    with_checksum: bool,
) -> Result<Vec<u8>, FrameError> {
    let cmd_size = command.encoded_len();
    let mut metadata_buf = Vec::new();
    metadata.encode(&mut metadata_buf).map_err(|e| FrameError::Decode(format!("MessageMetadata 编码失败：{e}")))?;
    let metadata_size = metadata_buf.len();
    let checksum_len = if with_checksum { 6 } else { 0 };
    let total_size = 4 + cmd_size + checksum_len + 4 + metadata_size + payload.len();
    let to_u32 = |value: usize| -> Result<u32, FrameError> {
        u32::try_from(value).map_err(|_| FrameError::TooLarge { size: value, max: MAX_FRAME_BYTES })
    };
    let total = to_u32(total_size)?;
    let cmd_len = to_u32(cmd_size)?;
    let meta_len = to_u32(metadata_size)?;

    let mut out = Vec::with_capacity(4 + total_size);
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&cmd_len.to_be_bytes());
    command.encode(&mut out).ok();
    if with_checksum {
        let size_field = meta_len.to_be_bytes();
        let checksum = checksum_of(&size_field, &metadata_buf, payload);
        out.extend_from_slice(&MAGIC_CRC32C.to_be_bytes());
        out.extend_from_slice(&checksum.to_be_bytes());
    }
    out.extend_from_slice(&meta_len.to_be_bytes());
    out.extend_from_slice(&metadata_buf);
    out.extend_from_slice(payload);
    Ok(out)
}

/// 读长度前缀：返回"整帧（不含长度前缀本身）的字节数"。
///
/// * `Ok(None)` ⇒ 前缀还没收够 4 字节（流式读取继续等）；
/// * `Err(TooLarge)` ⇒ 声明长度超限，必须断开连接（不能继续按该长度等下去）。
///
/// # Errors
/// 声明长度超过 [`MAX_FRAME_BYTES`]。
pub fn peek_frame_len(prefix: &[u8]) -> Result<Option<usize>, FrameError> {
    if prefix.len() < 4 {
        return Ok(None);
    }
    let mut head = [0_u8; 4];
    head.copy_from_slice(&prefix[..4]);
    let declared = u32::from_be_bytes(head) as usize;
    if declared > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { size: declared, max: MAX_FRAME_BYTES });
    }
    Ok(Some(declared))
}

/// 解码一个完整帧（`frame` = **含** 4 字节 `TOTAL_SIZE` 的整帧）。
///
/// # Errors
/// 见 [`FrameError`]：长度不符、protobuf 解码失败、魔数错、CRC32C 不匹配。
pub fn decode_frame(frame: &[u8]) -> Result<DecodedFrame<'_>, FrameError> {
    let declared = match peek_frame_len(frame)? {
        Some(len) => len,
        None => return Err(FrameError::Truncated { need: 4, have: frame.len() }),
    };
    if frame.len() < 4 + declared {
        return Err(FrameError::Truncated { need: 4 + declared, have: frame.len() });
    }
    let body = &frame[4..4 + declared];
    if body.len() < 4 {
        return Err(FrameError::Truncated { need: 4, have: body.len() });
    }
    let mut head = [0_u8; 4];
    head.copy_from_slice(&body[..4]);
    let cmd_size = u32::from_be_bytes(head) as usize;
    if body.len() < 4 + cmd_size {
        return Err(FrameError::Truncated { need: 4 + cmd_size, have: body.len() });
    }
    let command =
        BaseCommand::decode(&body[4..4 + cmd_size]).map_err(|e| FrameError::Decode(format!("BaseCommand: {e}")))?;
    let rest = &body[4 + cmd_size..];
    if command.command_type() != command_type::MESSAGE {
        return Ok(DecodedFrame::Command(Box::new(command)));
    }

    let command_message = command.message.clone().unwrap_or_default();
    let (metadata_slice, payload, checksummed) = split_metadata_and_payload(rest)?;
    let metadata =
        MessageMetadata::decode(metadata_slice).map_err(|e| FrameError::Decode(format!("MessageMetadata: {e}")))?;
    Ok(DecodedFrame::Message { command: command_message, metadata: Box::new(metadata), payload, checksummed })
}

/// 拆出 `[brokerEntryMetadata?][MAGIC][CHECKSUM]?[METADATA_SIZE][METADATA][PAYLOAD]`。
///
/// 返回 `(metadata 字节, payload 字节, 是否校验过 CRC32C)`。
fn split_metadata_and_payload(rest: &[u8]) -> Result<(&[u8], &[u8], bool), FrameError> {
    // ① 可选的 broker entry metadata（MAGIC 0x0e02）：[MAGIC u16][SIZE u32][正文]
    let mut cursor = rest;
    if cursor.len() >= 2 {
        let mut magic = [0_u8; 2];
        magic.copy_from_slice(&cursor[..2]);
        if u16::from_be_bytes(magic) == MAGIC_BROKER_ENTRY_METADATA {
            if cursor.len() < 6 {
                return Err(FrameError::MissingMetadataSize);
            }
            let mut size = [0_u8; 4];
            size.copy_from_slice(&cursor[2..6]);
            let size = u32::from_be_bytes(size) as usize;
            let skip = 6 + size;
            if cursor.len() < skip {
                return Err(FrameError::MetadataOutOfRange { metadata_size: size, remaining: cursor.len() });
            }
            cursor = &cursor[skip..];
        }
    }
    // ② 可选的 CRC32C 头：[MAGIC u16 = 0x0e01][CHECKSUM u32]
    let mut checksummed = false;
    let mut expected = 0_u32;
    if cursor.len() >= 2 {
        let mut magic = [0_u8; 2];
        magic.copy_from_slice(&cursor[..2]);
        let magic = u16::from_be_bytes(magic);
        if magic == MAGIC_CRC32C {
            if cursor.len() < 6 {
                return Err(FrameError::MissingMetadataSize);
            }
            let mut sum = [0_u8; 4];
            sum.copy_from_slice(&cursor[2..6]);
            expected = u32::from_be_bytes(sum);
            checksummed = true;
            cursor = &cursor[6..];
        } else if magic == MAGIC_BROKER_ENTRY_METADATA {
            // 已经跳过 broker entry metadata 后不该再出现；如实报错而不是继续瞎猜
            return Err(FrameError::BadMagic(magic));
        }
    }
    // ③ METADATA_SIZE + METADATA
    if cursor.len() < 4 {
        return Err(FrameError::MissingMetadataSize);
    }
    let mut size = [0_u8; 4];
    size.copy_from_slice(&cursor[..4]);
    let metadata_size = u32::from_be_bytes(size) as usize;
    if cursor.len() < 4 + metadata_size {
        return Err(FrameError::MetadataOutOfRange { metadata_size, remaining: cursor.len() - 4 });
    }
    if checksummed {
        // CRC 覆盖 [METADATA_SIZE 4 字节][METADATA][PAYLOAD] —— 即整个 cursor
        let actual = crc32c::crc32c(cursor);
        if actual != expected {
            return Err(FrameError::ChecksumMismatch { expected, actual });
        }
    }
    let metadata = &cursor[4..4 + metadata_size];
    let payload = &cursor[4 + metadata_size..];
    Ok((metadata, payload, checksummed))
}

/// 该压缩类型是否受支持（`NONE` / `ZLIB`）。
#[must_use]
pub const fn compression_supported(compression: i32) -> bool {
    matches!(compression, compression_type::NONE | compression_type::ZLIB)
}

/// 压缩类型名（日志/指标）。
#[must_use]
pub const fn compression_name(compression: i32) -> &'static str {
    match compression {
        compression_type::NONE => "NONE",
        compression_type::LZ4 => "LZ4",
        compression_type::ZLIB => "ZLIB",
        compression_type::ZSTD => "ZSTD",
        compression_type::SNAPPY => "SNAPPY",
        _ => "UNKNOWN",
    }
}
