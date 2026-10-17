//! 流式收帧：`FrameReader` / `FrameBatch`（半个帧的缓存与 EOF 计数）与 `SyslogConnection`。

use super::*;

/// 已握手的 TCP 连接上"已有帧在手、短暂收集窗口"的等待时长。
///
/// 语义：第一次读阻塞到 `idle_timeout`（判断连接是否还活着）；一旦手里有帧，
/// 就只再等这么久去攒更多帧，然后交出去 —— 避免低速率设备（如 1 条/秒）
/// 的帧被"攒到空闲超时"才上送。
const FRAME_COLLECT_WINDOW: Duration = Duration::from_millis(50);

/// 一次流式读取的结果（TCP 与 TLS 共用）。
///
/// **语义**：`frames` 是**本次调用**读到的完整帧，不是整条连接的全部帧 ——
/// 调用方应在连接生命周期内循环调用，直到 `eof` 或 `idle_timeout` 为真。
/// 这样"单连接只读 N 帧就丢弃剩余字节"的静默丢数据在结构上不可能再发生。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameBatch {
    /// 本次读到的完整帧。
    pub frames: Vec<Vec<u8>>,
    /// 本次被分帧层丢弃的帧数（畸形长度头 / 超长帧 / 连接关闭时的半帧）。
    ///
    /// `dropped > 0` 表示分帧已失步（缓冲区被整段丢弃），调用方应**断开该连接**，
    /// 并把该计数写进 `agf_ingest_syslog_frames_dropped_total`（丢弃必须可观测）。
    pub dropped: usize,
    /// 对端已关闭连接（EOF）。
    pub eof: bool,
    /// 空闲超时：连接仍开着，但 `idle_timeout` 内没有新数据。
    pub idle_timeout: bool,
}

/// 流式 syslog 分帧读取器（TCP 与 TLS 同一份实现：分帧与洪泛保护只写一遍）。
#[derive(Debug)]
pub struct FrameReader<S> {
    stream: S,
    buf: Vec<u8>,
    max_message_bytes: usize,
    max_frames_per_read: usize,
    idle_timeout: Duration,
}

impl<S: AsyncRead + Unpin> FrameReader<S> {
    /// 构造。
    ///
    /// `max_frames_per_read` 是**单次调用**返回的帧数上限（**不是**每连接上限）；
    /// 连接生命周期内的总帧数不受它限制。
    #[must_use]
    pub fn new(stream: S, max_message_bytes: usize, max_frames_per_read: usize, idle_timeout: Duration) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            max_message_bytes: max_message_bytes.max(1),
            max_frames_per_read: max_frames_per_read.max(1),
            idle_timeout,
        }
    }

    /// 读取一批帧。
    ///
    /// # Errors
    /// 读取出错（对端 RST、底层 I/O 故障）。EOF 与空闲超时**不是错误**，
    /// 通过 [`FrameBatch`] 的 `eof` / `idle_timeout` 汇报。
    pub async fn read_batch(&mut self) -> DomainResult<FrameBatch> {
        let ceiling = self.max_message_bytes.saturating_mul(8).max(8_192);
        let mut chunk = vec![0_u8; 8_192];
        let mut frames: Vec<Vec<u8>> = Vec::new();
        let mut dropped = 0_usize;
        let mut wait = self.idle_timeout;
        loop {
            if !self.buf.is_empty() {
                let split = SyslogFraming::split(&self.buf, self.max_message_bytes);
                frames.extend(split.frames);
                dropped = dropped.saturating_add(split.dropped);
                if split.consumed > 0 {
                    self.buf.drain(..split.consumed);
                }
            }
            if frames.len() >= self.max_frames_per_read || dropped > 0 {
                // 到量或分帧已失步：先把已到手的帧交出去（失步由调用方断连）。
                return Ok(FrameBatch { frames, dropped, eof: false, idle_timeout: false });
            }
            match tokio::time::timeout(wait, self.stream.read(&mut chunk)).await {
                Err(_) => {
                    // 半帧留在缓冲区：如实计入 dropped，不假装收到、也不静默丢弃。
                    let leftover = usize::from(!self.buf.is_empty());
                    let idle = frames.is_empty();
                    return Ok(FrameBatch {
                        frames,
                        dropped: dropped.saturating_add(leftover),
                        eof: false,
                        idle_timeout: idle,
                    });
                }
                Ok(Err(e)) => return Err(DomainError::Internal(format!("读取 TCP 流失败: {e}"))),
                Ok(Ok(0)) => {
                    let leftover = usize::from(!self.buf.is_empty());
                    return Ok(FrameBatch {
                        frames,
                        dropped: dropped.saturating_add(leftover),
                        eof: true,
                        idle_timeout: false,
                    });
                }
                Ok(Ok(n)) => {
                    self.buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
                    if self.buf.len() > ceiling {
                        warn!(bytes = self.buf.len(), "Syslog TCP 缓冲区超限，丢弃半帧并断开连接");
                        self.buf.clear();
                        return Ok(FrameBatch {
                            frames,
                            dropped: dropped.saturating_add(1),
                            eof: false,
                            idle_timeout: false,
                        });
                    }
                    // 手里已有帧：只再等一个短收集窗口，避免低速率连接迟迟不上送。
                    wait = FRAME_COLLECT_WINDOW;
                }
            }
        }
    }
}

/// 一条已接入的 syslog 连接（TCP / TLS）+ 对端地址。
#[derive(Debug)]
pub struct SyslogConnection<S> {
    reader: FrameReader<S>,
    peer: SocketAddr,
    pub(super) mutual_tls: bool,
}

impl<S: AsyncRead + Unpin> SyslogConnection<S> {
    /// 组装（监听器 `accept*` 内部使用；测试也可直接构造）。
    #[must_use]
    pub fn new(
        stream: S,
        peer: SocketAddr,
        max_message_bytes: usize,
        max_frames_per_read: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            reader: FrameReader::new(stream, max_message_bytes, max_frames_per_read, idle_timeout),
            peer,
            mutual_tls: false,
        }
    }

    /// Attributes obtained by the TCP/TLS listener after accepting the connection.
    #[must_use]
    pub fn transport_peer(&self) -> crate::pipeline::TransportPeer {
        crate::pipeline::TransportPeer { ip: Some(self.peer.ip()), mutual_tls: self.mutual_tls }
    }

    /// 对端地址（写入原始日志的 `origin`）。
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// 读取一批帧（见 [`FrameBatch`]；应在连接生命周期内循环调用）。
    ///
    /// # Errors
    /// 读取出错。
    pub async fn read_batch(&mut self) -> DomainResult<FrameBatch> {
        self.reader.read_batch().await
    }

    /// 取回底层流（测试用：断言 TLS 握手结果等）。
    #[must_use]
    pub fn into_inner(self) -> S {
        self.reader.stream
    }
}
