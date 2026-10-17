//! 插件稳定 ABI（v1）——**本 crate 唯一允许出现 `unsafe` 的模块**。
//!
//! # 为什么需要"版本化符号 + `repr(C)` 描述符"
//!
//! Rust **没有稳定 ABI**：`String` / `Vec` / trait object / enum 的布局都可能随编译器版本变化，
//! 所以跨动态库边界只能传 **C ABI 类型**。本模块的约定：
//!
//! * 插件导出**唯一一个**固定名字的符号 `agf_plugin_descriptor_v1`
//!   （名字里带 `_v1`：将来若要改布局就直接加 `_v2`，老宿主不会误读新插件）；
//! * 该符号返回 `#[repr(C)]` 的 [`PluginDescriptor`] 指针，描述符里另有 `abi_version`
//!   字段做**字段级二次门禁**（同一个 v1 符号下，布局改了也能被拒）；
//! * 描述符带一张**函数指针表** [`PluginVTable`]（`normalize` / `notify` /
//!   `free_string` / `last_error`），全部 `extern "C"`、全部可空；
//! * 所有字符串一律 **NUL 结尾 UTF-8**（`*const c_char` / `*mut c_char`），
//!   **绝不跨边界传 `String` / `Vec` / trait object**。
//!
//! # 调用约定细节（插件作者必须遵守）
//!
//! * `normalize(input, out_len) -> *mut c_char`：返回堆上 UTF-8 JSON，长度写进 `out_len`；
//!   返回的指针**必须**能用同一张表的 `free_string` 释放（宿主会释放，插件不得重复释放）；
//! * `notify(target, message) -> i32`：`0` 表示成功，非 `0` 表示业务失败（宿主会去读
//!   `last_error` 取原因）；
//! * `last_error() -> *const c_char`：返回**静态**字符串指针（`'static`，宿主不释放）；
//! * 插件把符号函数定义成 `unsafe extern "C" fn` 或 `extern "C" fn` 都可以 ——
//!   对宿主而言调用是否 `unsafe` 由 ABI 决定，两者机器码一致。
//!
//! # 安全边界
//!
//! **插件是同进程代码，等同宿主权限，只应加载可信插件。** 本模块的 `unsafe` 只保证
//! "按 ABI 约定正确地读指针/调函数"，**不提供任何隔离**（详见 crate 文档）。

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_char;
use std::path::Path;

use libloading::Library;

use crate::error::PluginError;

/// 当前宿主实现的 ABI 版本。
pub const AGF_PLUGIN_ABI_VERSION: u32 = 1;

/// 插件必须导出的版本化符号名（不含结尾 NUL）。
pub const AGF_PLUGIN_DESCRIPTOR_SYMBOL_NAME: &str = "agf_plugin_descriptor_v1";

/// 供 [`libloading::Library::get`] 使用的符号名（带结尾 NUL，避免一次分配）。
pub(crate) const AGF_PLUGIN_DESCRIPTOR_SYMBOL: &[u8] = b"agf_plugin_descriptor_v1\0";

/// 插件类型。决定描述符里**必须**提供哪些函数指针。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum PluginKind {
    /// 自定义解析器 / 归一化函数：把厂商原始日志行转成 AGF-ECS 风格 JSON。
    Normalizer = 1,
    /// 自定义通知渠道：把一条消息投递出去。
    Notifier = 2,
}

impl PluginKind {
    /// 把 ABI 传来的裸 `u32` 还原成类型；未知值返回 `None`（由调用方转成描述符非法）。
    #[must_use]
    pub const fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Normalizer),
            2 => Some(Self::Notifier),
            _ => None,
        }
    }

    /// 转成 ABI 裸值。
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// 稳定的小写名字（用于日志与配置）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normalizer => "normalizer",
            Self::Notifier => "notifier",
        }
    }
}

/// 归一化函数：返回堆上 NUL 结尾 UTF-8 JSON，字节数写进 `out_len`。
pub type AgfNormalizeFn = unsafe extern "C" fn(input: *const c_char, out_len: *mut usize) -> *mut c_char;

/// 释放 `normalize` 返回的字符串（由插件提供，避免跨分配器释放）。
pub type AgfFreeStringFn = unsafe extern "C" fn(text: *mut c_char);

/// 通知函数：`0` = 成功，非 `0` = 业务失败（原因经 `last_error` 取）。
pub type AgfNotifyFn = unsafe extern "C" fn(target: *const c_char, message: *const c_char) -> i32;

/// 取最近一次失败原因：返回 `'static` 的 NUL 结尾 UTF-8 指针（宿主不释放）。
pub type AgfLastErrorFn = unsafe extern "C" fn() -> *const c_char;

/// 函数指针表（ABI v1）。全部可空。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PluginVTable {
    /// 归一化入口（[`PluginKind::Normalizer`] 必需）。
    pub normalize: Option<AgfNormalizeFn>,
    /// 释放 `normalize` 返回内存的入口（提供了 `normalize` 就必须提供它）。
    pub free_string: Option<AgfFreeStringFn>,
    /// 通知入口（[`PluginKind::Notifier`] 必需）。
    pub notify: Option<AgfNotifyFn>,
    /// 可选：最近一次失败原因。
    pub last_error: Option<AgfLastErrorFn>,
}

impl PluginVTable {
    /// 全空的表（便于插件作者按需填字段）。
    #[must_use]
    pub const fn empty() -> Self {
        Self { normalize: None, free_string: None, notify: None, last_error: None }
    }
}

/// 插件描述符（ABI v1）—— 插件导出的 `agf_plugin_descriptor_v1()` 返回它的指针。
///
/// # 生命周期
/// 插件必须保证该指针**在插件被卸载前一直有效**（通常用 `Box::leak` 或 `static`）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PluginDescriptor {
    /// 插件声明的 ABI 版本；与宿主不匹配一律拒绝加载。
    pub abi_version: u32,
    /// 插件类型（[`PluginKind`] 的裸值）。
    pub kind: u32,
    /// 插件名（NUL 结尾 UTF-8）。
    pub name: *const c_char,
    /// 插件版本（NUL 结尾 UTF-8）。
    pub version: *const c_char,
    /// 函数指针表。
    pub vtable: PluginVTable,
    /// **前向兼容保留位：v1 必须为 0**（宿主强制校验，非 0 视为 ABI 不匹配）。
    pub reserved: u64,
}

/// 描述符的**纯数据视图**：不含函数指针，可安全地长期持有 / 打印 / 序列化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMetadata {
    /// 插件声明的 ABI 版本。
    pub abi_version: u32,
    /// 插件类型。
    pub kind: PluginKind,
    /// 插件名。
    pub name: String,
    /// 插件版本。
    pub version: String,
    /// 是否提供归一化入口。
    pub has_normalize: bool,
    /// 是否提供通知入口。
    pub has_notify: bool,
    /// 是否提供字符串释放入口（提供了 `normalize` 就必须提供它）。
    pub has_free_string: bool,
    /// 描述符保留位（宿主强制要求为 0）。
    pub reserved: u64,
}

impl PluginMetadata {
    /// 校验描述符字段。任何一条不满足都返回 [`PluginError::BadDescriptor`]。
    ///
    /// 规则（ABI v1）：
    /// * `abi_version != 0`，`reserved == 0`；
    /// * `name` / `version` 各自 1..=64 字节，`name` 只允许 `[A-Za-z0-9._-]`，
    ///   `version` 只允许可见 ASCII（`0x21..=0x7e`）；
    /// * [`PluginKind::Normalizer`] 必须有 `normalize` **且** `free_string`
    ///   （否则宿主无法释放插件分配的内存）；[`PluginKind::Notifier`] 必须有 `notify`。
    pub fn validate(&self) -> Result<(), PluginError> {
        if self.abi_version == 0 {
            return Err(PluginError::BadDescriptor("abi_version 不得为 0（0 表示未填写版本）".to_string()));
        }
        if self.reserved != 0 {
            return Err(PluginError::BadDescriptor(format!("保留位 reserved 必须为 0，实际 {}", self.reserved)));
        }
        if self.name.is_empty() || self.name.len() > 64 {
            return Err(PluginError::BadDescriptor(format!("插件名长度必须在 1..=64 字节，实际 {}", self.name.len())));
        }
        if !self.name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
            return Err(PluginError::BadDescriptor(format!(
                "插件名 `{}` 含非法字符（只允许 [A-Za-z0-9._-]）",
                self.name
            )));
        }
        if self.version.is_empty() || self.version.len() > 64 {
            return Err(PluginError::BadDescriptor(format!(
                "插件版本长度必须在 1..=64 字节，实际 {}",
                self.version.len()
            )));
        }
        if !self.version.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(PluginError::BadDescriptor(format!("插件版本 `{}` 含非可见 ASCII 字符", self.version)));
        }
        match self.kind {
            PluginKind::Normalizer => {
                if !self.has_normalize {
                    return Err(PluginError::BadDescriptor("normalizer 插件必须提供 normalize 函数指针".to_string()));
                }
                if !self.has_free_string {
                    return Err(PluginError::BadDescriptor(
                        "normalizer 插件必须同时提供 free_string（否则宿主无法释放插件分配的内存）".to_string(),
                    ));
                }
            }
            PluginKind::Notifier => {
                if !self.has_notify {
                    return Err(PluginError::BadDescriptor("notifier 插件必须提供 notify 函数指针".to_string()));
                }
            }
        }
        Ok(())
    }
}

/// 本平台动态库文件后缀（不含点）：Windows `dll`，macOS `dylib`，其余 `so`。
#[must_use]
pub const fn plugin_file_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        "dll"
    } else if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    }
}

/// 按平台约定把插件名拼成动态库文件名（Windows `name.dll`，其余 `libname.so` / `libname.dylib`）。
#[must_use]
pub fn plugin_file_name(name: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{name}.{}", plugin_file_suffix())
    } else {
        format!("lib{name}.{}", plugin_file_suffix())
    }
}

// ---------------------------------------------------------------------------
// 以下是本模块的 unsafe 部分：装载动态库、读描述符、调插件函数。
// 每个 unsafe 块都带 SAFETY 注释；除此之外 crate 内没有任何 unsafe。
// ---------------------------------------------------------------------------

/// 装载动态库（文件存在性与类型检查在这里做，错误分类明确）。
///
/// # Safety
/// 本函数内部完成全部 `unsafe` 操作；对调用者是安全函数。但请注意：
/// **装载动态库会执行插件的初始化例程**，等同调用未知外部代码——只应加载可信插件。
pub(crate) fn open_library(path: &Path) -> Result<Library, PluginError> {
    if !path.exists() {
        return Err(PluginError::NotFound(path.to_path_buf()));
    }
    if !path.is_file() {
        return Err(PluginError::NotAFile(path.to_path_buf()));
    }
    // SAFETY: `path` 已确认存在且为常规文件。`Library::new` 之所以是 unsafe fn，
    // 是因为装载会执行库内初始化例程（等同调用未知外部代码）、卸载会执行终止例程。
    // 调用方已通过 crate 文档明确"只应加载可信插件、不做沙箱承诺"，这是本 crate 的显式契约。
    unsafe { Library::new(path) }.map_err(|source| PluginError::Load { path: path.to_path_buf(), source })
}

/// 从已装载的库里读出 ABI v1 描述符并做字段校验。
pub(crate) fn read_descriptor(library: &Library) -> Result<(PluginMetadata, PluginVTable), PluginError> {
    type DescriptorFn = unsafe extern "C" fn() -> *const PluginDescriptor;

    // SAFETY: 符号名由 ABI 约定固定（`AGF_PLUGIN_DESCRIPTOR_SYMBOL` 带结尾 NUL）；
    // 声明的函数类型是 ABI 契约的一部分。若插件用了别的签名，那属于"不遵守 ABI 的插件"，
    // 后果由插件承担（同进程代码边界，文档已如实声明）。
    let symbol = unsafe { library.get::<DescriptorFn>(AGF_PLUGIN_DESCRIPTOR_SYMBOL) }.map_err(|source| {
        PluginError::MissingSymbol { symbol: AGF_PLUGIN_DESCRIPTOR_SYMBOL_NAME.to_string(), source }
    })?;

    // SAFETY: 调用 ABI 约定的 v1 符号。插件必须返回一个指向 `'static`、正确对齐的
    // `PluginDescriptor` 的指针（或空指针，下面立刻排除）。
    let raw = unsafe { symbol() };
    if raw.is_null() {
        return Err(PluginError::BadDescriptor("agf_plugin_descriptor_v1() 返回了空指针".to_string()));
    }

    // SAFETY: 上面已排除空指针；指针的有效性由插件按 ABI 约定保证（同进程、同一份 ABI 文档）。
    let descriptor: &PluginDescriptor = unsafe { &*raw };

    // SAFETY: `descriptor.name` / `descriptor.version` 按 ABI 约定要么为空指针、
    // 要么指向 NUL 结尾的 UTF-8 字符串；`c_string` 对空指针返回 None。
    let name = unsafe { c_string(descriptor.name) }
        .ok_or_else(|| PluginError::BadDescriptor("描述符 name 为空指针或不是合法 UTF-8".to_string()))?;
    // SAFETY: 同上。
    let version = unsafe { c_string(descriptor.version) }
        .ok_or_else(|| PluginError::BadDescriptor("描述符 version 为空指针或不是合法 UTF-8".to_string()))?;

    let kind = PluginKind::from_u32(descriptor.kind)
        .ok_or_else(|| PluginError::BadDescriptor(format!("未知的插件类型 kind={}", descriptor.kind)))?;

    let metadata = PluginMetadata {
        abi_version: descriptor.abi_version,
        kind,
        name,
        version,
        has_normalize: descriptor.vtable.normalize.is_some(),
        has_notify: descriptor.vtable.notify.is_some(),
        has_free_string: descriptor.vtable.free_string.is_some(),
        reserved: descriptor.reserved,
    };
    metadata.validate()?;
    Ok((metadata, descriptor.vtable))
}

/// 调用插件的 `normalize`。
pub(crate) fn call_normalize(vtable: PluginVTable, input: &str) -> Result<String, PluginError> {
    let Some(normalize) = vtable.normalize else {
        return Err(PluginError::Call("插件没有提供 normalize 函数指针".to_string()));
    };
    let c_input =
        CString::new(input).map_err(|err| PluginError::Call(format!("输入含 NUL 字节，无法传给 C ABI：{err}")))?;

    let mut out_len: usize = 0;
    // SAFETY: `normalize` 来自本次加载的描述符，调用方（`LoadedPlugin`）保证
    // `Library` 在调用期间存活；`c_input` 在整个调用期间存活且以 NUL 结尾；
    // `out_len` 是本函数栈上的有效可写指针（`&raw mut` 不产生中间引用）。
    let ptr = unsafe { normalize(c_input.as_ptr(), &raw mut out_len) };

    if ptr.is_null() {
        return Err(PluginError::Call(last_error_or(vtable, "normalize 返回了空指针")));
    }
    if out_len == 0 {
        free_string(vtable, ptr);
        return Err(PluginError::Call("normalize 返回的字符串长度为 0".to_string()));
    }

    // SAFETY: 插件按 ABI 保证 `ptr` 指向 `out_len` 字节的可读缓冲区，且在
    // `free_string` 之前一直有效；本切片只在该窗口内使用，读完立刻释放。
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), out_len) };
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(err) => {
            free_string(vtable, ptr);
            return Err(PluginError::Call(format!("normalize 返回的字节不是合法 UTF-8：{err}")));
        }
    };
    free_string(vtable, ptr);
    Ok(text)
}

/// 调用插件的 `notify`。
pub(crate) fn call_notify(vtable: PluginVTable, target: &str, message: &str) -> Result<(), PluginError> {
    let Some(notify) = vtable.notify else {
        return Err(PluginError::Call("插件没有提供 notify 函数指针".to_string()));
    };
    let c_target = CString::new(target).map_err(|err| PluginError::Call(format!("target 含 NUL 字节：{err}")))?;
    let c_message = CString::new(message).map_err(|err| PluginError::Call(format!("message 含 NUL 字节：{err}")))?;

    // SAFETY: 同 `call_normalize`：函数指针来自本次加载的描述符，两个 CString
    // 在调用期间存活且以 NUL 结尾。
    let code = unsafe { notify(c_target.as_ptr(), c_message.as_ptr()) };
    if code == 0 {
        return Ok(());
    }
    Err(PluginError::Call(last_error_or(vtable, &format!("notify 返回非 0 状态码 {code}"))))
}

/// 释放插件返回的字符串（若插件提供了 `free_string`；否则交给插件自己约定，不做假设）。
fn free_string(vtable: PluginVTable, ptr: *mut c_char) {
    if let Some(free) = vtable.free_string {
        // SAFETY: `ptr` 是同一插件 `normalize` 返回、尚未释放的指针；
        // 每个返回指针只在这里释放一次（`call_normalize` 的三条路径互斥）。
        unsafe { free(ptr) };
    }
}

/// 取插件的 `last_error`；拿不到就退回 `fallback`。
fn last_error_or(vtable: PluginVTable, fallback: &str) -> String {
    if let Some(get) = vtable.last_error {
        // SAFETY: ABI 约定 `last_error` 返回 `'static` 的 NUL 结尾 UTF-8 指针或空指针；
        // 宿主不释放该指针。
        let ptr = unsafe { get() };
        // SAFETY: 同上（空指针由 `c_string` 处理）。
        if let Some(message) = unsafe { c_string(ptr) } {
            if !message.is_empty() {
                return format!("{fallback}（插件 last_error：{message}）");
            }
        }
    }
    fallback.to_string()
}

/// 把 NUL 结尾的 C 字符串拷成 Rust `String`；空指针或非法 UTF-8 返回 `None`。
///
/// # Safety
/// `ptr` 必须为空指针，或指向一个在本次调用期间有效、NUL 结尾的字符串。
unsafe fn c_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: 由本函数的调用契约保证：非空指针指向有效的 NUL 结尾字符串。
    let raw = unsafe { CStr::from_ptr(ptr) };
    raw.to_str().ok().map(ToString::to_string)
}
