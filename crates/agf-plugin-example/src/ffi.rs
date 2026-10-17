//! **本 crate 唯一的 `unsafe` 模块**：ABI v1 的入口点（描述符符号 + 四个函数指针实现）。
//!
//! 为什么必须 unsafe：
//! * 宿主通过 C ABI 传进来的是**裸指针**（`*const c_char` 输入 / `*mut usize` 出参 /
//!   需要归还所有权的 `*mut c_char`），读写裸指针在 Rust 里只能写 `unsafe`；
//! * edition 2024 下 `#[unsafe(no_mangle)]` 本身也归 `unsafe_code` lint 管。
//!
//! 每个块都带 `SAFETY:` 注释；宿主侧的 `unsafe` 也集中在它自己的 `abi` 模块里。

#![allow(unsafe_code)]

use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_char;
use std::io::Write as _;
use std::path::Path;
use std::ptr;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

use agf_plugin::AGF_PLUGIN_ABI_VERSION;
use agf_plugin::PluginDescriptor;
use agf_plugin::PluginKind;
use agf_plugin::PluginVTable;

use crate::normalize::normalize_line;

/// 描述符里的名字字段（NUL 结尾；`static` 因此在插件卸载前一直有效）。
pub(crate) static NAME_C: &[u8] = b"agf-plugin-example\0";

/// 描述符里的版本字段（NUL 结尾）。
pub(crate) static VERSION_C: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

/// 最近一次失败原因（`last_error` 返回的指针，`'static`）。
static LAST_ERROR: AtomicPtr<c_char> = AtomicPtr::new(ptr::null_mut());

/// **ABI v1 唯一入口符号**：宿主用这个名字取描述符。
///
/// # 为什么返回"泄漏"的描述符
/// ABI 约定：返回的指针必须在插件卸载前一直有效。这里用 `Box::leak` 把描述符提升为
/// `'static`——**刻意不做静态初始化**，因为 `static` 需要 `Sync`，而含裸指针的
/// `PluginDescriptor` 不是 `Sync`，硬做就得上 `unsafe impl Sync`。
/// 宿主每次加载只调用一次（几十字节），重复调用也只是再泄漏一份。
#[unsafe(no_mangle)]
pub extern "C" fn agf_plugin_descriptor_v1() -> *const PluginDescriptor {
    Box::leak(Box::new(build_descriptor()))
}

/// 组装描述符（函数指针表 + 名字/版本）。
pub(crate) fn build_descriptor() -> PluginDescriptor {
    PluginDescriptor {
        abi_version: AGF_PLUGIN_ABI_VERSION,
        kind: PluginKind::Normalizer.as_u32(),
        name: NAME_C.as_ptr().cast::<c_char>(),
        version: VERSION_C.as_ptr().cast::<c_char>(),
        vtable: PluginVTable {
            normalize: Some(normalize_entry),
            free_string: Some(free_string_entry),
            notify: Some(notify_entry),
            last_error: Some(last_error_entry),
        },
        reserved: 0,
    }
}

/// 记录失败原因，供宿主经 `last_error` 取回。
///
/// 旧的错误指针**刻意不回收**：错误路径极少触发（每次最多几十字节），
/// 换来的是本函数**完全没有 `unsafe`**（`CString::into_raw` 是安全函数，
/// 只有 `from_raw` 才 unsafe）。这是拿"可忽略的泄漏"换"更小的 unsafe 面"。
fn set_last_error(message: &str) {
    let text = CString::new(message).unwrap_or_default();
    LAST_ERROR.store(text.into_raw(), Ordering::Release);
}

/// ABI：`last_error() -> *const c_char`。
///
/// 返回 `'static` 的 NUL 结尾字符串；宿主**不释放**它。
pub extern "C" fn last_error_entry() -> *const c_char {
    LAST_ERROR.load(Ordering::Acquire)
}

/// ABI：`normalize(input, out_len) -> *mut c_char`。
///
/// 成功时返回堆上 UTF-8 JSON（宿主用 [`free_string_entry`] 释放），
/// 失败时返回空指针并把原因写进 `last_error`。
///
/// # Safety
/// 调用方（宿主）必须保证：
/// * `input` 为空指针，或指向一个在本次调用期间有效、NUL 结尾的 UTF-8 字符串；
/// * `out_len` 为空指针，或指向一个可写的 `usize`。
pub unsafe extern "C" fn normalize_entry(input: *const c_char, out_len: *mut usize) -> *mut c_char {
    if input.is_null() {
        set_last_error("normalize: input 是空指针");
        return ptr::null_mut();
    }
    if out_len.is_null() {
        set_last_error("normalize: out_len 是空指针");
        return ptr::null_mut();
    }

    // SAFETY: 由本函数的调用契约保证 input 非空且指向 NUL 结尾字符串；
    // `CStr::from_ptr` 只读取到第一个 NUL 为止，不越界。
    let raw = unsafe { CStr::from_ptr(input) };
    let Ok(line) = raw.to_str() else {
        set_last_error("normalize: 输入不是合法 UTF-8");
        return ptr::null_mut();
    };

    let json = match normalize_line(line) {
        Ok(json) => json,
        Err(reason) => {
            set_last_error(&format!("normalize: {reason}"));
            return ptr::null_mut();
        }
    };

    let Ok(text) = CString::new(json) else {
        set_last_error("normalize: 归一化结果含 NUL 字节");
        return ptr::null_mut();
    };
    let len = text.as_bytes().len();

    // SAFETY: out_len 已确认非空，按 ABI 它是一个有效的 `usize` 可写位置。
    unsafe { out_len.write(len) };
    text.into_raw()
}

/// ABI：`free_string(ptr)` —— 释放 [`normalize_entry`] 返回的字符串。
///
/// # Safety
/// `text` 必须为空指针，或必须是 [`normalize_entry`] 用 `CString::into_raw` 交出、
/// **尚未释放**的指针；宿主必须保证每个返回值只释放一次。
pub unsafe extern "C" fn free_string_entry(text: *mut c_char) {
    if text.is_null() {
        return;
    }
    // SAFETY: 由调用契约保证 text 来自同一次 `normalize_entry` 的 `CString::into_raw`，
    // 且所有权已交回插件、不会被重复释放。
    unsafe { drop(CString::from_raw(text)) };
}

/// ABI：`notify(target, message) -> i32`（`0` = 成功，非 `0` = 业务失败）。
///
/// `target` 解释为**文件路径**：消息以追加方式写进去（可被端到端测试直接观测）。
///
/// # Safety
/// `target` / `message` 必须为空指针，或指向在本次调用期间有效、NUL 结尾的 UTF-8 字符串。
pub unsafe extern "C" fn notify_entry(target: *const c_char, message: *const c_char) -> i32 {
    if target.is_null() || message.is_null() {
        set_last_error("notify: target/message 是空指针");
        return -1;
    }

    // SAFETY: 两个指针均已确认非空，按 ABI 指向 NUL 结尾字符串。
    let (raw_target, raw_message) = unsafe { (CStr::from_ptr(target), CStr::from_ptr(message)) };
    let (Ok(file_path), Ok(text)) = (raw_target.to_str(), raw_message.to_str()) else {
        set_last_error("notify: 参数不是合法 UTF-8");
        return -2;
    };

    match append_line(file_path, text) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(&format!("notify: 追加写 {file_path} 失败：{err}"));
            -3
        }
    }
}

/// 追加写一行到文件（自定义通知渠道的真实副作用）。
fn append_line(file_path: &str, text: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(Path::new(file_path))?;
    writeln!(file, "{text}")
}
