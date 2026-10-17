//! BPF ringbuf UAPI：独占 consumer page + 只读 producer/double data mapping。
use super::abi;
use crate::{
    invalid,
    record::{ExecEvent, RECORD_SIZE, decode},
};
use std::{
    ffi::c_void,
    io,
    os::fd::{AsRawFd, OwnedFd},
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

pub(super) const CAPACITY: usize = 512 * 1024;
struct Mapping {
    // 保留 mmap 的原始无类型地址；字节切片只在记录长度检查后创建。
    address: *mut c_void,
    length: usize,
}
impl std::fmt::Debug for Mapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mapping").field("length", &self.length).finish_non_exhaustive()
    }
}
impl Mapping {
    fn new(fd: &OwnedFd, length: usize, protection: i32, offset: i64) -> io::Result<Self> {
        // SAFETY: 内核校验长度和偏移；MAP_SHARED 及仍存活的映射对象保留底层页面。
        let address = unsafe { abi::mmap(std::ptr::null_mut(), length, protection, 1, fd.as_raw_fd(), offset) };
        if address as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        if address.is_null() {
            // SAFETY: 即使成功映射到零地址，也先释放再拒绝使用。
            unsafe { abi::munmap(address, length) };
            return Err(invalid("null ring mapping refused"));
        }
        Ok(Self { address, length })
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: 成功映射只有一个所有者，保留原地址和长度，不在其它位置解除映射。
        unsafe { abi::munmap(self.address, self.length) };
    }
}
#[derive(Debug)]
pub(super) struct Ring {
    consumer: Mapping,
    producer: Mapping,
    page: usize,
    tail: u64,
    _map: OwnedFd,
}
impl Ring {
    pub(super) fn new(map: OwnedFd) -> io::Result<Self> {
        // SAFETY: 支持的 Linux libc ABI 中 _SC_PAGESIZE=30；该调用无指针参数。
        let page = usize::try_from(unsafe { abi::sysconf(30) }).map_err(|_| invalid("page size unavailable"))?;
        if !page.is_power_of_two() || !(4096..=65536).contains(&page) {
            return Err(invalid("unsupported page size"));
        }
        let consumer = Mapping::new(&map, page, 3, 0)?;
        let producer =
            Mapping::new(&map, page + 2 * CAPACITY, 1, i64::try_from(page).map_err(|_| invalid("page offset"))?)?;
        // SAFETY: mmap 按页对齐，长度至少八字节，计数器由 BPF ringbuf 初始化。
        let tail = unsafe { &*consumer.address.cast::<AtomicU64>() }.load(Ordering::Acquire);
        Ok(Self { consumer, producer, page, tail, _map: map })
    }
    pub(super) fn next(&mut self) -> io::Result<Option<ExecEvent>> {
        loop {
            // SAFETY: 生产者映射仍存活并按页对齐，内核在此发布生产位置。
            let head = unsafe { &*self.producer.address.cast::<AtomicU64>() }.load(Ordering::Acquire);
            let available = head.wrapping_sub(self.tail);
            if available == 0 {
                return Ok(None);
            }
            if available > CAPACITY as u64 || available < 8 {
                return Err(invalid("ring producer/consumer distance invalid"));
            }
            let position = usize::try_from(self.tail & (CAPACITY as u64 - 1)).map_err(|_| invalid("ring position"))?;
            // SAFETY: 位置经过容量掩码且按八字节对齐，记录头位于双重数据映射内。
            let data = unsafe { self.producer.address.byte_add(self.page + position) };
            // SAFETY: 记录仍被保留，u32 地址对齐；acquire 对应内核的提交存储。
            let length = unsafe { &*data.cast::<AtomicU32>() }.load(Ordering::Acquire);
            if length & (1 << 31) != 0 {
                return Ok(None);
            }
            let discarded = length & (1 << 30) != 0;
            let length = usize::try_from(length & ((1 << 30) - 1)).map_err(|_| invalid("record length"))?;
            if length != RECORD_SIZE {
                return Err(invalid("unexpected fixed eBPF record length"));
            }
            let advance = (length + 8 + 7) & !7;
            if advance as u64 > available {
                return Err(invalid("ring record exceeds published bytes"));
            }
            let event = if discarded {
                None
            } else {
                // SAFETY: 长度固定且已校验，双重映射覆盖回绕；消费者 release 前生产者
                // 不能回收该记录，因此先复制，再推进消费位置。
                let bytes = unsafe { std::slice::from_raw_parts(data.byte_add(8).cast::<u8>(), length) }.to_vec();
                Some(decode(&bytes)?)
            };
            self.tail = self.tail.wrapping_add(advance as u64);
            // SAFETY: 只有一个消费者写入；构造时已经校验映射和位置对齐。
            unsafe { &*self.consumer.address.cast::<AtomicU64>() }.store(self.tail, Ordering::Release);
            if event.is_some() {
                return Ok(event);
            }
        }
    }
}
