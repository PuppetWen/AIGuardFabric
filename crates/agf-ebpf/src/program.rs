//! 固定 BPF_PROG_TYPE_TRACEPOINT 指令；无外部字节码或不受信任参数。
//! 内核 UAPI 依据 include/uapi/linux/bpf.h；使用 helper 1/5/14/15/115/131/132/133。
use crate::invalid;
use std::{collections::BTreeMap, io};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Insn {
    pub(crate) code: u8,
    pub(crate) regs: u8,
    pub(crate) offset: i16,
    pub(crate) imm: i32,
}
impl Insn {
    fn new(code: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
        Self { code, regs: (src << 4) | dst, offset, imm }
    }
}
#[derive(Default)]
struct Assembly {
    instructions: Vec<Insn>,
    labels: BTreeMap<&'static str, usize>,
    jumps: Vec<(usize, &'static str)>,
}
impl Assembly {
    fn insn(&mut self, code: u8, dst: u8, src: u8, offset: i16, imm: i32) {
        self.instructions.push(Insn::new(code, dst, src, offset, imm));
    }
    fn map(&mut self, dst: u8, fd: i32) {
        self.insn(0x18, dst, 1, 0, fd); // 以 BPF_PSEUDO_MAP_FD 加载映射描述符。
        self.insn(0, 0, 0, 0, 0);
    }
    fn call(&mut self, helper: i32) {
        self.insn(0x85, 0, 0, 0, helper);
    }
    fn mov(&mut self, dst: u8, src: u8) {
        self.insn(0xbf, dst, src, 0, 0);
    }
    fn imm(&mut self, dst: u8, imm: i32) {
        self.insn(0xb7, dst, 0, 0, imm);
    }
    fn jump(&mut self, code: u8, dst: u8, imm: i32, label: &'static str) {
        self.jumps.push((self.instructions.len(), label));
        self.insn(code, dst, 0, 0, imm);
    }
    fn label(&mut self, name: &'static str) -> io::Result<()> {
        if self.labels.insert(name, self.instructions.len()).is_some() {
            return Err(invalid("duplicate BPF label"));
        }
        Ok(())
    }
    fn finish(mut self) -> io::Result<Vec<Insn>> {
        for (index, label) in self.jumps {
            let target = *self.labels.get(label).ok_or_else(|| invalid("missing BPF label"))?;
            let relative = i64::try_from(target).map_err(|_| invalid("BPF target"))?
                - i64::try_from(index).map_err(|_| invalid("BPF index"))?
                - 1;
            self.instructions[index].offset = i16::try_from(relative).map_err(|_| invalid("BPF branch too long"))?;
        }
        Ok(self.instructions)
    }
}

pub(crate) fn exec_program(events: i32, lost: i32) -> io::Result<Vec<Insn>> {
    if events < 0 || lost < 0 {
        return Err(invalid("invalid BPF map descriptors"));
    }
    let mut p = Assembly::default();
    p.mov(6, 1); // ctx 保存在跨 helper 调用稳定的 R6。
    p.map(1, events);
    p.imm(2, 280);
    p.imm(3, 0);
    p.call(131);
    p.jump(0x15, 0, 0, "lost"); // reserve 失败也记录丢失，不能假装无事件。
    p.mov(7, 0);
    for offset in (0_i16..280).step_by(8) {
        p.insn(0x7a, 7, 0, offset, 0);
    }
    p.call(5);
    p.insn(0x7b, 7, 0, 0, 0);
    p.call(14);
    p.insn(0x77, 0, 0, 0, 32);
    p.insn(0x63, 7, 0, 8, 0);
    p.call(15);
    p.insn(0x63, 7, 0, 12, 0);
    p.insn(0x61, 3, 6, 8, 0);
    p.insn(0x57, 3, 0, 0, 0xffff);
    p.insn(0x0f, 3, 6, 0, 0);
    p.mov(1, 7);
    p.insn(0x07, 1, 0, 0, 24);
    p.imm(2, 256);
    p.call(115);
    p.jump(0xd5, 0, 0, "discard"); // 内核字符串读取返回值 <=0 时丢弃。
    p.insn(0x63, 7, 0, 16, 0);
    p.mov(1, 7);
    p.imm(2, 0);
    p.call(132);
    p.jump(0x05, 0, 0, "exit");
    p.label("discard")?;
    p.mov(1, 7);
    p.imm(2, 0);
    p.call(133);
    p.label("lost")?;
    p.insn(0x62, 10, 0, -4, 0);
    p.map(1, lost);
    p.mov(2, 10);
    p.insn(0x07, 2, 0, 0, -4);
    p.call(1);
    p.jump(0x15, 0, 0, "exit");
    p.imm(1, 1);
    p.insn(0xdb, 0, 1, 0, 0); // 用 BPF_ATOMIC | DW | ADD 原子累加丢失数。
    p.label("exit")?;
    p.imm(0, 0);
    p.insn(0x95, 0, 0, 0, 0);
    p.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn fixed_program_has_forward_only_branches_valid_map_pairs_and_bounded_writes() {
        let code = exec_program(17, 18).unwrap();
        assert_eq!(std::mem::size_of::<Insn>(), 8);
        for (index, instruction) in code.iter().enumerate() {
            if instruction.code == 0x18 {
                assert_eq!(instruction.regs >> 4, 1);
                assert!([17, 18].contains(&instruction.imm));
                assert_eq!(code[index + 1].code, 0);
            }
            if [0x05, 0x15, 0xd5].contains(&instruction.code) {
                assert!(instruction.offset >= 0);
                let target = index + 1 + usize::try_from(instruction.offset).unwrap();
                assert!(target < code.len());
                assert_ne!(code[target].code, 0);
            }
            if instruction.code == 0x7a {
                assert!((0..=272).contains(&instruction.offset));
            }
        }
        assert_eq!(code.iter().filter(|i| i.code == 0x7a).count(), 35);
        assert_eq!(code.last().unwrap().code, 0x95);
    }
    #[test]
    fn invalid_descriptor_or_unresolved_branch_is_rejected() {
        assert!(exec_program(-1, 2).is_err());
        let mut code = Assembly::default();
        code.jump(0x05, 0, 0, "absent");
        assert!(code.finish().is_err());
    }
}
