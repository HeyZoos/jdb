#[macro_export]
macro_rules! registers {
    ($apply:ident) => {
        define_gpr_64!($apply, rax, 0)
        define_gpr_64!($apply, rdx, 1)
        define_gpr_64!($apply, rcx, 2)
        define_gpr_64!($apply, rbx, 3)
        define_gpr_64!($apply, rsi, 4)
        define_gpr_64!($apply, rdi, 5)
        define_gpr_64!($apply, rbp, 6)
        define_gpr_64!($apply, rsp, 7)
        define_gpr_64!($apply, r8,  8)
        define_gpr_64!($apply, r9,  9)
        define_gpr_64!($apply, r10, 10)
        define_gpr_64!($apply, r11, 11)
        define_gpr_64!($apply, r12, 12)
        define_gpr_64!($apply, r13, 13)
        define_gpr_64!($apply, r14, 14)
        define_gpr_64!($apply, r15, 15)
        define_gpr_64!($apply, rip, 16)
        define_gpr_64!($apply, eflags, 49)
        define_gpr_64!($apply, cs, 51)
        define_gpr_64!($apply, fs, 54)
        define_gpr_64!($apply, gs, 55)
        define_gpr_64!($apply, ss, 52)
        define_gpr_64!($apply, ds, 53)
        define_gpr_64!($apply, es, 50)
        define_gpr_64!($apply, orig_rax, -1)
    };
}

/// Compute the byte offset of a general-purpose register field inside the `libc::user` struct.
///
/// This macro determines where a specific CPU register (like `rip`, `rax`, etc.) is located inside
/// the `libc::user` structure enabling you to perform a read or write.
///
/// It calculates the total offset by summing:
/// - the offset of the `regs` field inside `libc::user`, and
/// - the offset of the requested register inside the nested `user_regs_struct`.
///
/// # Example
/// ```
/// use jdb::gpr_offset;
///
/// // This computes the byte offset of the RIP register.
/// // It should match the known offset (here, 128) for the platform.
/// assert_eq!(128, gpr_offset!(rip));
/// ```
///
/// Note: The exact expected offset (like `128`) depends on the platform and ABI.
#[macro_export]
macro_rules! gpr_offset {
    ($reg:tt) => {
        std::mem::offset_of!(nix::libc::user, regs)
            + std::mem::offset_of!(nix::libc::user_regs_struct, $reg)
    };
}

#[macro_export]
macro_rules! define_gpr_64 {
    ($apply:ident, $name:ident, $dwarf_id:expr) => {
        $apply!(
            $name,
            $dwarf_id,
            8,
            gpr_offset!($name),
            RegisterType::GPR,
            RegisterFormat::UInt
        )
    };
}

#[macro_export]
macro_rules! to_enum_variant {
    ($name:ident, $($rest:tt)*) => { $name, };
}

pub enum RegisterType {
    GPR,
    SubGPR,
    FPR,
    DR
}

pub enum RegisterFormat {
    UInt,
    DoubleFloat,
    LongDouble,
    Vector,
}

pub struct RegisterInfo {
    id: RegisterId,
    name: String,
    dwarf_id: i32,
    size: usize,
    offset: usize,
    register_type: RegisterType,
    register_format: RegisterFormat,
}

pub const REGISTER_INFO: [RegisterInfo; 0] = [];

macro_rules! make_register_id_enum {
    () => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum RegisterId {
            registers!(to_enum_variant)
        }
    };
}

make_register_id_enum!();
