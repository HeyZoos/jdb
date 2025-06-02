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
