#[allow(unused_mut)]
#[allow(asm_sub_register)]
#[allow(unused_assignments)]

use crate::exit_codes::DebugStatus;
use std::arch::asm;
use std::mem::size_of;
use std::ptr;
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;
use winapi::um::debugapi::{CheckRemoteDebuggerPresent, IsDebuggerPresent};
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::Process32FirstW;
use winapi::um::tlhelp32::Process32NextW;
use winapi::um::tlhelp32::PROCESSENTRY32W;
use winapi::um::tlhelp32::TH32CS_SNAPPROCESS;
use winapi::um::winnt::{HANDLE};
use winapi::um::winuser::FindWindowW;
use winsafe::WString;

pub unsafe fn adbg_is_debugger_present() -> DebugStatus {
    if IsDebuggerPresent() != 0 {
        return DebugStatus::IsDebuggerPresent;
    } else {
        return DebugStatus::None;
    }
}

pub fn adbg_being_debugged_peb() -> DebugStatus {
    let mut found: BOOL = 0;

    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!(
          "xor rax, rax",
          "mov rax, gs:[60h]",
          "mov rax, [rax + 02h]",
          "and rax, 0FFh",
          "mov {found}, rax",
          found = out(reg) found
        );

        #[cfg(not(target_arch = "x86_64"))]
        asm!(
          "xor eax, eax",
          "mov eax, fs:[0x30]",
          "mov eax, [eax + 0x02]",
          "and eax, 0xFF",
          "mov {found}, eax",
          found = out(reg) found
        );
    }

    if found != 0 {
        return DebugStatus::BeingDebuggedPeb;
    } else {
        return DebugStatus::None;
    }
}

pub fn adbg_nt_global_flag_peb() -> DebugStatus {
    let mut found: BOOL = 0;

    unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!(
          "xor rax, rax",
          "mov rax, gs:[60h]",
          "mov rax, [rax + 0BCh]",
          "and rax, 70h",
          "mov {found}, rax",
          found = out(reg) found
        );

        #[cfg(not(target_arch = "x86_64"))]
        asm!(
          "xor eax, eax",
          "mov eax, fs: [0x30]",
          "mov eax, [eax + 0x68]",
          "and eax, 0x00000070"
          "mov {found}, eax",
          found = out(reg) found
        );
    }

    if found != 0 {
        return DebugStatus::NtGlobalFlagPeb;
    } else {
        return DebugStatus::None;
    }
}

pub unsafe fn adbg_check_remote_debugger_present() -> DebugStatus {
    let mut h_process: HANDLE = INVALID_HANDLE_VALUE;
    let mut found: BOOL = 0;

    h_process = GetCurrentProcess();
    CheckRemoteDebuggerPresent(h_process, &mut found);

    if found != 0 {
        return DebugStatus::RemoteDebuggerPresent;
    } else {
        return DebugStatus::None;
    }
}

pub unsafe fn adbg_check_window_class_name() -> DebugStatus {
    let mut found: bool = false;
    let mut h_window: HWND = ptr::null_mut();
    let window_class_name_olly: WString = WString::from_str("OLLYDBG");
    let window_class_name_immunity: WString = WString::from_str("ID");

    h_window = FindWindowW(window_class_name_olly.as_ptr(), ptr::null_mut());

    if h_window != ptr::null_mut() {
        found = true;
    }

    h_window = FindWindowW(window_class_name_immunity.as_ptr(), ptr::null_mut());

    if h_window != ptr::null_mut() {
        found = true;
    }

    if found {
        return DebugStatus::FoundOpenWindow;
    } else {
        return DebugStatus::None;
    }
}

pub unsafe fn adbg_check_window_name() -> DebugStatus {
    let mut found: bool = false;
    let mut h_window: HWND = ptr::null_mut();
    let window_name_olly: WString = WString::from_str("OLLYDBG");
    let window_name_immunity: WString = WString::from_str("ID");

    h_window = FindWindowW(window_name_olly.as_ptr(), ptr::null_mut());

    if h_window != ptr::null_mut() {
        found = true;
    }

    h_window = FindWindowW(window_name_immunity.as_ptr(), ptr::null_mut());

    if h_window != ptr::null_mut() {
        found = true;
    }

    if found {
        return DebugStatus::FoundOpenWindow;
    } else {
        return DebugStatus::None;
    }
}

pub unsafe fn adbg_process_file_name() -> DebugStatus{
    let debuggers_filename: Vec<String> = vec![
        String::from("cheatengine-x86_64.exe"),
        String::from("ollydbg.exe"),
        String::from("ida.exe"),
        String::from("ida64.exe"),
        String::from("radare2.exe"),
        String::from("x64dbg.exe"),
        String::from("httpdebuggerui.exe"),
        String::from("wireshark.exe"),
        String::from("fiddler.exe"),
        String::from("vboxservice.exe"),
        String::from("processhacker.exe"),
        String::from("pestudio.exe"),
        String::from("x96dbg.exe"),
        String::from("x32dbg.exe"),
        String::from("prl_cc.exe"),
        String::from("prl_tools.exe"),
        String::from("xenservice.exe"),
        String::from("qemu-ga.exe"),
        String::from("joeboxcontrol.exe"),
        String::from("ksdumperclient.exe"),
        String::from("ksdumper.exe"),
        String::from("joeboxserver.exe"),
    ];

    let mut process_information = &mut PROCESSENTRY32W {
        dwSize: 0,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };

    let process_list: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    process_information.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    if Process32FirstW(process_list, process_information) != 0 {
        while Process32NextW(process_list, process_information) != 0 {
            for debugger in debuggers_filename.clone() {
                let exe_file = WString::from_wchars_slice(&process_information.szExeFile[..])
                    .to_string()
                    .replace("\u{0}", "")
                    .to_lowercase();

                if exe_file == debugger {
                    return DebugStatus::DebuggerProcessFilename;
                }
            }
        }
    }

    CloseHandle(process_list);
    return DebugStatus::None;
}