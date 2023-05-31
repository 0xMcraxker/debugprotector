mod antidbg;
mod exit_codes;

use crate::exit_codes::DebugStatus;

const CHECKS: [unsafe fn() -> DebugStatus; 7] = [
    antidbg::adbg_is_debugger_present,
    antidbg::adbg_being_debugged_peb,
    antidbg::adbg_nt_global_flag_peb,
    antidbg::adbg_check_remote_debugger_present,
    antidbg::adbg_check_window_class_name,
    antidbg::adbg_check_window_name,
    antidbg::adbg_process_file_name
];

// Check for a debugger and exit if there is one
pub fn detect() {
    let dbg = running_debuggers();
    if let Some(dbg) = dbg.get(0) {
        // Exit with the corresponding exit code.
        // Unwrapping is safe because it will only give a `None` if the variant is 
        // a `DebugStatus::None` which is impossible as `running_debuggers` 
        // does not allow these in the return value
        std::process::exit(dbg.value().unwrap()) 
    }
}

/// Checks whether there is a debugger present
/// # Returns
/// * `true` if it found a debugger
/// * `false` if it did **not** find a debugger
/// # Example
/// ```rs
/// use debugprotector::debugger_present;
/// 
/// let being_debugged = debugger_present();
/// if being_debugged {
///     println!("There is a debugger watching");
/// } else {
///     println!("No debugger present");
/// }
/// ```
pub fn debugger_present() -> bool {
    unsafe {
        for check in CHECKS {
            if let DebugStatus::None = check() {
                continue
            } else {
                return true
            }
        }
        false
    }
}

/// Returns a vector of all found indicators of a debugger
/// # Example
/// If a a call to the Windows API function `IsDebuggerPresent` returns true and a process named `ida.exe` is found to be running,
/// the function will return a `vec![DebugStatus::IsDebuggerPresent, DebugStatus::DebuggerProcessFilename]`.
/// If no indicators are found, an emtpy `Vec` is returned.
/// ```rs
/// use debugprotector::running_debuggers;
/// use debugprotector::exit_codes::DebugStatus;
/// assert_eq(running_debuggers(), vec![DebugStatus::IsDebuggerPresent, DebugStatus::DebuggerProcessFilename])
/// ```
pub fn running_debuggers() -> Vec<DebugStatus> {
    let mut found: Vec<DebugStatus> = Vec::new();
    for check in CHECKS {
        unsafe {
            let check_res = check();
            if let DebugStatus::None = check_res {
                continue;
            } else {
                found.push(check_res);
            }
        }
    }
    found

}