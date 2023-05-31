# debugprotector

## Using default method

The `detect` method will check for a debugger and self kill the program

```rs
use debugprotector::detect;

fn main() {
  detect();
}
```

## Using single methods.

This crate has the following functions:
```rs
use debugprotector::antidbg;
antidbg::adbg_is_debugger_present();
antidbg::adbg_being_debugged_peb();
antidbg::adbg_nt_global_flag_peb();
antidbg::adbg_check_remote_debugger_present();
antidbg::adbg_check_window_class_name();
antidbg::adbg_check_window_name();
antidbg::adbg_process_file_name();
```

## Collaborators
Thanks to [lucascherzer](https://github.com/lucascherzer) to be a collaborator of this small crate.