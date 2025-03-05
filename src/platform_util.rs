#[cfg(target_os = "windows")]
mod windows_util;

#[cfg(target_os = "macos")]
mod macos_util;

#[cfg(target_os = "windows")]
pub use windows_util::{active_process, active_window};

#[cfg(target_os = "macos")]
pub use macos_util::{active_process, active_window};

