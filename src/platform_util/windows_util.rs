#[cfg(target_os = "windows")]
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Threading::{GetProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use windows::Win32::Foundation::{RECT, HANDLE, CloseHandle};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use std::process::Command;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct ActiveProcessInfo {
    pub window_title: String,
    pub process_id: u32,
    pub executable_name: String,
    pub command_line: String,
    pub window_x: i32,
    pub window_y: i32,
    pub width: i32,
    pub height: i32,
}

pub fn active_process() -> Option<String> {
    unsafe {
        let hwnd: HWND = GetForegroundWindow();
        let mut buffer = [0u16; 512];
        let len = GetWindowTextW(hwnd, &mut buffer);
        let window_title = if len > 0 {
            OsString::from_wide(&buffer[..len as usize]).to_string_lossy().into_owned()
        } else {
            "Unknown".to_string()
        };

        let mut process_id: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut proc_entry: PROCESSENTRY32W = std::mem::zeroed();
        proc_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut executable_name = "Unknown".to_string();
        if Process32FirstW(snapshot, &mut proc_entry).is_ok() {
            loop {
                if proc_entry.th32ProcessID == process_id {
                    executable_name = OsString::from_wide(&proc_entry.szExeFile)
                        .to_string_lossy()
                        .into_owned();
                    break;
                }
                if !Process32NextW(snapshot, &mut proc_entry).is_ok() {
                    break;
                }
            }
        }

        // Get window position and size
        let mut rect: RECT = std::mem::zeroed();
        let (window_x, window_y, width, height) = if GetWindowRect(hwnd, &mut rect).is_ok() {
            (rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)
        } else {
            (0, 0, 0, 0)
        };

        // Get command line arguments
        let command_line = get_process_command_line(process_id).unwrap_or("Unknown".to_string());

        let info = ActiveProcessInfo {
            window_title,
            process_id,
            executable_name: executable_name.trim_end_matches('\0').to_string(),
            command_line,
            window_x,
            window_y,
            width,
            height,
        };

        serde_json::to_string(&info).ok()
    }
}

fn get_process_command_line(process_id: u32) -> Option<String> {
    let output = Command::new("wmic")
        .args(["process", "where", &format!("ProcessId={}", process_id), "get", "CommandLine"])
        .output()
        .ok()?; // Get the output, return None if it fails

    let cmdline = String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1) // Skip the header line
        .collect::<Vec<_>>() // Collect into a Vec<&str>
        .join(" ") // Join multiple lines into a single string
        .trim()
        .to_string();

    if cmdline.is_empty() || cmdline == "CommandLine" {
        None
    } else {
        Some(cmdline)
    }
}

pub fn active_window() -> Option<String> {
    unsafe {
        let hwnd: HWND = GetForegroundWindow();
        let mut buffer = [0u16; 512];
        let len = GetWindowTextW(hwnd, &mut buffer);
        let window_title = if len > 0 {
            OsString::from_wide(&buffer[..len as usize]).to_string_lossy().into_owned()
        } else {
            "Unknown".to_string()
        };

        let info = serde_json::json!({ "window_title": window_title });
        Some(info.to_string())
    }
}

