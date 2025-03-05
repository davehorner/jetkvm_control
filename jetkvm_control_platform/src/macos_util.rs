#[cfg(target_os = "macos")]
    use serde::Serialize;
    use std::process::Command;

    #[derive(Serialize, Debug)]
    struct ActiveProcessInfo {
        window_title: String,
        process_id: u32,
        executable_name: String,
        command_line: String,
        window_x: i32,
        window_y: i32,
        width: i32,
        height: i32,
    }

    pub fn active_process() -> Option<String> {
        // Step 1: Get frontmost process name
        let window_title = get_active_window_title().unwrap_or_else(|| "Unknown".to_string());
        println!("DEBUG: Window Title: {}", window_title);

        // Step 2: Get PID using osascript
        let process_id = get_frontmost_pid().unwrap_or(0);
        println!("DEBUG: Frontmost PID: {}", process_id);

        // Step 3: Get executable name
        let executable_name = window_title.clone();

        // Step 4: Get command line
        let command_line = get_process_command_line(process_id).unwrap_or_else(|| "Unknown".to_string());
        println!("DEBUG: Command Line: {}", command_line);

        // Step 5: Get window position and size
        let (window_x, window_y, width, height) = get_window_geometry().unwrap_or((0, 0, 0, 0));
        println!("DEBUG: Window Geometry: x={}, y={}, width={}, height={}", window_x, window_y, width, height);

        let info = ActiveProcessInfo {
            window_title,
            process_id,
            executable_name,
            command_line,
            window_x,
            window_y,
            width,
            height,
        };

        serde_json::to_string(&info).ok()
    }

    /// Retrieves the frontmost process PID using osascript
    fn get_frontmost_pid() -> Option<u32> {
        let output = Command::new("osascript")
            .arg("-e")
            .arg("tell application \"System Events\" to get unix id of first process whose frontmost is true")
            .output()
            .ok()?;

        let pid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("DEBUG: osascript PID output: {:?}", pid_str);

        pid_str.parse::<u32>().ok()
    }

    /// Retrieves the command line of a process by its PID
    fn get_process_command_line(process_id: u32) -> Option<String> {
        let output = Command::new("ps")
            .arg("-o")
            .arg("command=")
            .arg("-p")
            .arg(process_id.to_string())
            .output()
            .ok()?;

        let cmdline = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("DEBUG: ps command output: {:?}", cmdline);

        if cmdline.is_empty() {
            None
        } else {
            Some(cmdline)
        }
    }

    /// Retrieves the active window title using osascript
    fn get_active_window_title() -> Option<String> {
        let output = Command::new("osascript")
            .arg("-e")
            .arg("tell application \"System Events\" to get title of front window of (first process whose frontmost is true)")
            .output()
            .ok()?;

        let title = String::from_utf8_lossy(&output.stdout).trim().to_string();
        println!("DEBUG: osascript title output: {:?}", title);

        if title.is_empty() {
            None
        } else {
            Some(title)
        }
    }

    /// Retrieves window position (X, Y) and size (Width, Height) using osascript
    fn get_window_geometry() -> Option<(i32, i32, i32, i32)> {
        // Get window position (X, Y)
        let output_pos = Command::new("osascript")
            .arg("-e")
            .arg("tell application \"System Events\" to get position of front window of (first process whose frontmost is true)")
            .output()
            .ok()?;

        let position_str = String::from_utf8_lossy(&output_pos.stdout).trim().to_string();
        println!("DEBUG: osascript position output: {:?}", position_str);

        let positions: Vec<i32> = position_str
            .split(", ")
            .filter_map(|s| s.parse::<i32>().ok())
            .collect();

        // Get window size (Width, Height)
        let output_size = Command::new("osascript")
            .arg("-e")
            .arg("tell application \"System Events\" to get size of front window of (first process whose frontmost is true)")
            .output()
            .ok()?;

        let size_str = String::from_utf8_lossy(&output_size.stdout).trim().to_string();
        println!("DEBUG: osascript size output: {:?}", size_str);

        let sizes: Vec<i32> = size_str
            .split(", ")
            .filter_map(|s| s.parse::<i32>().ok())
            .collect();

        if positions.len() == 2 && sizes.len() == 2 {
            Some((positions[0], positions[1], sizes[0], sizes[1]))
        } else {
            None
        }
    }

    /// Retrieves the active window information in JSON format
    pub fn active_window() -> Option<String> {
        let window_title = get_active_window_title().unwrap_or_else(|| "Unknown".to_string());
        let (window_x, window_y, width, height) = get_window_geometry().unwrap_or((0, 0, 0, 0));

        let info = serde_json::json!({
            "window_title": window_title,
            "window_x": window_x,
            "window_y": window_y,
            "width": width,
            "height": height
        });

        Some(info.to_string())
    }

    /// Run the module for debugging
    fn main() {
        println!("Active Process: {:?}", active_process());
        println!("Active Window: {:?}", active_window());
    }

