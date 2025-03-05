use clap::Parser;
use std::process::Command;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng;
use tokio_rustls::TlsAcceptor;
use rustls::{ServerConfig, pki_types::{CertificateDer, PrivatePkcs8KeyDer}};
use std::fs::{File, OpenOptions};
use std::io::{Write};
use tokio::io::BufReader;
use rcgen::generate_simple_self_signed;
use rustls::crypto::CryptoProvider;
use tokio::io::AsyncBufReadExt;
use hex;
use tokio_rustls::server::TlsStream;

mod platform_util;
pub use platform_util::*;

#[cfg(target_os = "windows")]
mod windows_util {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Threading::GetProcessId;
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId};
   use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ}; 
  // use std::os::windows::raw::HANDLE; 
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use serde::Serialize;
    use std::ptr::null_mut;
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
   use windows::Win32::Foundation::RECT;
  // use windows::Win32::System::WindowsProgramming::GetCommandLineW;
use windows::Win32::Foundation::UNICODE_STRING;

use windows::Win32::System::Memory::VirtualQueryEx;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
// use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
use windows::Win32::Foundation::{HANDLE, CloseHandle,GetLastError};
#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    pub Reserved1: usize,
    pub PebBaseAddress: *mut usize,
    pub Reserved2: [usize; 2],
    pub UniqueProcessId: *mut usize,
    pub Reserved3: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut PROCESS_BASIC_INFORMATION,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}


#[derive(Serialize, serde::Deserialize, Debug)]
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
    let output = std::process::Command::new("wmic")
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

/*
/// Retrieves the command line arguments of a process
fn get_process_command_line(process_id: u32) -> Option<String> {
    unsafe {
        let process_handle: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id).ok()?;

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut return_length = 0;
if NtQueryInformationProcess(
    process_handle, 
    0, 
    &mut pbi as *mut _ as _, 
    std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
    &mut return_length
) != 0  // `0` means success
{
    CloseHandle(process_handle);
    return None;
}
        

        let peb_address = pbi.PebBaseAddress as usize;
        let mut peb: [u8; std::mem::size_of::<usize>()] = [0; std::mem::size_of::<usize>()];
        let mut bytes_read = 0;
        if ReadProcessMemory(process_handle, peb_address as _, peb.as_mut_ptr() as _, peb.len(), Some(&mut bytes_read)).is_err() {
           CloseHandle(process_handle); 
            return None;
        }

        let process_parameters_address = usize::from_ne_bytes(peb);
        let mut process_parameters: [u8; std::mem::size_of::<usize>()] = [0; std::mem::size_of::<usize>()];
        if ReadProcessMemory(process_handle, process_parameters_address as _, process_parameters.as_mut_ptr() as _, process_parameters.len(), Some(&mut bytes_read)).is_err() {
           CloseHandle(process_handle); 
            return None;
        }

        let command_line_unicode_string = usize::from_ne_bytes(process_parameters);
        let mut unicode_string: UNICODE_STRING = std::mem::zeroed();
        if ReadProcessMemory(process_handle, command_line_unicode_string as _, &mut unicode_string as *mut _ as _, std::mem::size_of::<UNICODE_STRING>(), Some(&mut bytes_read)).is_err() {
           CloseHandle(process_handle); 
            return None;
        }

        let buffer_address = unicode_string.Buffer.0 as usize;
        let mut buffer = vec![0u16; (unicode_string.Length / 2) as usize];
        if ReadProcessMemory(process_handle, buffer_address as _, buffer.as_mut_ptr() as _, unicode_string.Length as usize, Some(&mut bytes_read)).is_err() {
           CloseHandle(process_handle); 
            return None;
        }
        CloseHandle(process_handle); 
        Some(OsString::from_wide(&buffer).to_string_lossy().into_owned())
    }
}
*/
    
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
}

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

/// RPC Server for JetKVM Control
#[derive(Parser, Debug)]
#[command(version, about = "JetKVM Control RPC Server", long_about = None)]
struct Args {
    /// Host address to bind to
    #[arg(short='H', long, default_value = "0.0.0.0")]
    host: String,

    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Password for authentication
    #[arg(short='P', long)]
    password: String,

    /// Path to TLS certificate
    #[arg(long, default_value = "cert.pem")]
    cert_path: String,

    /// Path to TLS private key
    #[arg(long, default_value = "key.pem")]
    key_path: String,

    /// Initialize self-signed certificate
    #[arg(long)]
    init_cert: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcRequest {
    command: String,
    data: Option<String>,
    hmac: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcResponse {
    success: bool,
    data: serde_json::Value,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Install the default crypto provider for rustls
    rustls::crypto::aws_lc_rs::default_provider().install_default(); 
    let args = Args::parse();
    
    if args.init_cert {
        generate_self_signed_cert(&args.cert_path, &args.key_path)?;
        println!("Self-signed certificate and key generated.");
        return Ok(());
    }
    
    let addr = format!("{}:{}", args.host, args.port);
    let password = Arc::new(args.password);
    let tls_acceptor = match load_tls_config(&args.cert_path, &args.key_path) {
        Ok(acceptor) => acceptor,
        Err(e) => {
            eprintln!("Failed to load TLS config: {}", e);
            return Err(e);
        }
    };

    let listener = TcpListener::bind(&addr).await?;
    println!("Server listening on {}", addr);

    loop {
        let (socket, _) = listener.accept().await?;
        let password = Arc::clone(&password);
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let tls_stream = match tls_acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(_) => return,
            };
            handle_client(tls_stream, password).await;
        });
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> std::io::Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;
    let mut cert_reader =std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::BufReader::new(key_file);

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader).into_iter().collect::<Result<Vec<_>, _>>()?;
    let mut keys: Vec<PrivatePkcs8KeyDer> = rustls_pemfile::pkcs8_private_keys(&mut key_reader).into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    let key = keys.remove(0);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn generate_self_signed_cert(cert_path: &str, key_path: &str) -> std::io::Result<()> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    
    let mut cert_file = OpenOptions::new().create(true).write(true).truncate(true).open(cert_path)?;
    cert_file.write_all(cert.cert.pem().as_bytes())?;
    
    let mut key_file = OpenOptions::new().create(true).write(true).truncate(true).open(key_path)?;
    key_file.write_all(cert.key_pair.serialize_pem().as_bytes())?;
    
    Ok(())
}

fn compute_hmac(password: &str, challenge: u64, command: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).expect("HMAC can take key of any size");
    mac.update(&challenge.to_be_bytes());
    mac.update(command.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

async fn handle_client(
    socket: TlsStream<TcpStream>, 
    password: Arc<String>
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt; // Ensure AsyncRead is in scope
    
    let mut reader = BufReader::new(socket); // Use tokio::io::BufReader
    let mut line = String::new();

    // Generate and send challenge
    let challenge: u64 = rand::thread_rng().gen();
    let challenge_msg = format!("CHALLENGE:{}\n", challenge);
    reader.get_mut().write_all(challenge_msg.as_bytes()).await?;
    reader.get_mut().flush().await?;

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            println!("Client disconnected (EOF)");
            break;
        }

        let json_part = line.trim(); // Trim whitespace/newline
        if json_part.is_empty() {
            continue;
        }

        println!("Received JSON: {}", json_part);

        process_request(reader.get_mut(), &password, challenge, json_part).await?;
    }

    Ok(())
}

async fn process_request(
    socket: &mut TlsStream<TcpStream>,
    password: &str,
    challenge: u64,
    json_part: &str
) -> std::io::Result<()> {
    if let Ok(request) = serde_json::from_str::<RpcRequest>(json_part) {
        let expected_hmac = compute_hmac(password, challenge, &request.command);
        let response = if request.hmac == expected_hmac {
            RpcResponse {
                success: true,
                data: match request.command.as_str() {
                    "active_process" => serde_json::from_str(
                        &platform_util::active_process().unwrap_or("{}".to_string())
                    ).unwrap_or(serde_json::json!({})),

                    "active_window" => serde_json::from_str(
                        &platform_util::active_window().unwrap_or("{}".to_string())
                    ).unwrap_or(serde_json::json!({})),

                    _ => serde_json::json!({ "message": "Command executed successfully" }),
                },
            }
        } else {
            RpcResponse {
                success: false,
                data: serde_json::json!({ "error": "Authentication failed" }),
            }
        };

        let response_json = serde_json::to_string(&response).unwrap() + "\n";
        socket.write_all(response_json.as_bytes()).await?;
        socket.flush().await?;
    } else {
        println!("Error parsing JSON: {}", json_part);
    }
    Ok(())
}
