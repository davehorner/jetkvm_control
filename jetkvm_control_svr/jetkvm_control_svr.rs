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

#[cfg(target_os = "windows")]
use jetkvm_control_platform::windows_util as platform_util;

#[cfg(target_os = "macos")]
use jetkvm_control_platform::macos_util as platform_util;

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
    password: Arc<String>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(socket);
    let mut line = String::new();

    // ✅ Generate and send JSON challenge response
    let challenge: u64 = rand::thread_rng().gen();
    let challenge_response = serde_json::json!({
        "challenge": challenge
    });
    let challenge_msg = serde_json::to_string(&challenge_response).unwrap() + "\n";
    reader.get_mut().write_all(challenge_msg.as_bytes()).await?;
    reader.get_mut().flush().await?;

    // ✅ Read authentication request
    line.clear();
    let bytes_read = reader.read_line(&mut line).await?;
    if bytes_read == 0 {
        println!("Client disconnected (EOF)");
        return Ok(());
    }

    // ✅ Parse authentication request as JSON
    if let Ok(request) = serde_json::from_str::<RpcRequest>(line.trim()) {
        let expected_hmac = compute_hmac(&password, challenge, &request.command);

        if request.hmac != expected_hmac {
            let auth_response = serde_json::json!({
                "success": false,
                "error": "Authentication failed"
            });
            let response_json = serde_json::to_string(&auth_response).unwrap() + "\n";
            reader.get_mut().write_all(response_json.as_bytes()).await?;
            reader.get_mut().flush().await?;
            return Ok(()); // Reject connection on failed authentication
        }

        let auth_response = serde_json::json!({
            "success": true,
            "message": "Authentication successful"
        });
        let response_json = serde_json::to_string(&auth_response).unwrap() + "\n";
        reader.get_mut().write_all(response_json.as_bytes()).await?;
        reader.get_mut().flush().await?;
    } else {
        println!("Error parsing authentication request");
        return Ok(());
    }

    // ✅ Proceed to normal request handling after authentication
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            println!("Client disconnected (EOF)");
            break;
        }

        process_request(reader.get_mut(), &password, challenge, line.trim()).await?;
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
