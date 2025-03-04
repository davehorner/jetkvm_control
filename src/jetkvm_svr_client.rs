use clap::Parser;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use serde::{Serialize, Deserialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex;
use std::sync::Arc;
use rustls::pki_types::ServerName;

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(version, about = "JetKVM Standalone Client", long_about = None)]
struct Args {
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,
    #[arg(short, long, default_value = "8080")]
    port: u16,
    #[arg(short = 'P', long)]
    password: String,
    #[arg(long, default_value = "cert.pem")]
    ca_cert_path: String,
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
    rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);

    let tls_connector = load_tls_config(&args.ca_cert_path)?;
    let stream = TcpStream::connect(&addr).await?;
    let domain = ServerName::try_from(args.host.clone()).unwrap();
    let mut tls_stream = tls_connector.connect(domain, stream).await.unwrap();

    // Receive challenge from server
    let mut buffer = vec![0; 1024];
    let n = tls_stream.read(&mut buffer).await?;
    let challenge = String::from_utf8_lossy(&buffer[..n]).trim().replace("CHALLENGE:", "").parse::<u64>().unwrap();

    // Request active window
    send_request(&mut tls_stream, &args.password, challenge, "active_window").await?;
    send_request(&mut tls_stream, &args.password, challenge, "active_process").await?;

    Ok(())
}

async fn send_request(tls_stream: &mut tokio_rustls::client::TlsStream<TcpStream>, password: &str, challenge: u64, command: &str) -> std::io::Result<()> {
    let request = RpcRequest {
        command: command.to_string(),
        data: None,
        hmac: compute_hmac(password, challenge, command),
    };
    let mut request_json = serde_json::to_string(&request).unwrap();
    request_json.push('\n'); // Ensure request ends with newline 
    println!("{:?}",request_json);
    tls_stream.write_all(request_json.as_bytes()).await?;

    let mut buffer = vec![0; 1024];
    let n = tls_stream.read(&mut buffer).await?;
   // Convert bytes to a UTF-8 string
    let received_data = String::from_utf8_lossy(&buffer[..n]);
    
    // Print the raw data received
    println!("Received buffer: {:?}", received_data); 
    let response: RpcResponse = serde_json::from_slice(&buffer[..n]).unwrap();

    println!("Response for {}: {}", command, response.data);
    Ok(())
}

fn load_tls_config(ca_cert_path: &str) -> std::io::Result<TlsConnector> {
    let mut root_store = RootCertStore::empty();
    let cert_file = File::open(ca_cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = certs(&mut cert_reader);
    for cert in certs {
        if let Ok(cert) = cert {
            root_store.add(cert.into());
        }
    }
    let config = ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

fn compute_hmac(password: &str, challenge: u64, command: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).expect("HMAC can take key of any size");
    mac.update(&challenge.to_be_bytes());
    mac.update(command.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

