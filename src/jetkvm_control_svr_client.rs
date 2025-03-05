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
use tokio::sync::Mutex;
use rustls::pki_types::ServerName;
use mlua::{Lua, UserData, UserDataMethods, Result as LuaResult, Value as LuaValue};
use mlua::LuaSerdeExt;
use mlua::prelude::LuaError;

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(version, about = "JetKVM Standalone Client", long_about = None)]
struct Args {
    #[arg(short = 'H', long, default_value = "localhost")]
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
    #[serde(default)]
    data: serde_json::Value,
}

/// JetKVM Control Server Client
struct JetKVMControlSvrClient {
    host: String,
    port: u16,
    password: String,
    ca_cert_path: String,
    challenge: Option<u64>,
    tls_stream: Option<tokio_rustls::client::TlsStream<TcpStream>>,
}

impl JetKVMControlSvrClient {
    fn new() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            password: String::new(),
            ca_cert_path: "cert.pem".to_string(),
            challenge: None,
            tls_stream: None,
        }
    }

    async fn connect(&mut self, host: String, port: u16, password: String, ca_cert_path: String) -> LuaResult<bool> {
        self.host = host;
        self.port = port;
        self.password = password;
        self.ca_cert_path = ca_cert_path;

        let addr = format!("{}:{}", self.host, self.port);
        let tls_connector = load_tls_config(&self.ca_cert_path).map_err(mlua::Error::external)?;
        let stream = TcpStream::connect(&addr).await.map_err(mlua::Error::external)?;
        let domain = ServerName::try_from(self.host.clone()).unwrap();
        let mut tls_stream = tls_connector.connect(domain, stream).await.map_err(mlua::Error::external)?;

        // Receive challenge from server
        let mut buffer = vec![0; 1024];
        let n = tls_stream.read(&mut buffer).await.map_err(mlua::Error::external)?;
        let challenge = String::from_utf8_lossy(&buffer[..n])
            .trim()
            .replace("CHALLENGE:", "")
            .parse::<u64>()
            .unwrap();
        self.challenge = Some(challenge);

        self.tls_stream = Some(tls_stream);
        println!("Connected to JetKVM Control Server");
        Ok(true)
    }

async fn send_command(&mut self, lua: &Lua, command: String) -> LuaResult<LuaValue> {
    if let Some(tls_stream) = &mut self.tls_stream {
        let challenge = self.challenge.unwrap_or(0);
        let request = RpcRequest {
            command: command.clone(),
            data: None,
            hmac: compute_hmac(&self.password, challenge, &command),
        };

        let mut request_json = serde_json::to_string(&request).unwrap();
        request_json.push('\n');
        tls_stream.write_all(request_json.as_bytes()).await.map_err(|e| LuaError::external(e))?;

        let mut buffer = vec![0; 1024];
        let n = tls_stream.read(&mut buffer).await.map_err(|e| LuaError::external(e))?;
        let response: RpcResponse = serde_json::from_slice(&buffer[..n]).map_err(|e| LuaError::external(e))?;

        // Convert JSON response to Lua table using the *same* Lua state
        let lua_value: LuaValue = lua.to_value(&response.data).map_err(|e| LuaError::external(e))?;
        Ok(lua_value)
    } else {
        Err(LuaError::external("Not connected to server"))
    }
}

}


/// Runs the Lua script asynchronously
#[tokio::main(flavor = "current_thread")]
async fn main() -> LuaResult<()> {
rustls::crypto::aws_lc_rs::default_provider().install_default(); // Install the crypto provider

    let lua = Lua::new();
    let client = Arc::new(Mutex::new(JetKVMControlSvrClient::new()));

    // Define the `connect` function
    let connect = {
        let client = client.clone();
        lua.create_async_function(move |_, (host, port, password, ca_cert_path): (String, u16, String, String)| {
            let client = client.clone();
            async move {
                let mut client_guard = client.lock().await;
                let result = client_guard.connect(host, port, password, ca_cert_path).await?;
                Ok(result)
            }
        })?
    };

    // Define the `send_command` function
let send_command = {
    let client = client.clone();
    lua.create_async_function(move |lua, command: String| {
        let client = client.clone();
        async move {
            let mut client_guard = client.lock().await;
            let result = client_guard.send_command(&lua, command).await?;
            Ok(result)
        }
    })?
};


    lua.globals().set("connect", connect)?;
    lua.globals().set("send_command", send_command)?;

    let lua_script = r#"
print("Attempting to connect...")
local success = connect("localhost", 8080, "dave", "cert.pem")
print("Connect result:", success)

if success then
    local result = send_command("active_window")  -- JSON automatically converted to Lua table

    print("\n--- Received Data ---")
    for key, value in pairs(result) do
        print(key .. ":", value)
    end
    print("\n--- Direct Access ---")
   print("Window Title:", result.window_title or "N/A")

    local result = send_command("active_process")  -- JSON automatically converted to Lua table
    -- Accessing specific properties directly
   print("\n--- Direct Access ---")
   print("Process ID:", result.process_id or "N/A")
   print("Executable Name:", result.executable_name or "N/A")
   print("Window X:", result.window_x or "N/A")
   print("Window Y:", result.window_y or "N/A")
   print("Width:", result.width or "N/A")
   print("Height:", result.height or "N/A") 

else
    print("Failed to connect")
end
    "#;

    lua.load(lua_script).exec_async().await?;
    Ok(())
}

/// Loads the TLS configuration
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

/// Computes HMAC for authentication
fn compute_hmac(password: &str, challenge: u64, command: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(password.as_bytes()).expect("HMAC can take key of any size");
    mac.update(&challenge.to_be_bytes());
    mac.update(command.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

