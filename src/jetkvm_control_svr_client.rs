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


    async fn connect(
    &mut self, host: String, port: u16, password: String, ca_cert_path: String
) -> LuaResult<(bool, String)> {
    self.host = host;
    self.port = port;
    self.password = password;
    self.ca_cert_path = ca_cert_path;

    println!("Connecting to {}:{} with password {} ({})", self.host, self.port, self.password,self.ca_cert_path);
    let addr = format!("{}:{}", self.host, self.port);
    let tls_connector = load_tls_config(&self.ca_cert_path).map_err(LuaError::external)?;
    println!("Connecting to {}:{} with password {}", self.host, self.port, self.password);
    let stream = TcpStream::connect(&addr).await.map_err(LuaError::external)?;
    println!("Connecting to {}:{} with password {}", self.host, self.port, self.password);
    let domain = ServerName::try_from(self.host.clone()).unwrap();
    println!("Connecting to {}:{} with password {}", self.host, self.port, self.password);
    let mut tls_stream = tls_connector.connect(domain, stream).await.map_err(LuaError::external)?;
    println!("Connected to server");

    // ✅ Step 1: Read JSON Challenge from Server
    let mut buffer = vec![0; 1024];
    let n = tls_stream.read(&mut buffer).await.map_err(LuaError::external)?;
    let server_response: serde_json::Value = serde_json::from_slice(&buffer[..n])
        .map_err(|e| LuaError::external(format!("Invalid JSON response: {}", e)))?;

    let challenge = server_response["challenge"]
        .as_u64()
        .ok_or_else(|| LuaError::external("Invalid challenge format from server"))?;
    self.challenge = Some(challenge);

    println!("Authentication successful");
    // ✅ Step 2: Send Authentication Request
    let auth_request = RpcRequest {
        command: "auth".to_string(),
        data: None,
        hmac: compute_hmac(&self.password, challenge, "auth"),
    };

    let mut request_json = serde_json::to_string(&auth_request).unwrap();
    request_json.push('\n');
    tls_stream.write_all(request_json.as_bytes()).await.map_err(LuaError::external)?;

    // ✅ Step 3: Read Authentication Response
    let n = tls_stream.read(&mut buffer).await.map_err(LuaError::external)?;
    let auth_response: serde_json::Value = serde_json::from_slice(&buffer[..n])
        .map_err(|e| LuaError::external(format!("Invalid JSON response: {}", e)))?;

    // ✅ Step 4: Validate Authentication
    if !auth_response["success"].as_bool().unwrap_or(false) {
        let error_msg = auth_response["error"].as_str().unwrap_or("Unknown authentication error");
        return Ok((false, error_msg.to_string())); // ✅ Return `(false, "Authentication failed")`
    }

    println!("Authentication successful");
    // ✅ Step 5: Authentication Successful
    self.tls_stream = Some(tls_stream);
    let success_message = "Connected successfully".to_string();
    Ok((true, success_message)) // ✅ Return `(true, "Connected successfully")`
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

            // Convert JSON response to Lua table
            let lua_value: LuaValue = lua.to_value(&response.data).map_err(|e| LuaError::external(e))?;
            Ok(lua_value)
        } else {
            Err(LuaError::external("Not connected to server"))
        }
    }
}

/// **Newtype Wrapper** to allow implementing `UserData`
struct LuaJetKVMControlSvrClient(Arc<Mutex<JetKVMControlSvrClient>>);

impl LuaJetKVMControlSvrClient {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(JetKVMControlSvrClient::new())))
    }
}
impl Clone for LuaJetKVMControlSvrClient {
    fn clone(&self) -> Self {
        Self(self.0.clone()) // Clone Arc to maintain reference count
    }
}

impl UserData for LuaJetKVMControlSvrClient {
    fn add_methods<'lua, M: UserDataMethods<Self>>(methods: &mut M) {


                methods.add_async_method("connect", |_, this, (host, port, password, ca_cert_path): (String, u16, String, String)| {
            let this = Arc::clone(&this.0);  // ✅ Clone Arc to avoid ownership issues
            async move {
                println!("Connecting to {}:{} with password {}", host, port, password);
                let mut client = this.lock().await;
                let (success, message) = client.connect(host, port, password, ca_cert_path).await?;
                println!("dropping client");
                drop(client); 
                Ok((success, message))  // ✅ Return tuple (bool, String) for Lua
            }
        });
        methods.add_async_method("send_command", |lua, this, command: String| {
            let this = Arc::clone(&this.0);
            async move {
                let mut client = this.lock().await;
                client.send_command(&lua, command).await
            }
        });
    }
}

/// Registers the Lua bindings
#[cfg(feature = "lua")]
pub fn register_lua(lua: &Lua) -> LuaResult<()> {



    let globals = lua.globals();

    // Register the constructor for JetKvmControlSvrClient
    let new_svr = lua.create_function(|lua, ()| {
        let svr = LuaJetKVMControlSvrClient::new();
        lua.create_userdata(svr) // ✅ Store the object inside Lua so it doesn't get dropped
    })?;

    globals.set("JetKvmControlSvrClient", new_svr)?;

    Ok(())

    /*
    let globals = lua.globals();

    let new_svr = lua.create_async_function(|lua, ()| async move {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static INSTANCE_COUNT: AtomicUsize = AtomicUsize::new(0);
        let instance_id = INSTANCE_COUNT.fetch_add(1, Ordering::Relaxed);
        let instance_name = format!("svr_{}", instance_id);

        let svr = LuaJetKVMControlSvrClient::new();
        let svr_userdata = lua.create_userdata(svr)?;

        // ✅ Create a strong registry reference to prevent garbage collection
        let registry_key = lua.create_registry_value(svr_userdata.clone())?;

        {
            let mut instances = GLOBAL_INSTANCES.lock().await;
            instances.insert(instance_name.clone(), registry_key);
        }

        // ✅ Also store it in Lua's global scope
        lua.globals().set(instance_name.clone(), svr_userdata.clone())?;

        println!("Created instance: {}", instance_name);

        Ok(svr_userdata)
    })?;

    globals.set("JetKvmControlSvrClient", new_svr)?;

    Ok(())
     */
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> LuaResult<()> {
    use clap::Parser;

    rustls::crypto::aws_lc_rs::default_provider().install_default(); // Install the crypto provider

    let args = Args::parse();

    let lua = Lua::new();
    let client = Arc::new(Mutex::new(JetKVMControlSvrClient::new()));

    // Push CLI args into Lua globals
    lua.globals().set("HOST", args.host.clone())?;
    lua.globals().set("PORT", args.port)?;
    lua.globals().set("PASSWORD", args.password.clone())?;
    lua.globals().set("CERT_PATH", args.ca_cert_path.clone())?;

    // Define the `connect` function
    let connect = {
    let client = client.clone();
    let host = args.host.clone();
    let port = args.port;
    let password = args.password.clone();
    let ca_cert_path = args.ca_cert_path.clone();

    lua.create_async_function(move |_, ()| {
        let client = client.clone();
        let host = host.clone();
        let password = password.clone();
        let ca_cert_path = ca_cert_path.clone();
        async move {
            let mut client_guard = client.lock().await;
            println!("Connecting to {}:{} with password {}", host, port, password);
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
    // Register JetKvmControlSvrClient before running Lua
    register_lua(&lua)?;

    let lua_script = r#"
print("Using Args: ", HOST, PORT, PASSWORD, CERT_PATH)

-- Create the server object
local svr = JetKvmControlSvrClient()
print("Attempting to connect to", HOST, PORT, CERT_PATH)
-- Use global variables for connection
local success, message = svr:connect(HOST, PORT, PASSWORD, CERT_PATH)
print("Connect result:", success, "Message:", message)

if not success then
    print("❌ Failed to authenticate. Exiting...")
    return
end

if success then
    local result = svr:send_command("active_window")  

    print("\n--- Received Data ---")
    for key, value in pairs(result) do
        print(key .. ":", value)
    end
    print("\n--- Direct Access ---")
    print("Window Title:", result.window_title or "N/A")

    local result = svr:send_command("active_process")  
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


use std::collections::HashMap;

// Global storage for instances (prevents Rust from dropping them)
lazy_static::lazy_static! {
    static ref GLOBAL_INSTANCES: Arc<Mutex<HashMap<String, mlua::RegistryKey>>> =
        Arc::new(Mutex::new(HashMap::new()));
}