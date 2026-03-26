use anyhow::Result as AnyResult;
use clap::{CommandFactory, Parser};
use jetkvm_control::jetkvm_config::JetKvmConfig;
use jetkvm_control::jetkvm_rpc_client::JetKvmRpcClient;
use tracing::{error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, registry, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliConfig {
    /// The host address to connect to.
    #[arg(short = 'H', long)]
    host: Option<String>,

    /// The port number to use.
    #[arg(short = 'p', long)]
    port: Option<String>,

    /// The API endpoint.
    #[arg(short = 'a', long)]
    api: Option<String>,

    /// The password for authentication.
    #[arg(short = 'P', long)]
    password: Option<String>,

    /// Increase log verbosity. Default output is warnings and errors only.
    /// Use -v for debug logging (WebRTC internals silenced), or -vv for
    /// full debug output including WebRTC internals.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    // When the "lua" feature is enabled, the first positional argument is the Lua script path.
    #[cfg(feature = "lua")]
    /// Path to the Lua script to execute.
    #[arg(required = false, index = 1, default_value = "", num_args = 0..=1)]
    lua_script: String,

    #[arg(short = 'C', long, default_value = "cert.pem")]
    ca_cert_path: Option<String>,

    /// Initialize or edit the jetkvm_control.toml interactively.
    #[arg(short = 'c', long = "config_init")]
    config_init: bool,

    /// Path to a specific jetkvm_control.toml config file.
    /// When provided, this takes precedence over the default search locations
    /// (current directory, CARGO_MANIFEST_DIR, /etc/jetkvm_control/).
    #[arg(short = 'f', long = "config")]
    config_path: Option<String>,
}

/// Loads configuration from file (or uses the default) and then applies CLI overrides.
///
/// If `--config <path>` was provided, loads exclusively from that path (errors are fatal).
/// Otherwise, falls back to the default search order: current directory, CARGO_MANIFEST_DIR,
/// then system-wide (/etc/jetkvm_control/). CLI flags (-H, -P, etc.) override any file values.
fn load_and_override_config(cli_config: &CliConfig) -> JetKvmConfig {
    let mut config = if let Some(path) = &cli_config.config_path {
        // Explicit --config path: load from that file or fail with a clear error.
        match JetKvmConfig::load_from_file(path) {
            Ok(cfg) => {
                println!("✅ Loaded config from: {}", path);
                (cfg, path.clone(), true)
            }
            Err(err) => {
                eprintln!("Error: Failed to load config from '{}': {}", path, err);
                std::process::exit(1);
            }
        }
    } else {
        // No explicit path: search default locations.
        JetKvmConfig::load().unwrap_or_else(|err| {
            warn!(
                "Failed to load jetkvm_control.toml ({}). Using default configuration.",
                err
            );
            (JetKvmConfig::default(), "".to_string(), true)
        })
    };

    if let Some(host) = &cli_config.host {
        config.0.host = host.clone();
    }
    if let Some(port) = &cli_config.port {
        config.0.port = port.clone();
    }
    if let Some(api) = &cli_config.api {
        config.0.api = api.clone();
    }
    if let Some(password) = &cli_config.password {
        config.0.password = password.clone();
    }
    if let Some(ca_cert_path) = &cli_config.ca_cert_path {
        config.0.ca_cert_path = ca_cert_path.clone();
    }
    config.0
}

#[tokio::main]
async fn main() -> AnyResult<()> {
    // Install the default crypto provider for rustls
    #[cfg(feature = "tls")]
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();
    // Parse CLI arguments.
    let cli_config = CliConfig::parse();
    info!("CLI config provided: {:?}", cli_config);
    if cli_config.config_init {
        jetkvm_control::jetkvm_config::interactive_config_location().await?;
        return Ok(());
    }
    #[cfg(feature = "lua")]
    {
        if cli_config.lua_script.is_empty() {
            eprintln!("Error: You must provide a Lua script when using the lua feature.");
            // Print help and exit.
            CliConfig::command().print_help().expect("failed to print help");
            println!(); // newline after help
            std::process::exit(1);
        }
    }

    let filter_directive = log_filter_for_verbosity(cli_config.verbose);

    // Initialize tracing subscriber with the constructed filter.
    // Create an EnvFilter using the directive.
    let env_filter = EnvFilter::new(filter_directive);

    // Build a subscriber with the filter layer and formatting layer.
    registry().with(env_filter).with(fmt::layer()).init();
    info!("Starting jetkvm_control demo...");

    // Load configuration from file (or default) and override with CLI options.
    let config = load_and_override_config(&cli_config);

    // Validate that the critical field 'host' is set.
    if config.host.trim().is_empty() {
        eprintln!("Error: No host specified. Please set 'host' in jetkvm_control.toml or provide it via --host / -H.");
        CliConfig::command()
            .print_help()
            .expect("Failed to print help");
        std::process::exit(1);
    }

    // Create and connect the client.
    let mut client = JetKvmRpcClient::new(config.clone());
    if let Err(err) = client.connect().await {
        error!("Failed to connect to RPC server: {:?}", err);
        std::process::exit(1);
    }
    client.wait_for_channel_open().await?;

    // Lua mode: if the "lua" feature is enabled, read and execute the provided Lua script.
    #[cfg(feature = "lua")]
    {
        use jetkvm_control::lua_engine::LuaEngine;
        use std::sync::Arc;
        use tokio::sync::Mutex;


// Resolve lua_script to a full absolute path
let lua_script_path = tokio::fs::canonicalize(&cli_config.lua_script).await.map_err(|e| {
    anyhow::anyhow!(
        "Error resolving Lua script path '{}'.\nArguments: {:?}\nCurrent directory: '{}'\nError: {}",
        &cli_config.lua_script,
        std::env::args().collect::<Vec<_>>(),
        std::env::current_dir().unwrap().display(),
        e
    )
})?;

let script = tokio::fs::read_to_string(&lua_script_path).await.map_err(|e| {
    anyhow::anyhow!(
        "Error reading Lua script from '{}'. Arguments passed: {:?}. Error details: {}",
        cli_config.lua_script,
        std::env::args().collect::<Vec<_>>(),
        e
    )
})?;

println!("Current working directory: {}", std::env::current_dir()?.display());
info!("Executing Lua script from {}", &cli_config.lua_script);

        // Wrap the client in an Arc/Mutex for the Lua engine.
        let client_arc = Arc::new(Mutex::new(client));
        let lua_engine = LuaEngine::new(client_arc.clone());
        lua_engine.register_builtin_functions()?;

        let config_clone = config.clone(); // ✅ Clone before moving

        lua_engine.lua().globals().set("HOST", config_clone.host)?;
        lua_engine.lua().globals().set("PORT", config_clone.port)?;
        lua_engine
            .lua()
            .globals()
            .set("PASSWORD", config_clone.password)?;
        lua_engine
            .lua()
            .globals()
            .set("CERT_PATH", config_clone.ca_cert_path)?;

        lua_engine.exec_script(&script).await?;
        info!("Lua script executed successfully.");
        // Logout after Lua execution
        client_arc.lock().await.logout().await?;
    }

    // Normal mode: if the "lua" feature is not enabled, perform normal actions.
    #[cfg(not(feature = "lua"))]
    {
        use jetkvm_control::device::{rpc_get_device_id, rpc_ping};
        use jetkvm_control::system::rpc_get_edid;

        let ping = rpc_ping(&client).await;
        info!("Ping: {:?}", ping);
        let device_id = rpc_get_device_id(&client).await;
        info!("Device ID: {:?}", device_id);
        let edid = rpc_get_edid(&client).await;
        info!("EDID: {:?}", edid);
        // Logout after Lua execution
        client.logout().await?;
    }

    Ok(())
}

/// Returns the tracing filter directive string for the given verbosity level.
///
/// Verbosity levels:
///   0 (default) — `warn` with webrtc_ice silenced (quiet output)
///   1 (-v)      — `debug` with noisy WebRTC modules silenced
///   2+ (-vv)    — `debug` for all modules including WebRTC internals
fn log_filter_for_verbosity(verbose: u8) -> &'static str {
    match verbose {
        0 => "warn,webrtc_ice=off",
        1 => "debug,\
              webrtc_sctp=off,\
              webrtc::peer_connection=off,\
              webrtc_dtls=off,\
              webrtc_mdns=off,\
              hyper_util::client=off,\
              webrtc_data::data_channel=off,\
              webrtc_ice=off",
        _ => "debug",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default verbosity (no -v flag) should produce warn-level output
    /// with webrtc_ice silenced for clean user-facing output.
    #[test]
    fn test_verbosity_0_is_warn() {
        let filter = log_filter_for_verbosity(0);
        assert!(filter.starts_with("warn"), "default should be warn level");
        assert!(filter.contains("webrtc_ice=off"), "webrtc_ice should be silenced at default level");
    }

    /// Single -v should enable debug logging but silence noisy WebRTC modules.
    #[test]
    fn test_verbosity_1_is_debug_filtered() {
        let filter = log_filter_for_verbosity(1);
        assert!(filter.starts_with("debug"), "-v should enable debug level");
        assert!(filter.contains("webrtc_sctp=off"), "webrtc_sctp should be silenced");
        assert!(filter.contains("webrtc_ice=off"), "webrtc_ice should be silenced");
        assert!(filter.contains("webrtc_dtls=off"), "webrtc_dtls should be silenced");
        assert!(filter.contains("webrtc_mdns=off"), "webrtc_mdns should be silenced");
    }

    /// Double -vv should enable full debug output with no modules silenced.
    #[test]
    fn test_verbosity_2_is_full_debug() {
        let filter = log_filter_for_verbosity(2);
        assert_eq!(filter, "debug", "-vv should be unfiltered debug");
    }

    /// Higher verbosity levels (e.g., -vvv) should behave the same as -vv.
    #[test]
    fn test_verbosity_3_plus_is_full_debug() {
        assert_eq!(log_filter_for_verbosity(3), "debug");
        assert_eq!(log_filter_for_verbosity(255), "debug");
    }
}
