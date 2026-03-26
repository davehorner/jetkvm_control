#![cfg(feature = "lua")]
// jetkvm_control/src/lua_engine.rs

use anyhow::Result as AnyResult;
use mlua::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::jetkvm_control_svr_client;
use crate::jetkvm_rpc_client::JetKvmRpcClient;
use crate::keyboard;
use crate::mouse;

/// LuaEngine encapsulates an mlua::Lua instance and a shared RPC client.
/// It registers built-in functions (such as keyboard and mouse functions) so that Lua scripts can trigger RPC calls.
pub struct LuaEngine {
    lua: Lua,
    client: Arc<Mutex<JetKvmRpcClient>>,
}

impl LuaEngine {
    /// Creates a new LuaEngine given a shared RPC client.
    pub fn new(client: Arc<Mutex<JetKvmRpcClient>>) -> Self {
        let lua = Lua::new();
        Self { lua, client }
    }

    pub fn register_delay(lua: &Lua) -> LuaResult<()> {
        let delay_fn = lua.create_function(|_, millis: u64| {
            std::thread::sleep(Duration::from_millis(millis)); // ⬅️ Now blocking
            Ok(())
        })?;
        lua.globals().set("delay", delay_fn)?;
        Ok(())
        /* let delay_fn = lua.create_async_function(|_, millis: u64| async move {
            sleep(Duration::from_millis(millis)).await;
            Ok(())
        })?;
        lua.globals().set("delay", delay_fn)?;
        Ok(())
        */
    }

    /// Registers built-in functions from other modules (e.g., keyboard and mouse) to the Lua context.
    ///
    /// This includes the generic `send_rpc` function which allows Lua scripts to invoke
    /// arbitrary JSON-RPC methods on the JetKVM device — enabling features like ATX power
    /// control that don't have dedicated Lua bindings.
    pub fn register_builtin_functions(&self) -> LuaResult<()> {
        keyboard::register_lua(&self.lua, self.client.clone())?;
        mouse::register_lua(&self.lua, self.client.clone())?;
        jetkvm_control_svr_client::register_lua(&self.lua)?;
        Self::register_delay(&self.lua)?;
        Self::register_send_rpc(&self.lua, self.client.clone())?;
        Ok(())
    }

    /// Registers a generic `send_rpc(method, params_json)` Lua function that forwards
    /// arbitrary JSON-RPC calls to the JetKVM device over the WebRTC data channel.
    ///
    /// This bridges the gap between the JetKVM firmware's full JSON-RPC API and the
    /// subset of Lua bindings provided by jetkvm_control. Lua scripts can call any
    /// method the device supports without needing a dedicated Rust binding.
    ///
    /// # Lua signature
    /// ```lua
    /// result_json = send_rpc(method_name, params_json_string)
    /// ```
    ///
    /// # Arguments (from Lua)
    /// * `method` — The JSON-RPC method name (e.g., `"setATXPowerAction"`, `"getATXState"`)
    /// * `params_json` — A JSON string of the method parameters (e.g., `'{"action": "reset"}'`)
    ///
    /// # Returns
    /// A JSON string of the RPC response, or raises a Lua error on invalid JSON or RPC failure.
    ///
    /// # Example Lua usage
    /// ```lua
    /// -- Query ATX power/HDD LED state
    /// local state = send_rpc("getATXState", "{}")
    /// print("ATX state: " .. state)
    ///
    /// -- Press the ATX reset button
    /// send_rpc("setATXPowerAction", '{"action": "reset"}')
    ///
    /// -- Short press the ATX power button
    /// send_rpc("setATXPowerAction", '{"action": "power-short"}')
    ///
    /// -- Long press the ATX power button (force off, holds ~5s)
    /// send_rpc("setATXPowerAction", '{"action": "power-long"}')
    /// ```
    pub fn register_send_rpc(lua: &Lua, client: Arc<Mutex<JetKvmRpcClient>>) -> LuaResult<()> {
        let send_rpc_fn = lua.create_async_function(move |_, (method, params_json): (String, String)| {
            let client = client.clone();
            async move {
                // Parse the JSON string into a serde_json::Value for the RPC layer.
                let params: serde_json::Value = serde_json::from_str(&params_json)
                    .map_err(|e| mlua::Error::external(e))?;
                // Forward the call through the WebRTC JSON-RPC channel.
                let result = client.lock().await.send_rpc(&method, params).await
                    .map_err(|e| mlua::Error::external(e))?;
                // Return the result as a JSON string back to Lua.
                Ok(result.to_string())
            }
        })?;
        lua.globals().set("send_rpc", send_rpc_fn)?;
        Ok(())
    }

    /// Asynchronously executes the provided Lua script.
    pub async fn exec_script(&self, script: &str) -> AnyResult<()> {
        self.lua
            .load(script)
            .exec_async()
            .await
            .map_err(|e| e.into())
    }

    /// Provides access to the underlying Lua instance.
    pub fn lua(&self) -> &Lua {
        &self.lua
    }
}

/// Tests for the LuaEngine and the `send_rpc` Lua binding.
///
/// These tests use an unconnected `JetKvmRpcClient` (no real WebRTC session) which is
/// sufficient to validate that:
///   - Lua functions are correctly registered in the global namespace
///   - JSON parsing in `send_rpc` properly rejects malformed input
///   - The RPC layer correctly surfaces "not connected" errors
///   - The engine can execute Lua scripts and the `delay` function works
///
/// Integration tests against a live JetKVM device are not included here — use the
/// Lua example scripts in `lua-examples/` (e.g., `atx_status.lua`) for end-to-end validation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::jetkvm_config::JetKvmConfig;

    /// Helper: creates an unconnected RPC client wrapped in Arc<Mutex> for test use.
    /// No network calls are made — the client is in a disconnected state, which is
    /// intentional for testing error paths and function registration.
    fn make_test_client() -> Arc<Mutex<JetKvmRpcClient>> {
        let config = JetKvmConfig::default();
        Arc::new(Mutex::new(JetKvmRpcClient::new(config)))
    }

    /// Verify that LuaEngine::new() produces a working Lua VM with standard globals.
    #[test]
    fn test_lua_engine_creation() {
        let client = make_test_client();
        let engine = LuaEngine::new(client);
        assert!(engine.lua().globals().get::<mlua::Value>("print").is_ok());
    }

    /// Verify the `delay(ms)` function registers and is callable with 0ms.
    #[test]
    fn test_register_delay() {
        let lua = Lua::new();
        LuaEngine::register_delay(&lua).expect("register_delay should succeed");
        let delay: mlua::Function = lua.globals().get("delay").expect("delay should be registered");
        delay.call::<()>(0u64).expect("delay(0) should succeed");
    }

    /// Exhaustive check that all expected Lua globals are present after registration.
    /// This catches regressions where a new Rust function forgets to call `.set()`.
    #[test]
    fn test_register_builtin_functions() {
        let client = make_test_client();
        let engine = LuaEngine::new(client);
        engine
            .register_builtin_functions()
            .expect("register_builtin_functions should succeed");

        let globals = engine.lua().globals();

        // Keyboard functions (from keyboard.rs)
        assert!(globals.get::<mlua::Function>("send_return").is_ok(), "send_return should be registered");
        assert!(globals.get::<mlua::Function>("send_ctrl_a").is_ok(), "send_ctrl_a should be registered");
        assert!(globals.get::<mlua::Function>("send_ctrl_c").is_ok(), "send_ctrl_c should be registered");
        assert!(globals.get::<mlua::Function>("send_ctrl_v").is_ok(), "send_ctrl_v should be registered");
        assert!(globals.get::<mlua::Function>("send_ctrl_x").is_ok(), "send_ctrl_x should be registered");
        assert!(globals.get::<mlua::Function>("send_windows_key").is_ok(), "send_windows_key should be registered");
        assert!(globals.get::<mlua::Function>("send_text").is_ok(), "send_text should be registered");
        assert!(globals.get::<mlua::Function>("send_key_combinations").is_ok(), "send_key_combinations should be registered");

        // Mouse functions (from mouse.rs)
        assert!(globals.get::<mlua::Function>("move_mouse").is_ok(), "move_mouse should be registered");
        assert!(globals.get::<mlua::Function>("left_click").is_ok(), "left_click should be registered");
        assert!(globals.get::<mlua::Function>("right_click").is_ok(), "right_click should be registered");
        assert!(globals.get::<mlua::Function>("middle_click").is_ok(), "middle_click should be registered");
        assert!(globals.get::<mlua::Function>("double_click").is_ok(), "double_click should be registered");

        // Utility functions
        assert!(globals.get::<mlua::Function>("delay").is_ok(), "delay should be registered");

        // Generic RPC binding (from register_send_rpc — enables ATX power control etc.)
        assert!(globals.get::<mlua::Function>("send_rpc").is_ok(), "send_rpc should be registered");
    }

    /// Verify send_rpc can be registered independently (not just via register_builtin_functions).
    #[test]
    fn test_register_send_rpc() {
        let client = make_test_client();
        let lua = Lua::new();
        LuaEngine::register_send_rpc(&lua, client).expect("register_send_rpc should succeed");
        assert!(
            lua.globals().get::<mlua::Function>("send_rpc").is_ok(),
            "send_rpc should be registered"
        );
    }

    /// send_rpc must reject malformed JSON in the params argument before touching the RPC layer.
    #[tokio::test]
    async fn test_send_rpc_rejects_invalid_json() {
        let client = make_test_client();
        let engine = LuaEngine::new(client);
        engine
            .register_builtin_functions()
            .expect("register should succeed");

        let result = engine
            .exec_script(r#"send_rpc("someMethod", "not valid json{")"#)
            .await;
        assert!(result.is_err(), "invalid JSON params should cause an error");
    }

    /// send_rpc with valid JSON but no WebRTC connection must surface the "not connected" error.
    #[tokio::test]
    async fn test_send_rpc_rejects_unconnected_client() {
        let client = make_test_client();
        let engine = LuaEngine::new(client);
        engine
            .register_builtin_functions()
            .expect("register should succeed");

        let result = engine
            .exec_script(r#"send_rpc("ping", "{}")"#)
            .await;
        assert!(result.is_err(), "send_rpc on unconnected client should error");
    }

    /// Basic sanity check: a Lua script with no RPC calls should execute successfully.
    #[tokio::test]
    async fn test_exec_script_basic() {
        let client = make_test_client();
        let engine = LuaEngine::new(client);
        engine
            .register_builtin_functions()
            .expect("register should succeed");

        let result = engine.exec_script("x = 1 + 2").await;
        assert!(result.is_ok(), "basic Lua script should succeed");
    }

    /// Verify that `delay(ms)` actually sleeps for approximately the requested duration.
    #[tokio::test]
    async fn test_exec_script_with_delay() {
        let client = make_test_client();
        let engine = LuaEngine::new(client);
        engine
            .register_builtin_functions()
            .expect("register should succeed");

        let start = std::time::Instant::now();
        let result = engine.exec_script("delay(50)").await;
        let elapsed = start.elapsed();
        assert!(result.is_ok(), "delay script should succeed");
        assert!(
            elapsed.as_millis() >= 40,
            "delay(50) should sleep at least ~50ms, got {}ms",
            elapsed.as_millis()
        );
    }

    /// Verify that the config globals (HOST, PORT, PASSWORD, CERT_PATH) that main.rs
    /// injects into the Lua VM can be set and read back correctly.
    #[test]
    fn test_lua_globals_set_by_main() {
        let client = make_test_client();
        let engine = LuaEngine::new(client);
        engine.lua().globals().set("HOST", "10.0.0.1").expect("set HOST");
        engine.lua().globals().set("PORT", "80").expect("set PORT");
        engine.lua().globals().set("PASSWORD", "secret").expect("set PASSWORD");
        engine.lua().globals().set("CERT_PATH", "cert.pem").expect("set CERT_PATH");

        let host: String = engine.lua().globals().get("HOST").unwrap();
        assert_eq!(host, "10.0.0.1");
    }
}
