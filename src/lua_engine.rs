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
    pub fn register_builtin_functions(&self) -> LuaResult<()> {
        keyboard::register_lua(&self.lua, self.client.clone())?;
        mouse::register_lua(&self.lua, self.client.clone())?;
        jetkvm_control_svr_client::register_lua(&self.lua)?;
        Self::register_delay(&self.lua)?;
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
