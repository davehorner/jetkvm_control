pub mod auth;
pub mod device;
pub mod jetkvm_config;
pub mod jetkvm_rpc_client;
pub mod keyboard;
pub mod lua_engine;
pub mod mouse;
pub mod rpc_client;
pub mod system;

pub use jetkvm_rpc_client::JetKvmRpcClient;
pub mod jetkvm_control_svr_client;


// Re-export std common modules
pub mod prelude {
    pub use std::env;
    pub use std::error::Error;
    pub use std::fs;
    pub use std::io;
    pub use std::path::{Path, PathBuf};
    pub use std::process::exit;
    pub use std::process::Child;
    pub use std::process::Command;
    pub use std::process::Stdio;
    pub use std::sync::mpsc;
    pub use std::sync::{Arc, Mutex};
    pub use std::time::Instant;
    pub use tracing::{debug, error, info};
    #[cfg(feature = "lua")]
    pub use mlua::prelude::*;
    #[cfg(not(feature = "lua"))]
    pub type LuaResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    #[cfg(feature = "lua")]
    pub use mlua::UserData;
    
    #[cfg(not(feature = "lua"))]
    pub trait UserData {}
    #[cfg(feature = "lua")]
    pub use mlua::UserDataMethods;

    #[cfg(not(feature = "lua"))]
    pub trait UserDataMethods<T> {}

    #[cfg(feature = "lua")]
    pub use mlua::Error as LuaError;
    
    // #[cfg(not(feature = "lua"))]
    // #[derive(Debug)]
    // pub struct LuaError(Box<dyn std::error::Error + Send + Sync>);
    
    // #[cfg(not(feature = "lua"))]
    // impl LuaError {
    //     // This function mimics mlua::Error::external,
    //     // wrapping an error into our LuaError.
    //     pub fn external<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
    //         LuaError(Box::new(err))
    //     }
        
    //     // Optionally, you can add a helper for string errors:
    //     pub fn external_str<S: Into<String>>(s: S) -> Self {
    //         LuaError(Box::new(std::io::Error::new(std::io::ErrorKind::Other, s.into())))
    //     }
    // }
    
    // #[cfg(not(feature = "lua"))]
    // impl std::fmt::Display for LuaError {
    //     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    //         write!(f, "{}", self.0)
    //     }
    // }
    
    // #[cfg(not(feature = "lua"))]
    // impl std::error::Error for LuaError {
    //     fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    //         Some(&*self.0)
    //     }
    // }

}



