use crate::jetkvm_rpc_client::JetKvmRpcClient;
use anyhow::Result as AnyResult;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};

/// Sends an absolute mouse report with x, y coordinates and button state.
pub async fn rpc_abs_mouse_report(
    client: &JetKvmRpcClient,
    x: i64,
    y: i64,
    buttons: u64,
) -> AnyResult<Value> {
    let params = json!({
        "x": x,
        "y": y,
        "buttons": buttons,
    });
    client.send_rpc("absMouseReport", params).await
}

/// Sends a wheel report with the given wheelY value.
pub async fn rpc_wheel_report(client: &JetKvmRpcClient, wheel_y: i64) -> AnyResult<Value> {
    let params = json!({ "wheelY": wheel_y });
    client.send_rpc("wheelReport", params).await
}

/// Moves the mouse to the specified absolute coordinates.
pub async fn rpc_move_mouse(client: &JetKvmRpcClient, x: i64, y: i64) -> AnyResult<()> {
    let params = json!({
        "x": x,
        "y": y,
        "buttons": 0,
    });
    client.send_rpc("absMouseReport", params).await?;
    Ok(())
}

/// Simulates a left mouse click at the specified coordinates.
/// It moves the mouse (optional if already positioned), then sends a press and release.
pub async fn rpc_left_click(client: &JetKvmRpcClient, x: i64, y: i64) -> AnyResult<()> {
    // Optionally move the mouse first:
    rpc_move_mouse(client, x, y).await?;

    // Press left button (assumed bit 0: value = 1)
    let params_down = json!({
        "x": x,
        "y": y,
        "buttons": 1
    });
    client.send_rpc("absMouseReport", params_down).await?;

    // Wait a little bit
    sleep(Duration::from_millis(100)).await;

    // Release button
    let params_up = json!({
        "x": x,
        "y": y,
        "buttons": 0
    });
    client.send_rpc("absMouseReport", params_up).await?;
    Ok(())
}

/// Simulates a right mouse click at the specified coordinates.
/// Right-click is typically represented as button bit 1 (value = 2).
pub async fn rpc_right_click(client: &JetKvmRpcClient, x: i64, y: i64) -> AnyResult<()> {
    rpc_move_mouse(client, x, y).await?;
    let params_down = json!({
        "x": x,
        "y": y,
        "buttons": 2
    });
    client.send_rpc("absMouseReport", params_down).await?;
    sleep(Duration::from_millis(100)).await;
    let params_up = json!({
        "x": x,
        "y": y,
        "buttons": 0
    });
    client.send_rpc("absMouseReport", params_up).await?;
    Ok(())
}

/// Simulates a middle mouse click at the specified coordinates.
/// Middle-click is typically represented as button bit 2 (value = 4).
pub async fn rpc_middle_click(client: &JetKvmRpcClient, x: i64, y: i64) -> AnyResult<()> {
    rpc_move_mouse(client, x, y).await?;
    let params_down = json!({
        "x": x,
        "y": y,
        "buttons": 4
    });
    client.send_rpc("absMouseReport", params_down).await?;
    sleep(Duration::from_millis(100)).await;
    let params_up = json!({
        "x": x,
        "y": y,
        "buttons": 0
    });
    client.send_rpc("absMouseReport", params_up).await?;
    Ok(())
}

/// Simulates a double left click at the specified coordinates.
pub async fn rpc_double_click(client: &JetKvmRpcClient, x: i64, y: i64) -> AnyResult<()> {
    rpc_left_click(client, x, y).await?;
    // Short delay between clicks
    sleep(Duration::from_millis(150)).await;
    rpc_left_click(client, x, y).await?;
    Ok(())
}

/// Simulates a left click and drag from the given start coordinates to the center of the screen.
pub async fn rpc_left_click_and_drag_to_center(
    client: &JetKvmRpcClient,
    start_x: i64,
    start_y: i64,
) -> AnyResult<()> {
    // Define center coordinates. Adjust these values as needed for your display.
    let center_x = 960;
    let center_y = 540;

    // 1. Move the mouse to the starting position (no buttons pressed)
    client
        .send_rpc(
            "absMouseReport",
            json!({
                "x": start_x,
                "y": start_y,
                "buttons": 0,
            }),
        )
        .await?;
    sleep(Duration::from_millis(100)).await;

    // 2. Press the left button down (buttons = 1)
    client
        .send_rpc(
            "absMouseReport",
            json!({
                "x": start_x,
                "y": start_y,
                "buttons": 1,
            }),
        )
        .await?;
    sleep(Duration::from_millis(100)).await;

    // 3. Send intermediate drag updates from start to center.
    // We'll use a number of steps to simulate continuous movement.
    let steps = 100;
    for i in 1..=steps {
        let x = start_x + ((center_x - start_x) * i) / steps;
        let y = start_y + ((center_y - start_y) * i) / steps;
        client
            .send_rpc(
                "absMouseReport",
                json!({
                    "x": x,
                    "y": y,
                    "buttons": 1,
                }),
            )
            .await?;
        sleep(Duration::from_millis(50)).await;
    }

    // 4. Release the left button at the center.
    client
        .send_rpc(
            "absMouseReport",
            json!({
                "x": center_x,
                "y": center_y,
                "buttons": 0,
            }),
        )
        .await?;
    sleep(Duration::from_millis(100)).await;

    client
        .send_rpc(
            "absMouseReport",
            json!({
                "x": 960,
                "y": 540,
                "buttons": 1
            }),
        )
        .await?;

    client
        .send_rpc(
            "absMouseReport",
            json!({
                "x": 960,
                "y": 540,
                "buttons": 1,
            }),
        )
        .await?;
    Ok(())
}

/// Registers mouse functions to the provided Lua context.
#[cfg(feature = "lua")]
use mlua::prelude::*;
#[cfg(feature = "lua")]
use std::sync::Arc;
#[cfg(feature = "lua")]
use tokio::sync::Mutex;
#[cfg(feature = "lua")]
pub fn register_lua(lua: &Lua, client: Arc<Mutex<JetKvmRpcClient>>) -> LuaResult<()> {
    let left_click_fn = {
        let client = client.clone();
        lua.create_async_function(move |_, (x, y): (i64, i64)| {
            let client = client.clone();
            async move {
                rpc_left_click(&*client.lock().await, x, y)
                    .await
                    .map_err(mlua::Error::external)
            }
        })?
    };
    lua.globals().set("left_click", left_click_fn)?;

    let right_click_fn = {
        let client = client.clone();
        lua.create_async_function(move |_, (x, y): (i64, i64)| {
            let client = client.clone();
            async move {
                rpc_right_click(&*client.lock().await, x, y)
                    .await
                    .map_err(mlua::Error::external)
            }
        })?
    };
    lua.globals().set("right_click", right_click_fn)?;

    let middle_click_fn = {
        let client = client.clone();
        lua.create_async_function(move |_, (x, y): (i64, i64)| {
            let client = client.clone();
            async move {
                rpc_middle_click(&*client.lock().await, x, y)
                    .await
                    .map_err(mlua::Error::external)
            }
        })?
    };
    lua.globals().set("middle_click", middle_click_fn)?;

    let move_mouse_fn = {
        let client = client.clone();
        lua.create_async_function(move |_, (x, y): (i64, i64)| {
            let client = client.clone();
            async move {
                rpc_move_mouse(&*client.lock().await, x, y)
                    .await
                    .map_err(mlua::Error::external)
            }
        })?
    };
    lua.globals().set("move_mouse", move_mouse_fn)?;

    let double_click_fn = {
        let client = client.clone();
        lua.create_async_function(move |_, (x, y): (i64, i64)| {
            let client = client.clone();
            async move {
                rpc_double_click(&*client.lock().await, x, y)
                    .await
                    .map_err(mlua::Error::external)
            }
        })?
    };
    lua.globals().set("double_click", double_click_fn)?;

    Ok(())
}
