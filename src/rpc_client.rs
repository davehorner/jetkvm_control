use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Result as AnyResult};
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tracing::{debug, error};
use webrtc::data_channel::{
    data_channel_message::DataChannelMessage, data_channel_state::RTCDataChannelState,
    RTCDataChannel,
};

static REQUEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
/// A callback type for notifications. It takes the method name and params.
pub type NotificationCallback = Arc<dyn Fn(&str, &Value) + Send + Sync>;

pub struct RpcClient {
    pub dc: Arc<RTCDataChannel>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<AnyResult<Value>>>>>,
    notification_callback: Option<NotificationCallback>,
}

impl RpcClient {
    /// Creates a new RpcClient from an RTCDataChannel.
    pub fn new(dc: Arc<RTCDataChannel>) -> Self {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        Self {
            dc: dc.clone(),
            pending,
            notification_callback: None,
        }
    }
    /// Installs the on_message handler.
    /// This handler processes both responses (with an "id") and notifications (without an "id").
    pub fn install_message_handler(&self) {
        let pending = self.pending.clone();
        // Clone the callback Option (if any). Since it's an Option<Box<_>>,
        // we can clone it if we derive Clone for the Box (or just move a reference).
        // For simplicity, we'll move a clone of the Option here.
        let notification_callback = self.notification_callback.clone();
        self.dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let pending_clone = pending.clone(); // Clone it before moving it inside async

            Box::pin({
            let value = notification_callback.clone();
            async move {
                let text = String::from_utf8(msg.data.to_vec()).unwrap_or_default();

                match serde_json::from_str::<Value>(&text) {
                    Ok(v) => {
                        if let Some(id_val) = v.get("id") {
                            if let Some(id) = id_val.as_u64() {
                                let mut map = pending_clone.lock().unwrap();
                                if let Some(tx) = map.remove(&id) {
                                    let _ = tx.send(Ok(v));
                                } else {
                                    debug!("Response ID not found in pending map: {}", id);
                                }
                            }
                        } else {
                            debug!("msg: {}", text);
                                                   // This branch handles notifications (no "id" field).
                        if let Some(callback) = value.as_ref() {
                            if let Some(method) = v.get("method").and_then(|m| m.as_str()) {
                                // Extract "params" if available, defaulting to Null.
                                let params = v.get("params").cloned().unwrap_or(Value::Null);
                                callback(method, &params);
                            } else {
                                debug!("Notification received but missing 'method' field: {}", text);
                            }
                        } else {
                            debug!("Notification received (no callback installed): {}", text);
                        }
                        }
                    }
                    Err(e) => {
                        error!("❌ Invalid JSON Received: {}: {:?}", text, e);
                    }
                }
            }
            })
        }));
    }

    pub async fn send_rpc(&self, method: &str, params: Value) -> AnyResult<Value> {
        if self.dc.ready_state() != RTCDataChannelState::Open {
            error!("❌ DataChannel not open");
            return Err(anyhow!("DataChannel not open"));
        }

        let id = REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let payload = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id
        });
        let payload_str = payload.to_string();

        let (tx, rx) = oneshot::channel();
        {
            let mut map = self.pending.lock().unwrap();
            map.insert(id, tx);
        }

        match self.dc.send_text(&payload_str).await {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to send RPC: {:?}", e);
                return Err(anyhow!("Failed to send RPC"));
            }
        }

        match rx.await {
            Ok(response) => {
                //debug!("Received RPC Response: {:?}", response);
                response
            }
            Err(_) => {
                error!("Response channel closed");
                Err(anyhow!("Response channel closed"))
            }
        }
    }

    /// Sets the notification callback. The callback receives the method name and parameters.
    pub fn set_notification_callback<F>(&mut self, callback: F)
    where
        F: Fn(&str, &Value) + Send + Sync + 'static,
    {
        self.notification_callback = Some(Arc::new(callback));
    }
}
