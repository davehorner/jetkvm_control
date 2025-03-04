use crate::auth;
use crate::jetkvm_config::JetKvmConfig;
use crate::rpc_client::RpcClient;
use anyhow::{anyhow, Result as AnyResult};
use base64::{engine::general_purpose, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{atomic::AtomicUsize, Arc};
use tokio::{sync::Mutex, task::spawn_blocking};
use tokio::time::Duration;
use tracing::debug;
use webrtc::{
    api::{media_engine::MediaEngine, APIBuilder},
    dtls::extension::extension_use_srtp::SrtpProtectionProfile,
    peer_connection::{
        configuration::RTCConfiguration,
        sdp::{sdp_type::RTCSdpType, session_description::RTCSessionDescription},
    },
};

/// A global atomic for unique JSON-RPC request IDs.
static REQUEST_COUNTER: AtomicUsize = AtomicUsize::new(1);

#[derive(Serialize, Deserialize)]
struct WebRTCSessionRequest {
    sd: String,
}

#[derive(Serialize, Deserialize)]
struct WebRTCSessionResponse {
    sd: String,
}

/// `JetKvmRpcClient` encapsulates both an authenticated HTTP client and an established
/// WebRTC JSON-RPC connection.
pub struct JetKvmRpcClient {
    pub config: JetKvmConfig,
    pub http_client: Option<Client>,
    pub rpc_client: Option<RpcClient>,
    pub screen_size: Arc<Mutex<Option<(u32, u32)>>>,
}

impl JetKvmRpcClient {
    /// Creates a new `JetKvmRpcClient` without connecting.
    pub fn new(config: JetKvmConfig) -> Self {
        debug!("Initializing JetKvmRpcClient with config: {:?}", config);
        Self {
            config,
            http_client: None,
            rpc_client: None,
            screen_size: Arc::new(Mutex::new(None)),
        }
    }

    /// Connects the client to the JetKVM service.
    pub async fn connect(&mut self) -> AnyResult<()> {
        debug!("Connecting to JetKVM...");

        // 1. Authenticate via HTTP.
        let http_client = auth::login_local(&self.config.host, &self.config.password).await?;
        debug!("Authentication successful.");
        self.http_client = Some(http_client.clone());

        // 2. Initialize WebRTC.
        let mut setting_engine = webrtc::api::setting_engine::SettingEngine::default();
        setting_engine.set_srtp_protection_profiles(vec![
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ]);
        let media_engine = MediaEngine::default();
        let api = APIBuilder::new()
            .with_setting_engine(setting_engine)
            .with_media_engine(media_engine)
            .build();
        let config_rtc = RTCConfiguration::default();
        let peer_connection = Arc::new(api.new_peer_connection(config_rtc).await?);
        debug!("PeerConnection created.");

        // 3. Create a DataChannel named "rpc".
        let data_channel = peer_connection.create_data_channel("rpc", None).await?;
        data_channel.on_open(Box::new(move || {
            Box::pin(async move {
                debug!("✅ DataChannel 'rpc' is now open!");
            })
        }));

        debug!("DataChannel created and awaiting connection.");

        // 5. Create an SDP offer and set it locally.
        let offer = peer_connection.create_offer(None).await?;
        peer_connection.set_local_description(offer.clone()).await?;
        debug!("Local SDP Offer set.");

        // 6. Wrap the offer in JSON.
        let offer_type_str = match offer.sdp_type {
            RTCSdpType::Offer => "offer",
            RTCSdpType::Answer => "answer",
            RTCSdpType::Pranswer => "pranswer",
            RTCSdpType::Rollback => "rollback",
            _ => return Err(anyhow!("Unsupported SDP type")),
        };

        #[derive(Serialize)]
        struct LocalOfferJson {
            sdp: String,
            #[serde(rename = "type")]
            sdp_type: String,
        }

        let local_offer_json = LocalOfferJson {
            sdp: offer.sdp.clone(),
            sdp_type: offer_type_str.to_owned(),
        };

        let offer_str = serde_json::to_string(&local_offer_json)?;
        let encoded_offer = general_purpose::STANDARD.encode(offer_str);
        let session_request = WebRTCSessionRequest { sd: encoded_offer };

        // 7. Send the offer to the server.
        let url = self.config.session_url();
        //debug!("Sending SDP Offer to {}", url);

        let response = http_client.post(&url).json(&session_request).send().await?;
        let response_text = response.text().await?;
        //debug!("Received SDP Answer response: {}", response_text);

        let session_response: WebRTCSessionResponse = serde_json::from_str(&response_text)?;
        let decoded_answer = general_purpose::STANDARD.decode(session_response.sd)?;
        let answer_value: Value = serde_json::from_slice(&decoded_answer)?;
        //debug!("Decoded SDP answer: {}", answer_value);

        let sdp_field = answer_value
            .get("sdp")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing sdp field in answer"))?;

        let sdp_type_str = answer_value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("answer");

        let remote_desc = match sdp_type_str {
            "offer" => RTCSessionDescription::offer(sdp_field.to_owned())?,
            "answer" => RTCSessionDescription::answer(sdp_field.to_owned())?,
            "pranswer" => RTCSessionDescription::pranswer(sdp_field.to_owned())?,
            "rollback" => return Err(anyhow!("Rollback not supported")),
            other => return Err(anyhow!("Unknown SDP type: {}", other)),
        };

        peer_connection.set_remote_description(remote_desc).await?;
        debug!("Remote SDP Answer set.");

        let rpc_client = RpcClient::new(data_channel);
        rpc_client.install_message_handler();
        self.rpc_client = Some(rpc_client);

        debug!("JetKvmRpcClient connected successfully.");
        Ok(())
    }

    /// Sends an RPC request if the client is connected.
    pub async fn send_rpc(&self, method: &str, params: Value) -> AnyResult<Value> {
        match &self.rpc_client {
            Some(rpc) => rpc.send_rpc(method, params).await,
            None => Err(anyhow!(
                "RPC client is not connected. Call `connect()` first."
            )),
        }
    }
    /// Waits for the WebRTC DataChannel to be open.
    pub async fn wait_for_channel_open(&self) -> AnyResult<()> {
        if let Some(rpc_client) = &self.rpc_client {
            loop {
                if format!("{:?}", rpc_client.dc.ready_state()) == "Open" {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        } else {
            Err(anyhow!(
                "RPC client is not connected. Call `connect()` first."
            ))
        }
    }
    pub async fn ensure_connected(&mut self) -> AnyResult<()> {
        if self.rpc_client.is_none() {
            self.connect().await?;
        }
        Ok(())
    }
        /// Asynchronous logout function for normal use.
    pub async fn logout(&self) -> AnyResult<()> {

        if let Some(client) = &self.http_client {
            let url = format!("http://{}/auth/logout", self.config.host);
            let resp = client.post(&url).send().await;

            match resp {
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_else(|_| "Failed to read body".to_string());
                    tracing::info!("Logout Response [{}]: {}", status, body);
                    Ok(())
                }
                Err(e) => {
                    tracing::error!("Logout request failed: {}", e);
                    Err(anyhow::anyhow!("Logout request failed: {}", e))
                }
            }
        } else {
            tracing::warn!("No HTTP client available, skipping logout.");
            Ok(())
        }
    }

    /// Gracefully disconnects by logging out and closing the RPC connection.
    pub async fn shutdown(&mut self) {
        if self.config.no_auto_logout {
            tracing::info!("Auto-logout is disabled in config, skipping logout.");
        } else {
            if let Err(e) = self.logout().await {
                tracing::warn!("Failed to logout on shutdown: {}", e);
            }
        }

        if let Some(rpc) = self.rpc_client.take() {
            tracing::info!("Closing WebRTC RPC connection...");
            let _ = rpc.dc.close().await;
        }

        tracing::info!("JetKvmRpcClient shutdown completed.");
    }

}

impl Drop for JetKvmRpcClient {
    
    fn drop(&mut self) {
        tracing::info!("JetKvmRpcClient dropped.");
    }
}