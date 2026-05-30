// XEP-0384: OMEMO Encryption Implementation
// https://xmpp.org/extensions/xep-0384.html

use anyhow::{anyhow, Result};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use async_trait::async_trait;

use tokio_xmpp::AsyncClient as XMPPAsyncClient;
use xmpp_parsers::BareJid as JidBare;
use tokio_xmpp::Element;
use futures_util::StreamExt;

use crate::omemo::OmemoManager;
use crate::omemo::device_id::DeviceId;
use crate::omemo::OmemoPubSub;

mod xmpp_client_impl;
mod pubsub;
mod message;

// Re-export public items that external code references via crate::xmpp::omemo_integration::*
pub use pubsub::{
    publish_pubsub_item,
    publish_bundle_alternative_format,
    publish_pubsub_item_device_list,
    request_pubsub_items,
    publish_pubsub_item_with_client,
    publish_bundle_alternative_format_with_client,
    publish_pubsub_item_device_list_with_client,
    request_pubsub_items_with_client,
    store_pubsub_response_to,
    get_pubsub_response_from,
    element_to_xml_string,
};
pub use message::{
    handle_omemo_message,
    encrypt_message,
    publish_device_list,
    publish_key_bundle,
    XmppClient,
    parse_iv_from_header,
    add_iv_to_header,
    create_omemo_header,
    extract_omemo_data,
    process_incoming_omemo_message,
};

/// Shared map for storing pubsub responses by IQ request ID.
/// The event loop writes into this; the bridge polls from it.
pub type PubSubResponses = Arc<TokioMutex<std::collections::HashMap<String, String>>>;

/// Create a new empty PubSubResponses map.
pub fn new_pubsub_responses() -> PubSubResponses {
    Arc::new(TokioMutex::new(std::collections::HashMap::new()))
}

/// Implementation of OmemoPubSub that delegates to the XMPP connection.
/// Holds an Arc to the raw XMPP client and the shared pubsub response map.
#[derive(Clone)]
pub struct XmppPubSubBridge {
    pub(super) client: Arc<TokioMutex<XMPPAsyncClient>>,
    pub(super) responses: PubSubResponses,
}

impl XmppPubSubBridge {
    pub fn new(client: Arc<TokioMutex<XMPPAsyncClient>>, responses: PubSubResponses) -> Self {
        Self { client, responses }
    }
}

#[async_trait]
impl OmemoPubSub for XmppPubSubBridge {
    async fn request_items(&self, from: &str, node: &str) -> Result<String> {
        request_pubsub_items_with_client(&self.client, &self.responses, from, node).await
    }

    async fn publish_item(&self, to: Option<&str>, node: &str, id: &str, payload: &str) -> Result<()> {
        publish_pubsub_item_with_client(&self.client, to, node, id, payload).await
    }

    async fn publish_item_alternative(&self, to: Option<&str>, node: &str, id: &str, payload: &str) -> Result<()> {
        publish_bundle_alternative_format_with_client(&self.client, to, node, id, payload).await
    }

    async fn publish_device_list(&self, device_ids: &[DeviceId]) -> Result<()> {
        publish_pubsub_item_device_list_with_client(&self.client, device_ids).await
    }
}

// Define the OmemoIntegration struct that will be implemented below
pub struct OmemoIntegration {
    manager: Arc<TokioMutex<OmemoManager>>,
    // The JID field is used to identify the user in OMEMO operations,
    // though it's currently not directly accessed in the implementation
    jid: JidBare,
}

impl OmemoIntegration {
    /// Get the device ID for this OMEMO instance
    pub async fn get_device_id(&self) -> Result<DeviceId> {
        let manager_guard = self.manager.lock().await;
        Ok(manager_guard.get_device_id())
    }

    pub async fn publish_device_list(&self, client: &mut XMPPAsyncClient) -> Result<()> {
        // Get the bare JID and device ID
        let bare_jid = self.jid.to_string();
        let device_id = self.get_device_id().await?;
        
        // Generate a unique ID for the IQ stanza
        let request_id = uuid::Uuid::new_v4().to_string();
        
        // Create the element structure directly instead of parsing from string
        let mut device_elem = Element::bare("device", "eu.siacs.conversations.axolotl");
        device_elem.set_attr("id", device_id.to_string());
        
        let mut list_elem = Element::bare("list", "eu.siacs.conversations.axolotl");
        list_elem.append_child(device_elem);
        
        let mut item_elem = Element::bare("item", "http://jabber.org/protocol/pubsub");
        item_elem.set_attr("id", "current");
        item_elem.append_child(list_elem);
        
        let mut publish_elem = Element::bare("publish", "http://jabber.org/protocol/pubsub");
        publish_elem.set_attr("node", "eu.siacs.conversations.axolotl.devicelist");
        publish_elem.append_child(item_elem);
        
        let mut pubsub_elem = Element::bare("pubsub", "http://jabber.org/protocol/pubsub");
        pubsub_elem.append_child(publish_elem);
        
        let mut iq = Element::bare("iq", "jabber:client");
        iq.set_attr("type", "set");
        iq.set_attr("id", request_id.clone());
        iq.append_child(pubsub_elem);
        
        info!("Would publish PubSub item: {:?}", iq);
        
        // Send the stanza
        client.send_stanza(iq).await?;
        
        // Wait for a response with matching ID
        let timeout = tokio::time::Duration::from_secs(5);
        let start_time = tokio::time::Instant::now();
        
        while tokio::time::Instant::now().duration_since(start_time) < timeout {
            match tokio::time::timeout(
                tokio::time::Duration::from_millis(500),
                client.next()
            ).await {
                Ok(Some(event)) => match event {
                    tokio_xmpp::Event::Stanza(stanza) => {
                        if stanza.name() == "iq" && stanza.attr("id") == Some(&request_id) {
                            let iq_type = stanza.attr("type").unwrap_or("");
                            
                            if iq_type == "error" {
                                if let Some(error) = stanza.get_child("error", "") {
                                    let error_type = error.attr("type").unwrap_or("unknown");
                                    let mut error_text = "unknown error".to_string();
                                    
                                    for child in error.children() {
                                        if child.name() == "text" {
                                            error_text = child.text();
                                        }
                                    }
                                    
                                    let error_msg = format!("Failed to publish device list: {} ({})", error_text, error_type);
                                    error!("{}", error_msg);
                                    
                                    if error_text.contains("invalid item") {
                                        error!("Invalid item when publishing device list: {:?}", stanza);
                                    }
                                    
                                    return Err(anyhow!(error_msg));
                                }
                                
                                return Err(anyhow!("Failed to publish device list: unknown error"));
                            } else if iq_type == "result" {
                                info!("Successfully published device list for {}", bare_jid);
                                return Ok(());
                            }
                        }
                    },
                    tokio_xmpp::Event::Disconnected(reason) => {
                        return Err(anyhow!("Disconnected while waiting for device list publish response: {:?}", reason));
                    },
                    _ => {}
                },
                Ok(None) => {
                    return Err(anyhow!("Stream ended while waiting for device list publish response"));
                },
                Err(_) => {
                    // Timeout on this attempt, continue the loop
                    continue;
                }
            }
        }
        
        warn!("Timed out waiting for device list publish response");
        Ok(())
    }
}
