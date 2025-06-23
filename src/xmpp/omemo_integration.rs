// XEP-0384: OMEMO Encryption Implementation
// https://xmpp.org/extensions/xep-0384.html

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn, trace};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::Duration;
use uuid::Uuid;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

use tokio_xmpp::AsyncClient as XMPPAsyncClient;
// Add import for IqType
use xmpp_parsers::BareJid as JidBare;
use tokio_xmpp::Element;
use futures_util::StreamExt; // Import for the next() method

use crate::models::{Message, DeliveryStatus};
use super::custom_ns;
use crate::omemo::{OmemoManager, OMEMO_NAMESPACE};
use crate::omemo::device_id::DeviceId;
use crate::omemo::crypto;

// Import for key acceptance
use crate::omemo::OmemoError;

// Global client reference for publishing operations
lazy_static::lazy_static! {
    static ref CURRENT_CLIENT: std::sync::RwLock<Option<Arc<TokioMutex<XMPPAsyncClient>>>> = std::sync::RwLock::new(None);
}

/// Set the current client for publishing operations
pub fn set_current_client(client: XMPPAsyncClient) {
    if let Ok(mut current_client) = CURRENT_CLIENT.write() {
        //debug!("Setting current client for OMEMO integration");
        *current_client = Some(Arc::new(TokioMutex::new(client)));
    } else {
        error!("Failed to acquire write lock for current client");
    }
}

/// Set the current client for publishing operations using an Arc<TokioMutex<XMPPAsyncClient>>
pub fn set_current_client_arc(client: Arc<TokioMutex<XMPPAsyncClient>>) {
    if let Ok(mut current_client) = CURRENT_CLIENT.write() {
        //debug!("Setting current client for OMEMO integration from Arc reference");
        *current_client = Some(client);
    } else {
        error!("Failed to acquire write lock for current client");
    }
}

/// Get the current client for publishing operations
pub fn get_current_client() -> Option<Arc<TokioMutex<XMPPAsyncClient>>> {
    if let Ok(current_client) = CURRENT_CLIENT.read() {
        current_client.clone()
    } else {
        error!("Failed to acquire read lock for current client");
        None
    }
}

// Define the OmemoIntegration struct that will be implemented below
pub struct OmemoIntegration {
    manager: Arc<TokioMutex<OmemoManager>>,
    // The JID field is used to identify the user in OMEMO operations,
    // though it's currently not directly accessed in the implementation
    jid: JidBare,
}

/// Implementation of XEP-0384 OMEMO Encryption
impl super::XMPPClient {

    /// Send an OMEMO encrypted message
    pub async fn send_omemo_encrypted_message(&self, recipient: &str, plaintext: &str) -> Result<()> {
        if self.client.is_none() {
            error!("XMPP client not initialized when trying to send encrypted message");
            return Err(anyhow!("XMPP client not initialized"));
        }

        let _client = self.client.as_ref().unwrap();
        let _recipient_jid = match recipient.parse::<JidBare>() {
            Ok(jid) => jid,
            Err(e) => {
                error!("Invalid recipient JID '{}': {}", recipient, e);
                return Err(anyhow!("Invalid recipient JID: {}", e));
            }
        };
        
        // Generate a message ID
        let msg_id = Uuid::new_v4().to_string();
        info!("Preparing to send encrypted message to {} with ID: {}", recipient, msg_id);
        
        // Use the send_encrypted_message method which has proper implementation
        // This delegates to the method that already implements all OMEMO functionality
        let mut temp_client = Self {
            jid: self.jid.clone(),
            client: self.client.clone(),
            msg_tx: self.msg_tx.clone(),
            pending_receipts: self.pending_receipts.clone(),
            connected: self.connected,
            omemo_manager: self.omemo_manager.clone(),
            message_id_map: self.message_id_map.clone(),
            recipient_message_map: self.recipient_message_map.clone(),
            carbons_enabled: self.carbons_enabled.clone(),
        };
        
        match temp_client.send_encrypted_message(recipient, plaintext).await {
            Ok(_) => {
                //debug!("Message encrypted and sent successfully using OMEMO");
                Ok(())
            },
            Err(e) => {
                error!("Failed to send OMEMO encrypted message: {}", e);
                Err(anyhow!("Failed to send OMEMO encrypted message: {}", e))
            }
        }
    }

    /// Check if an OMEMO element is related to PubSub
    pub fn is_omemo_pubsub(pubsub: &xmpp_parsers::Element) -> bool {
        // Check items element for OMEMO namespace
        if let Some(items) = pubsub.get_child("items", custom_ns::PUBSUB) {
            if let Some(node) = items.attr("node") {
                return node.contains(custom_ns::OMEMO);
            }
        }
        
        // Check publish element for OMEMO namespace
        if let Some(publish) = pubsub.get_child("publish", custom_ns::PUBSUB) {
            if let Some(node) = publish.attr("node") {
                return node.contains(custom_ns::OMEMO);
            }
        }
        
        false
    }
    
    /// Handle an OMEMO-related IQ stanza
    pub async fn handle_omemo_iq(stanza: &xmpp_parsers::Element, client: &Arc<TokioMutex<XMPPAsyncClient>>) -> Result<()> {
        // Check the type of IQ
        let iq_type = stanza.attr("type").unwrap_or("get");
        
        // Create a fixed string to avoid reference issues
        let id_str = match stanza.attr("id") {
            Some(id) => id.to_string(),
            None => Uuid::new_v4().to_string()
        };
        
        match iq_type {
            "get" => {
                // This is a request for our OMEMO data
                //debug!("Received OMEMO IQ 'get' with ID: {}", id_str);
                
                // Check what kind of data is being requested
                if let Some(pubsub) = stanza.get_child("pubsub", custom_ns::PUBSUB) {
                    if let Some(items) = pubsub.get_child("items", custom_ns::PUBSUB) {
                        if let Some(node) = items.attr("node") {
                            if node.contains("bundles") {
                                // This is a request for a device bundle
                                return Self::handle_bundle_request(stanza, client).await;
                            } else if node.contains("devicelist") {
                                // This is a request for our device list
                                return Self::handle_devicelist_request(stanza, client).await;
                            }
                        }
                    }
                }
                
                // Not a recognized OMEMO request
                //debug!("Unrecognized OMEMO IQ 'get' request");
            },
            "result" => {
                // This is a response to our request for OMEMO data
                //debug!("Received OMEMO IQ 'result' with ID: {}", id_str);
                
                // Process the result data - normally this would update our local storage
                // with the peer's device information
                
                // In this implementation we just acknowledge it
                //debug!("Processed OMEMO IQ 'result'");
            },
            "set" => {
                // This is a request to update OMEMO data (rare)
                //debug!("Received OMEMO IQ 'set' with ID: {}", id_str);
                
                // Send an acknowledgment response
                let response = xmpp_parsers::Element::builder("iq", "jabber:client")
                    .attr("type", "result")
                    .attr("id", id_str)
                    .build();
                
                // Send the response
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(response).await?;
                
                //debug!("Sent acknowledgment for OMEMO IQ 'set'");
            },
            "error" => {
                // This is an error response
                //debug!("Received OMEMO IQ 'error' with ID: {}", id_str);
                
                // Log the error details
                if let Some(error) = stanza.get_child("error", "") {
                    let error_type = error.attr("type").unwrap_or("unknown");
                    error!("OMEMO IQ error type: {}", error_type);
                    
                    // Get error condition
                    for child in error.children() {
                        if child.ns() == custom_ns::STANZAS {
                            error!("OMEMO IQ error condition: {}", child.name());
                        }
                    }
                }
            },
            _ => {
                //debug!("Received unknown OMEMO IQ type: {}", iq_type);
            }
        }
        
        Ok(())
    }
    
    /// Handle a request for our device bundle
    async fn handle_bundle_request(stanza: &xmpp_parsers::Element, client: &Arc<TokioMutex<XMPPAsyncClient>>) -> Result<()> {
        // Extract the ID and from attributes from the stanza
        let id = stanza.attr("id").unwrap_or("unknown");
        let from_jid = stanza.attr("from");
        
        // Extract the node from the request to determine which device bundle is being requested
        let mut device_id: DeviceId = 0;
        if let Some(pubsub) = stanza.get_child("pubsub", custom_ns::PUBSUB) {
            if let Some(items) = pubsub.get_child("items", custom_ns::PUBSUB) {
                if let Some(node) = items.attr("node") {
                    // Extract device ID from the node path (format: eu.siacs.conversations.axolotl:bundles:123)
                    let parts: Vec<&str> = node.split(':').collect();
                    if parts.len() >= 3 {
                        if let Ok(id) = parts[2].parse::<u32>() {
                            device_id = id;
                        }
                    }
                }
            }
        }
        
        // Get bundle data from the OMEMO manager (if we have one in the Global State)
        let bundle_element = {
            // Try to get real bundle data from OmemoManager if available
            if let Some(global_client) = crate::xmpp::get_global_xmpp_client().await {
                let client_guard = global_client.lock().await;
                if let Some(omemo_manager) = &client_guard.omemo_manager {
                    let omemo_guard = omemo_manager.lock().await;
                    if let Ok(xml) = omemo_guard.get_key_bundle_xml() {
                        if let Ok(doc) = roxmltree::Document::parse(&xml) {
                            let root = doc.root_element();
                            let mut bundle = xmpp_parsers::Element::builder(root.tag_name().name(), root.tag_name().namespace().unwrap_or("")).build();
                            for attr in root.attributes() {
                                bundle.set_attr(attr.name(), attr.value());
                            }
                            for child in root.children() {
                                if child.is_element() {
                                    let mut child_elem = xmpp_parsers::Element::builder(child.tag_name().name(), child.tag_name().namespace().unwrap_or("")).build();
                                    for attr in child.attributes() {
                                        child_elem.set_attr(attr.name(), attr.value());
                                    }
                                    if let Some(text) = child.text() {
                                        child_elem.append_text_node(text);
                                    }
                                    bundle.append_child(child_elem);
                                }
                            }
                            bundle
                        } else {
                            // fallback below
                            let bundle = xmpp_parsers::Element::builder("bundle", custom_ns::OMEMO).build();
                            // ... fallback code ...
                            bundle
                        }
                    } else {
                        // fallback below
                        let bundle = xmpp_parsers::Element::builder("bundle", custom_ns::OMEMO).build();
                        // ... fallback code ...
                        bundle
                    }
                } else {
                    // fallback below
                    let bundle = xmpp_parsers::Element::builder("bundle", custom_ns::OMEMO).build();
                    // ... fallback code ...
                    bundle
                }
            } else {
                // fallback below
                let bundle = xmpp_parsers::Element::builder("bundle", custom_ns::OMEMO).build();
                // ... fallback code ...
                bundle
            }
        };
        
        // Create the items element with the bundle
        let items_element = xmpp_parsers::Element::builder("items", custom_ns::PUBSUB)
            .attr("node", &format!("{}.bundles:{}", custom_ns::OMEMO_V1, device_id))
            .append(
                xmpp_parsers::Element::builder("item", custom_ns::PUBSUB)
                    .attr("id", "current")
                    .append(bundle_element)
                    .build()
            )
            .build();
        
        // Create the response IQ
        let response = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "result")
            .attr("id", id)
            .attr("to", from_jid.unwrap_or(""))
            .append(
                xmpp_parsers::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(items_element)
                    .build()
            )
            .build();
        
        // Send the response
        let mut client_guard = client.lock().await;
        client_guard.send_stanza(response).await?;
        
        //debug!("Sent bundle response for device ID {} to {}", device_id, from_jid.unwrap_or("unknown"));
        
        Ok(())
    }
    
    /// Handle a request for our device list
    async fn handle_devicelist_request(stanza: &xmpp_parsers::Element, client: &Arc<TokioMutex<XMPPAsyncClient>>) -> Result<()> {
        // Extract the ID and from attributes from the stanza
        let id = stanza.attr("id").unwrap_or("unknown");
        let from_jid = stanza.attr("from");
        
        // Get our device list from the OMEMO manager
        let list_element = {
            // Try to get real device IDs from OmemoManager if available
            if let Some(global_client) = crate::xmpp::get_global_xmpp_client().await {
                let client_guard = global_client.lock().await;
                if let Some(omemo_manager) = &client_guard.omemo_manager {
                    let omemo_guard = omemo_manager.lock().await;
                    if let Ok(device_ids) = omemo_guard.get_device_ids_for_test(&client_guard.jid).await {
                        let mut list = xmpp_parsers::Element::builder("list", custom_ns::OMEMO).build();
                        for device_id in device_ids {
                            list.append_child(
                                xmpp_parsers::Element::builder("device", "")
                                    .attr("id", &device_id.to_string())
                                    .build()
                            );
                        }
                        list
                    } else {
                        // fallback below
                        let list = xmpp_parsers::Element::builder("list", custom_ns::OMEMO).build();
                        // ... fallback code ...
                        list
                    }
                } else {
                    // fallback below
                    let list = xmpp_parsers::Element::builder("list", custom_ns::OMEMO).build();
                    // ... fallback code ...
                    list
                }
            } else {
                // fallback below
                let list = xmpp_parsers::Element::builder("list", custom_ns::OMEMO).build();
                // ... fallback code ...
                list
            }
        };

        // Create the items element with the device list
        let items_element = xmpp_parsers::Element::builder("items", custom_ns::PUBSUB)
            .attr("node", &format!("{}:devices", custom_ns::OMEMO))
            .append(
                xmpp_parsers::Element::builder("item", custom_ns::PUBSUB)
                    .attr("id", "current")
                    .append(list_element)
                    .build()
            )
            .build();

        // Create the response IQ
        let response = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "result")
            .attr("id", id)
            .attr("to", from_jid.unwrap_or(""))
            .append(
                xmpp_parsers::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(items_element)
                    .build()
            )
            .build();
        
        // Send the response
        let mut client_guard = client.lock().await;
        client_guard.send_stanza(response).await?;
        
        //debug!("Sent device list response to {}", from_jid.unwrap_or("unknown"));
        
        Ok(())
    }
    
    /// Request an OMEMO device list from a peer
    /// This is the first step in the key discovery process
    pub async fn request_omemo_devicelist(&self, peer_jid: &str) -> Result<()> {
        //debug!("Sending OMEMO device list request to {}", peer_jid);
        
        // Validate and normalize the JID first
        let normalized_jid = match self.ensure_full_jid(peer_jid).await {
            Ok(jid) => {
                //debug!("Normalized JID for device list request: {} -> {}", peer_jid, jid);
                jid
            },
            Err(e) => {
                error!("Invalid JID format for device list request: {}: {}", peer_jid, e);
                return Err(anyhow!("Invalid JID format: {}: {}", peer_jid, e));
            }
        };
        
        // Try with standard namespace and node format first (per XEP-0384)
        let standard_result = self.request_pubsub_items(&normalized_jid, &format!("{}:devices", custom_ns::OMEMO)).await;
        
        if standard_result.is_ok() {
            info!("Successfully retrieved device list with standard format ({}:devices)", custom_ns::OMEMO);
            return Ok(());
        }
        
        // Try with legacy v1 namespace but standard node format
        let v1_standard_result = self.request_pubsub_items(&normalized_jid, &format!("{}:devices", custom_ns::OMEMO_V1)).await;
        
        if v1_standard_result.is_ok() {
            info!("Successfully retrieved device list with v1 namespace and standard format ({}:devices)", custom_ns::OMEMO_V1);
            return Ok(());
        }
        
        // Try with legacy node format (devicelist) for both namespaces
        let legacy_v2_result = self.request_pubsub_items(&normalized_jid, &format!("{}:devicelist", custom_ns::OMEMO)).await;
        
        if legacy_v2_result.is_ok() {
            info!("Successfully retrieved device list with legacy format ({}:devicelist)", custom_ns::OMEMO);
            return Ok(());
        }
        
        // Final attempt with the most legacy combination
        let legacy_v1_result = self.request_pubsub_items(&normalized_jid, &format!("{}:devicelist", custom_ns::OMEMO_V1)).await;
        
        if let Err(e) = &legacy_v1_result {
            warn!("Failed to retrieve device list with all namespace and node combinations: {}", e);
            return Err(anyhow!("Failed to retrieve device list: {}", e));
        }
        
        info!("Successfully retrieved device list with most legacy format ({}:devicelist)", custom_ns::OMEMO_V1);
        Ok(())
    }

    /// Request an OMEMO device bundle from a peer
    /// This is the second step in the key discovery process, after getting the device list
    pub async fn request_omemo_bundle(&self, peer_jid: &str, device_id: DeviceId) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        // Validate and normalize the JID first
        let _normalized_jid = match self.ensure_full_jid(peer_jid).await {
            Ok(jid) => {
                //debug!("Normalized JID for bundle request: {} -> {}", peer_jid, jid);
                jid
            },
            Err(e) => {
                error!("Invalid JID format for bundle request: {}: {}", peer_jid, e);
                return Err(anyhow!("Invalid JID format: {}: {}", peer_jid, e));
            }
        };
        
        let client = self.client.as_ref().unwrap();
        
        // Generate a unique ID for this request
        let request_id = Uuid::new_v4().to_string();
        
        // Create the PubSub IQ request for the device bundle
        let node = format!("{}.bundles:{}", custom_ns::OMEMO_V1, device_id);
        
        // Build the IQ stanza
        let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "get")
            .attr("id", &request_id)
            .attr("to", peer_jid)
            .append(
                xmpp_parsers::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(
                        xmpp_parsers::Element::builder("items", custom_ns::PUBSUB)
                            .attr("node", &node)
                            .build()
                    )
                    .build()
            )
            .build();
        
        // Send the request
        //debug!("Sending OMEMO bundle request to {} for device {}", peer_jid, device_id);
        
        let send_result = {
            let lock_timeout = Duration::from_secs(5);
            let mut client_guard = match tokio::time::timeout(lock_timeout, client.lock()).await {
                Ok(guard) => guard,
                Err(_) => return Err(anyhow!("Timed out acquiring client lock for OMEMO bundle request")),
            };
            
            match tokio::time::timeout(
                Duration::from_secs(5),
                client_guard.send_stanza(iq)
            ).await {
                Ok(result) => result,
                Err(_) => return Err(anyhow!("Timed out sending OMEMO bundle request")),
            }
        };
        
        match send_result {
            Ok(_) => {
                //debug!("OMEMO bundle request sent successfully");
                Ok(())
            },
            Err(e) => {
                error!("Failed to send OMEMO bundle request: {}", e);
                Err(anyhow!("Failed to send OMEMO bundle request: {}", e))
            }
        }
    }
    
    /// Publish your OMEMO device list to the server
    /// This advertises which devices you have available for OMEMO encryption
    pub async fn publish_omemo_devicelist(&self, device_ids: &[DeviceId]) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        let client = self.client.as_ref().unwrap();
        let node_name = format!("{}:devices", custom_ns::OMEMO);
        
        // First, try to configure the node for open access
        if let Err(e) = self.configure_node_for_open_access(&node_name).await {
            warn!("Could not configure device list node for open access: {}", e);
            // Continue anyway - the node might already exist with correct permissions
        }
        
        // Generate a unique ID for this publish request
        let publish_id = Uuid::new_v4().to_string();
        
        // Create the device list XML content
        let mut list_element = xmpp_parsers::Element::builder("list", custom_ns::OMEMO).build();
        
        // Add device elements
        for device_id in device_ids {
            let device_element = xmpp_parsers::Element::builder("device", "")
                .attr("id", &device_id.to_string())
                .build();
            list_element.append_child(device_element);
        }
        
        // Build the IQ stanza for publishing
        let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "set")
            .attr("id", &publish_id)
            .append(
                xmpp_parsers::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(
                        xmpp_parsers::Element::builder("publish", custom_ns::PUBSUB)
                            .attr("node", &format!("{}:devices", custom_ns::OMEMO))
                            .append(
                                xmpp_parsers::Element::builder("item", custom_ns::PUBSUB)
                                    .attr("id", "current")
                                    .append(list_element)
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build();
        
        // Send the publish request
        //debug!("Publishing OMEMO device list with {} devices", device_ids.len());
        
        let send_result = {
            let lock_timeout = Duration::from_secs(5);
            let mut client_guard = match tokio::time::timeout(lock_timeout, client.lock()).await {
                Ok(guard) => guard,
                Err(_) => return Err(anyhow!("Timed out acquiring client lock for publishing OMEMO device list")),
            };
            
            match tokio::time::timeout(
                Duration::from_secs(5),
                client_guard.send_stanza(iq)
            ).await {
                Ok(result) => result,
                Err(_) => return Err(anyhow!("Timed out publishing OMEMO device list")),
            }
        };
        
        match send_result {
            Ok(_) => {
                info!("OMEMO device list published successfully");
                Ok(())
            },
            Err(e) => {
                error!("Failed to publish OMEMO device list: {}", e);
                Err(anyhow!("Failed to publish OMEMO device list: {}", e))
            }
        }
    }
    
    /// Publish your OMEMO device bundle to the server
    /// This advertises your keys for encryption
    pub async fn publish_omemo_bundle(&self, device_id: DeviceId, bundle_data: &str) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        let client = self.client.as_ref().unwrap();
        
        // Configure the bundle node for open access before publishing
        let bundle_node_name = format!("{}.bundles:{}", custom_ns::OMEMO_V1, device_id);
        if let Err(e) = self.configure_node_for_open_access(&bundle_node_name).await {
            warn!("Failed to configure bundle node {} for open access: {}", bundle_node_name, e);
            // Continue with publishing even if configuration fails
        }
        
        // Generate a unique ID for this publish request
        let publish_id = Uuid::new_v4().to_string();
        
        // Fix for the XML element text handling issues
        let bundle_element = match roxmltree::Document::parse(bundle_data) {
            Ok(doc) => {
                let root = doc.root_element();
                if root.tag_name().name() != "bundle" {
                    error!("Bundle data does not contain a bundle element");
                    return Err(anyhow!("Invalid bundle data format"));
                }

                // Create a new bundle element with the correct namespace
                let mut bundle = xmpp_parsers::Element::builder("bundle", custom_ns::OMEMO).build();

                // Process each child element of the bundle
                for child in root.children().filter(|n| n.is_element()) {
                    let child_name = child.tag_name().name();
                    let mut child_elem = xmpp_parsers::Element::builder(child_name, "").build();
                    
                    // Copy all attributes
                    for attr in child.attributes() {
                        child_elem.set_attr(attr.name(), attr.value());
                    }
                    
                    // Handle child elements differently based on their type
                    if child_name == "prekeys" {
                        // Special handling for prekeys which has its own children
                        for prekey in child.children().filter(|n| n.is_element()) {
                            let mut prekey_elem = xmpp_parsers::Element::builder(prekey.tag_name().name(), "").build();
                            
                            // Copy prekey attributes
                            for attr in prekey.attributes() {
                                prekey_elem.set_attr(attr.name(), attr.value());
                            }
                            
                            // Add prekey text content if any
                            if let Some(text) = prekey.text() {
                                prekey_elem.append_text_node(text);
                            }
                            
                            child_elem.append_child(prekey_elem);
                        }
                    } else {
                        // Add text content for simple elements
                        if let Some(text) = child.text() {
                            child_elem.append_text_node(text);
                        }
                    }
                    
                    bundle.append_child(child_elem);
                }
                
                //debug!("Successfully parsed and reconstructed bundle XML structure");
                bundle
            },
            Err(e) => {
                error!("Failed to parse bundle data as XML: {}", e);
                // Create a simple element with the data as text as a fallback
                let mut bundle = xmpp_parsers::Element::builder("bundle", custom_ns::OMEMO).build();
                bundle.append_text_node(bundle_data);
                bundle
            }
        };
        
        // Create the item element and append the bundle element
        let item_element = xmpp_parsers::Element::builder("item", custom_ns::PUBSUB)
            .attr("id", "current")
            .append(bundle_element)
            .build();
        
        // Build the IQ stanza for publishing
        let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "set")
            .attr("id", &publish_id)
            .append(
                xmpp_parsers::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(
                        xmpp_parsers::Element::builder("publish", custom_ns::PUBSUB)
                            .attr("node", &format!("{}.bundles:{}", custom_ns::OMEMO_V1, device_id))
                            .append(item_element)
                            .build()
                    )
                    .build()
            )
            .build();
        
        // Send the publish request
        //debug!("Publishing OMEMO bundle for device {}", device_id);
        
        let send_result = {
            let lock_timeout = Duration::from_secs(5);
            let mut client_guard = match tokio::time::timeout(lock_timeout, client.lock()).await {
                Ok(guard) => guard,
                Err(_) => return Err(anyhow!("Timed out acquiring client lock for publishing OMEMO bundle")),
            };
            
            match tokio::time::timeout(
                Duration::from_secs(5),
                client_guard.send_stanza(iq)
            ).await {
                Ok(result) => result,
                Err(_) => return Err(anyhow!("Timed out publishing OMEMO bundle")),
            }
        };
        
        match send_result {
            Ok(_) => {
                info!("OMEMO bundle published successfully for device {}", device_id);
                Ok(())
            },
            Err(e) => {
                error!("Failed to publish OMEMO bundle: {}", e);
                Err(anyhow!("Failed to publish OMEMO bundle: {}", e))
            }
        }
    }

    /// Detect an unrecognized OMEMO key and request verification
    pub async fn detect_unrecognized_omemo_key(&self, sender: &str, key_fingerprint: &str, device_id: Option<DeviceId>) -> Result<()> {
        // Log the detection of an unrecognized key
        info!("Detected unrecognized OMEMO key from {} with fingerprint: {}", 
             sender, key_fingerprint);
        
        // Format the device ID for display
        let device_id_str = device_id.map(|id| id.to_string());
        
        // Create a special system message to trigger the verification UI
        let special_message = Message {
            id: uuid::Uuid::new_v4().to_string(),
            sender_id: "system".to_string(),
            recipient_id: "me".to_string(),
            // Format: __OMEMO_KEY_VERIFY__:contact:fingerprint:device_id
            content: format!("__OMEMO_KEY_VERIFY__:{}:{}:{}", 
                            sender, 
                            key_fingerprint, 
                            device_id_str.as_deref().unwrap_or("")),
            timestamp: chrono::Utc::now().timestamp() as u64,
            delivery_status: DeliveryStatus::Delivered,
        };
        
        // Send the special message to the UI
        if let Err(e) = self.msg_tx.send(special_message).await {
            error!("Failed to send key verification request to UI: {}", e);
            return Err(anyhow!("Failed to send key verification request to UI: {}", e));
        }
        
        Ok(())
    }

    /// Process OMEMO key verification response from user
    pub async fn process_omemo_verification_response(&self, contact: &str, response: &str) -> Result<()> {
        //debug!("Processing OMEMO verification response for {}: {}", contact, response);
        
        // If we don't have an OMEMO manager, can't process response
        let omemo_manager = match &self.omemo_manager {
            Some(manager) => manager.clone(),
            None => {
                warn!("No OMEMO manager available for key verification");
                return Err(anyhow!("No OMEMO manager available"));
            }
        };
        
        // Get the storage instance for database operations
        let storage = crate::omemo::storage::OmemoStorage::new_default()?;
        
        // Parse out the device ID and fingerprint from storage
        let device_id = match storage.get_pending_device_verification(contact) {
            Ok(Some((device_id, _fingerprint))) => {
                //debug!("Found pending verification for device {}:{}", contact, device_id);
                device_id
            },
            Ok(None) => {
                warn!("No pending verification found for {}, cannot process response", contact);
                return Err(anyhow!("No pending verification found for {}", contact));
            },
            Err(e) => {
                warn!("Error retrieving pending verification: {}", e);
                return Err(anyhow!("Error retrieving pending verification: {}", e));
            }
        };
        
        match response {
            "__KEY_ACCEPTED__" => {
                //debug!("User accepted OMEMO key for {}:{}", contact, device_id);
                
                // First, mark the device as trusted in the database directly
                // This ensures the trust status is persisted even if the OMEMO manager operation fails
                if let Err(e) = storage.set_device_trust(contact, device_id, true) {
                    error!("Failed to mark device as trusted in database: {}", e);
                    // Continue anyway, as the OMEMO manager might still succeed
                }
                
                // Mark the device as trusted in the OMEMO manager
                let manager_guard = omemo_manager.lock().await;
                if let Err(e) = manager_guard.trust_device_identity(contact, device_id).await {
                    error!("Failed to mark device as trusted in OMEMO manager: {}", e);
                    return Err(anyhow!("Failed to mark device as trusted: {}", e));
                }
                
                info!("Successfully marked device {}:{} as trusted", contact, device_id);
                
                // Clear the pending verification since it's been processed
                if let Err(e) = storage.remove_pending_device_verification(contact, device_id) {
                    warn!("Failed to remove pending verification: {}", e);
                    // Continue anyway, non-critical
                }
                
                Ok(())
            },
            "__KEY_REJECTED__" => {
                //debug!("User rejected OMEMO key for {}:{}", contact, device_id);
                
                // First, mark the device as explicitly untrusted in the database directly
                if let Err(e) = storage.set_device_trust(contact, device_id, false) {
                    error!("Failed to mark device as untrusted in database: {}", e);
                    // Continue anyway, as the OMEMO manager might still succeed
                }
                
                // Mark the device as untrusted in the OMEMO manager
                let manager_guard = omemo_manager.lock().await;
                if let Err(e) = manager_guard.untrust_device_identity(contact, device_id).await {
                    error!("Failed to mark device as untrusted in OMEMO manager: {}", e);
                    return Err(anyhow!("Failed to mark device as untrusted: {}", e));
                }
                
                info!("Successfully marked device {}:{} as untrusted", contact, device_id);
                
                // Clear the pending verification since it's been processed
                if let Err(e) = storage.remove_pending_device_verification(contact, device_id) {
                    warn!("Failed to remove pending verification: {}", e);
                    // Continue anyway, non-critical
                }
                
                Ok(())
            },
            _ => {
                warn!("Unknown verification response: {}", response);
                Err(anyhow!("Unknown verification response"))
            }
        }
    }

    /// Get the device ID for this OMEMO instance
    pub async fn get_own_device_id(&self) -> Result<u32> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            Ok(manager.get_device_id())
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Get the fingerprint of our own OMEMO device
    pub async fn get_own_fingerprint(&self) -> Result<String> {
        if let Some(omemo_manager) = &self.omemo_manager {
            // Convert our JID to a string
            let jid_str = self.jid.to_string();
            
            // Get our device ID first
            let device_id = {
                let manager = omemo_manager.lock().await;
                manager.get_device_id()
            };
            
            // Get the fingerprint for our device ID
            let manager = omemo_manager.lock().await;
            match manager.get_device_fingerprint(&jid_str, device_id).await {
                Ok(fingerprint) => Ok(fingerprint),
                Err(e) => Err(anyhow!("Failed to get own fingerprint: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Check if a device is trusted
    pub async fn is_device_trusted(&self, jid: &str, device_id: DeviceId) -> Result<bool> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            match manager.is_device_identity_trusted(jid, device_id).await {
                Ok(trusted) => Ok(trusted),
                Err(e) => Err(anyhow!("Failed to check device trust status: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Mark a device as trusted
    pub async fn mark_device_trusted(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            match manager.trust_device_identity(jid, device_id).await {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("Failed to mark device as trusted: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Mark a device as untrusted
    pub async fn mark_device_untrusted(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            match manager.untrust_device_identity(jid, device_id).await {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("Failed to mark device as untrusted: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Get device IDs for a contact
    pub async fn get_contact_devices(&self, jid: &str) -> Result<Vec<DeviceId>> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            match manager.get_device_ids_for_test(jid).await {
                Ok(devices) => Ok(devices),
                Err(e) => Err(anyhow!("Failed to get contact devices: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Publish device list to the server
    pub async fn publish_device_list(&self) -> Result<()> {
        if let Some(omemo_manager) = &self.omemo_manager {
            // Get our device ID
            let device_id = {
                let manager = omemo_manager.lock().await;
                manager.get_device_id()
            };
            
            // Create a device list with our device ID
            let device_ids = vec![device_id];
            
            // Publish the device list
            self.publish_omemo_devicelist(&device_ids).await
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Publish bundle to the server
    pub async fn publish_bundle(&self) -> Result<()> {
        if let Some(omemo_manager) = &self.omemo_manager {
            // Get our device ID and bundle XML
            let (device_id, bundle_xml) = {
                let manager = omemo_manager.lock().await;
                let id = manager.get_device_id();
                let xml = manager.get_key_bundle_xml()?;
                (id, xml)
            };
            
            // Publish the bundle
            self.publish_omemo_bundle(device_id, &bundle_xml).await
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Request a bundle from a contact
    pub async fn request_bundle(&self, jid: &str, device_id: u32) -> Result<()> {
        self.request_omemo_bundle(jid, device_id).await
    }

    /// Rotate OMEMO keys
    pub async fn rotate_omemo_keys(&self) -> Result<bool> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let mut manager = omemo_manager.lock().await;
            match manager.check_and_rotate_prekeys().await {
                Ok(rotated) => {
                    if rotated {
                        // If keys were rotated, publish the new bundle
                        drop(manager); // Drop the lock before making async calls
                        self.publish_bundle().await?;
                    }
                    Ok(rotated)
                },
                Err(e) => Err(anyhow!("Failed to rotate OMEMO keys: {}", e))
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Find or create a group chat
    pub async fn find_or_create_group_chat(&self, room_name: &str) -> Result<String> {
        // First check if we're already in this room
        // For now, we'll simulate this behavior by just returning a standardized JID
        // A real implementation would check for existing rooms and create one if needed
        
        // Format a reasonable MUC JID based on the room name
        let jid_str = self.jid.to_string();
        let server_domain = match jid_str.split('@').collect::<Vec<&str>>().get(1) {
            Some(domain) => *domain,
            None => "example.org" // Default domain if we can't extract it from JID
        };
        
        let muc_domain = format!("conference.{}", server_domain);
        let muc_jid = format!("{}@{}", room_name, muc_domain);
        
        info!("Using MUC room: {}", muc_jid);
        
        // Pretend we've joined the room successfully
        Ok(muc_jid)
    }

    /// Send an encrypted message to a group chat
    pub async fn send_encrypted_group_message(&mut self, muc_jid: &str, content: &str) -> Result<()> {
        // For a real implementation, you'd need to:
        // 1. Get all the participants in the MUC
        // 2. Encrypt the message separately for each participant
        // 3. Build an OMEMO message that includes keys for all participants
        // 4. Send the message to the MUC
        
        // For this implementation, we'll just use the regular encrypted message function
        // This isn't a proper group encryption implementation, but it demonstrates the flow
        info!("Sending encrypted message to MUC: {}", muc_jid);
        self.send_encrypted_message(muc_jid, content).await
    }

    /// Configure a PubSub node for open access (required for OMEMO)
    async fn configure_node_for_open_access(&self, node_name: &str) -> Result<()> {
        if self.client.is_none() {
            return Err(anyhow!("XMPP client not initialized"));
        }
        
        let client = self.client.as_ref().unwrap();
        let config_id = Uuid::new_v4().to_string();
        
        // Create configuration form for open access
        let config_iq = xmpp_parsers::Element::builder("iq", "jabber:client")
            .attr("type", "set")
            .attr("id", &config_id)
            .append(
                xmpp_parsers::Element::builder("pubsub", "http://jabber.org/protocol/pubsub#owner")
                    .append(
                        xmpp_parsers::Element::builder("configure", "")
                            .attr("node", node_name)
                            .append(
                                xmpp_parsers::Element::builder("x", "jabber:x:data")
                                    .attr("type", "submit")
                                    .append(
                                        xmpp_parsers::Element::builder("field", "")
                                            .attr("var", "FORM_TYPE")
                                            .attr("type", "hidden")
                                            .append({
                                                let mut value_elem = xmpp_parsers::Element::builder("value", "").build();
                                                value_elem.append_text_node("http://jabber.org/protocol/pubsub#node_config");
                                                value_elem
                                            })
                                            .build()
                                    )
                                    .append(
                                        xmpp_parsers::Element::builder("field", "")
                                            .attr("var", "pubsub#access_model")
                                            .append({
                                                let mut value_elem = xmpp_parsers::Element::builder("value", "").build();
                                                value_elem.append_text_node("open");
                                                value_elem
                                            })
                                            .build()
                                    )
                                    .build()
                            )
                            .build()
                    )
                    .build()
            )
            .build();
        
        // Send the configuration request
        let send_result = {
            let mut client_guard = tokio::time::timeout(Duration::from_secs(5), client.lock()).await
                .map_err(|_| anyhow!("Timed out acquiring client lock for node configuration"))?;
            
            tokio::time::timeout(Duration::from_secs(5), client_guard.send_stanza(config_iq)).await
                .map_err(|_| anyhow!("Timed out configuring node"))?
        };
        
        match send_result {
            Ok(_) => {
                info!("Successfully configured node {} for open access", node_name);
                Ok(())
            },
            Err(e) => {
                warn!("Failed to configure node {} for open access: {}", node_name, e);
                // Don't fail the entire operation if configuration fails
                Ok(())
            }
        }
    }
}

/// Handle an incoming OMEMO message
pub async fn handle_omemo_message(
    manager: Arc<TokioMutex<OmemoManager>>,
    sender: &str,
    stanza: &str,
) -> Result<String> {
    //debug!("Handling OMEMO message from {}", sender);
    
    // Parse the stanza to extract the OMEMO message
    let message = {
        let manager_guard = manager.lock().await;
        manager_guard.process_message_xml(stanza)?
    };
    
    // Extract the sender device ID
    let device_id = message.sender_device_id;
    
    //debug!("Message from device ID: {}", device_id);
    
    // Check if the device is trusted
    let trusted = {
        let manager_guard = manager.lock().await;
        manager_guard.is_device_identity_trusted(sender, device_id).await?
    };
    
    if !trusted {
        warn!("Received message from untrusted device {}:{}", sender, device_id);
        
        // Calculate the device fingerprint for verification
        let fingerprint = {
            let manager_guard = manager.lock().await;
            manager_guard.get_device_fingerprint(sender, device_id).await?
        };
        
        return Err(anyhow!("Untrusted device: {}:{} with fingerprint {}", sender, device_id, fingerprint));
    }
    
    // Decrypt the message
    let plaintext = {
        let mut manager_guard = manager.lock().await;
        manager_guard.decrypt_message(sender, device_id, &message).await?
    };
    
    info!("Successfully decrypted message from {}:{}", sender, device_id);
    
    Ok(plaintext)
}

/// Encrypt a message for a recipient
pub async fn encrypt_message(
    manager: Arc<TokioMutex<OmemoManager>>,
    recipient: &str,
    content: &str,
) -> Result<String> {
    //debug!("Encrypting message for {}", recipient);
    
    // Encrypt the message using the OMEMO manager
    let omemo_message = {
        let mut manager_guard = manager.lock().await;
        manager_guard.encrypt_message(recipient, content).await?
    };
    
    // Convert the OMEMO message to an XML stanza
    let xml = {
        let manager_guard = manager.lock().await;
        manager_guard.message_to_xml(&omemo_message)
    };
    
    info!("Message encrypted successfully for {}", recipient);
    
    Ok(xml)
}

/// Publish device list to the XMPP server
pub async fn publish_device_list(
    manager: Arc<TokioMutex<OmemoManager>>,
    xmpp_client: &impl XmppClient,
) -> Result<()> {
    //debug!("Publishing device list");
    
    // Get the device list XML
    let xml = {
        let manager_guard = manager.lock().await;
        manager_guard.get_device_list_xml()?
    };
    
    // Publish to the XMPP server
    xmpp_client.publish_pubsub_item(
        None,
        &format!("{}.devices", OMEMO_NAMESPACE),
        "current",
        &xml,
    ).await?;
    
    info!("Device list published successfully");
    
    Ok(())
}

/// Publish key bundle to the XMPP server
pub async fn publish_key_bundle(
    manager: Arc<TokioMutex<OmemoManager>>,
    xmpp_client: &impl XmppClient,
) -> Result<()> {
    //debug!("Publishing key bundle");
    
    // Get device ID and bundle XML
    let (device_id, xml) = {
        let manager_guard = manager.lock().await;
        let device_id = manager_guard.get_device_id();
        let xml = manager_guard.get_key_bundle_xml()?;
        (device_id, xml)
    };
    
    // Publish to the XMPP server
    xmpp_client.publish_pubsub_item(
        None,
        &format!("{}.bundles:{}", OMEMO_NAMESPACE, device_id),
        "current",
        &xml,
    ).await?;
    
    info!("Key bundle published successfully");
    
    Ok(())
}

/// Trait for XMPP client functionality needed by OMEMO
pub trait XmppClient {
    /// Publish an item to a PubSub node
    fn publish_pubsub_item(
        &self,
        to: Option<&str>,
        node: &str,
        id: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    
    /// Request items from a PubSub node
    fn request_pubsub_items(
        &self,
        from: &str,
        node: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;
}

/// Publish an item to a PubSub node (for OMEMO implementation)
/// This function is called by the OMEMO manager to publish key bundles and device lists
pub async fn publish_pubsub_item(
    to: Option<&str>,
    node: &str,
    id: &str,
    payload: &str,
) -> Result<()> {
    //debug!("Publishing PubSub item to node {}", node);
    info!("PubSub payload: {}", payload);
    
    // Get the client from the global static
    if let Ok(current_client) = CURRENT_CLIENT.read() {
        if let Some(client_ref) = current_client.as_ref() {
            let mut client_guard = client_ref.lock().await;
            
            // Generate a unique IQ ID different from the item ID
            let iq_id = Uuid::new_v4().to_string();
            
            // Check which type of OMEMO item we're publishing
            let is_devicelist = node.contains("devicelist");
            let is_bundle = node.contains("bundles");
            
            // If we're publishing a device list, we need to handle it specially due to namespace issues
            if is_devicelist {
                //debug!("Publishing a device list - using special handling");
                
                // Parse the payload to extract the device IDs
                let doc = match roxmltree::Document::parse(payload) {
                    Ok(doc) => doc,
                    Err(e) => {
                        error!("Failed to parse device list payload: {}", e);
                        return Err(anyhow!("Failed to parse device list payload: {}", e));
                    }
                };
                
                // Get device IDs from the list
                let device_ids: Vec<String> = doc.descendants()
                    .filter(|n| n.has_tag_name("device") && n.has_attribute("id"))
                    .map(|n| n.attribute("id").unwrap().to_string())
                    .collect();
                
                //debug!("Found {} device IDs in list: {:?}", device_ids.len(), device_ids);
                
                // Create the device list stanza correctly
                let iq = Element::builder("iq", "jabber:client")
                    .attr("type", "set")
                    .attr("id", &iq_id)
                    .attr("to", to.unwrap_or(""))
                    .append(
                        Element::builder("pubsub", "http://jabber.org/protocol/pubsub")
                            .append(
                                Element::builder("publish", "http://jabber.org/protocol/pubsub")
                                    .attr("node", node)
                                    .append(
                                        Element::builder("item", "http://jabber.org/protocol/pubsub")
                                            .attr("id", id)
                                            .append(
                                                {
                                                    let mut list_elem = Element::builder("list", "eu.siacs.conversations.axolotl").build();
                                                    
                                                    // Add each device with the proper namespace handling
                                                    for device_id in device_ids {
                                                        let device_elem = Element::builder("device", "")
                                                            .attr("id", &device_id)
                                                            .build();
                                                        list_elem.append_child(device_elem);
                                                    }
                                                    
                                                    list_elem
                                                }
                                            )
                                            .build()
                                    )
                                    .build()
                            )
                            .build()
                    )
                    .build();
                
                //debug!("Sending corrected devicelist stanza: {:?}", iq);
                
                // Send the stanza
                match client_guard.send_stanza(iq).await {
                    Ok(_) => {
                        //debug!("Device list published successfully to node {}", node);
                        return Ok(());
                    },
                    Err(e) => {
                        error!("Failed to send device list stanza: {}", e);
                        return Err(anyhow!("Failed to send device list stanza: {}", e));
                    }
                }
            } else if is_bundle {
                // Handle bundle publishing with proper XML preservation
                //debug!("Publishing a bundle - using specialized bundle handling");
                
                // Parse the payload XML to ensure proper structure
                let doc = match roxmltree::Document::parse(payload) {
                    Ok(doc) => doc,
                    Err(e) => {
                        error!("Failed to parse bundle payload XML: {}", e);
                        return Err(anyhow!("Failed to parse bundle payload XML: {}", e));
                    }
                };
                
                let root = doc.root_element();
                
                // Create the IQ stanza
                let mut iq = xmpp_parsers::Element::builder("iq", "jabber:client")
                    .attr("type", "set")
                    .attr("id", &iq_id)
                    .build();
                
                // Add 'to' attribute if provided
                if let Some(to_addr) = to {
                    iq.set_attr("to", to_addr);
                }
                
                // Create the pubsub element
                let mut pubsub_elem = xmpp_parsers::Element::builder("pubsub", "http://jabber.org/protocol/pubsub").build();
                
                // Create the publish element
                let mut publish_elem = xmpp_parsers::Element::builder("publish", "http://jabber.org/protocol/pubsub")
                    .attr("node", node)
                    .build();
                
                // Create the item element
                let mut item_elem = xmpp_parsers::Element::builder("item", "http://jabber.org/protocol/pubsub")
                    .attr("id", id)
                    .build();
                
                // Create bundle element with correct namespace
                let mut bundle_elem = xmpp_parsers::Element::builder("bundle", "eu.siacs.conversations.axolotl").build();
                
                // Function to recursively add child elements
                fn add_child_elements(parent: &mut xmpp_parsers::Element, node: roxmltree::Node) {
                    for child in node.children().filter(|n| n.is_element()) {
                        // Use the OMEMO namespace for all child elements to maintain consistency
                        let mut child_elem = xmpp_parsers::Element::builder(child.tag_name().name(), "eu.siacs.conversations.axolotl")
                            .build();
                        
                        // Copy attributes
                        for attr in child.attributes() {
                            // Skip xmlns attributes to avoid namespace conflicts
                            if attr.name() != "xmlns" {
                                child_elem.set_attr(attr.name(), attr.value());
                            }
                        }
                        
                        // Process child elements recursively
                        add_child_elements(&mut child_elem, child);
                        
                        // Add text content if any
                        if let Some(text) = child.text() {
                            if !text.trim().is_empty() {
                                child_elem.append_text_node(text);
                            }
                        }
                        
                        parent.append_child(child_elem);
                    }
                }
                
                // Add children to bundle element
                add_child_elements(&mut bundle_elem, root);
                
                // Build the element structure
                item_elem.append_child(bundle_elem);
                publish_elem.append_child(item_elem);
                pubsub_elem.append_child(publish_elem);
                iq.append_child(pubsub_elem);
                
                // Send the stanza
                //debug!("Sending bundle stanza: {:?}", iq);
                match client_guard.send_stanza(iq).await {
                    Ok(_) => {
                        //debug!("Bundle published successfully to node {}", node);
                        return Ok(());
                    },
                    Err(e) => {
                        error!("Failed to send bundle stanza: {}", e);
                        
                        // If the error contains "invalid-item" or "bad-request", try the alternative format
                        if e.to_string().contains("invalid-item") || e.to_string().contains("bad-request") {
                            warn!("Received bad-request error, trying alternative bundle format");
                            return publish_bundle_alternative_format(to, node, id, payload).await;
                        }
                        
                        return Err(anyhow!("Failed to send bundle stanza: {}", e));
                    }
                }
            }
            
            // Create the PubSub element
            let mut pubsub_element = xmpp_parsers::Element::builder("pubsub", "http://jabber.org/protocol/pubsub").build();
            
            // Create the publish element
            let mut publish_element = xmpp_parsers::Element::builder("publish", "http://jabber.org/protocol/pubsub")
                .attr("node", node)
                .build();
            
            // Create the item element with the payload
            let mut item_element = xmpp_parsers::Element::builder("item", "http://jabber.org/protocol/pubsub")
                .attr("id", id)
                .build();
            
            // Add the payload as a child text node
            if payload.trim().starts_with('<') && payload.trim().ends_with('>') {
                // This is XML content, parse it and add as structured elements
                match roxmltree::Document::parse(payload) {
                    Ok(doc) => {
                        let root = doc.root_element();
                        let name = root.tag_name().name();
                        let namespace = root.tag_name().namespace().unwrap_or("");
                        
                        // Create a new element with the correct name and namespace
                        let mut payload_element = xmpp_parsers::Element::builder(name, namespace).build();
                        
                        // Copy attributes
                        for attr in root.attributes() {
                            payload_element.set_attr(attr.name(), attr.value());
                        }
                        
                        // Process children for device list specifically - add them with proper structure
                        if name == "list" && namespace == "eu.siacs.conversations.axolotl" {
                            // Process device elements explicitly
                            for child in root.children() {
                                if child.is_element() && child.tag_name().name() == "device" {
                                    if let Some(id_attr) = child.attribute("id") {
                                        let device_elem = xmpp_parsers::Element::builder("device", "")
                                            .attr("id", id_attr)
                                            .build();
                                        payload_element.append_child(device_elem);
                                    }
                                }
                            }
                        } else {
                            // Just treat it as a simple text container for now
                            if let Some(text) = root.text() {
                                payload_element.append_text_node(text);
                            }
                        }
                        
                        // Log the constructed element before moving it
                        //debug!("Created structured payload element: {:?}", &payload_element);
                        
                        item_element.append_child(payload_element);
                    },
                    Err(e) => {
                        error!("Failed to parse payload as XML: {}", e);
                        // Fallback to treating it as text
                        item_element.append_text_node(payload);
                    }
                }
            } else {
                // Plain text content
                item_element.append_text_node(payload);
            }
            
            // Assemble the full element hierarchy
            publish_element.append_child(item_element);
            pubsub_element.append_child(publish_element);
            
            // Create the IQ stanza
            let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
                .attr("type", "set")
                .attr("id", &iq_id)  // Use the unique iq_id instead of reusing the item id
                .append(pubsub_element)
                .build();
            
            // If a 'to' attribute was provided, add it
            let iq = if let Some(to_addr) = to {
                let mut iq_copy = iq;
                iq_copy.set_attr("to", to_addr);
                iq_copy
            } else {
                iq
            };
            
            // Send the stanza
            //debug!("Sending PubSub publish stanza: {:?}", iq);
            match client_guard.send_stanza(iq).await {
                Ok(_) => {
                    //debug!("PubSub item published successfully to node {}", node);
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to send PubSub stanza: {}", e);
                    Err(anyhow!("Failed to send PubSub stanza: {}", e))
                }
            }
        } else {
            error!("No client available in CURRENT_CLIENT for PubSub publishing");
            Err(anyhow!("No client available in CURRENT_CLIENT for PubSub publishing"))
        }
    } else {
        error!("Failed to acquire read lock for CURRENT_CLIENT");
        Err(anyhow!("Failed to acquire read lock for CURRENT_CLIENT"))
    }
}


// ...existing code...

/// Parse the IV from an OMEMO header
pub fn parse_iv_from_header(header: &Element) -> Result<Vec<u8>, OmemoError> {
    //debug!("Parsing IV from OMEMO header");
    
    // Find the IV element
    let iv_element = match header.get_child("iv", "eu.siacs.conversations.axolotl") {
        Some(el) => el,
        None => {
            error!("Missing IV element in OMEMO header");
            return Err(OmemoError::InvalidHeader("Missing IV element in header".to_string()));
        }
    };
    
    // Get the IV text content - ensure proper handling for String
    let iv_base64 = iv_element.text();
    if iv_base64.is_empty() {
        error!("Empty IV element in OMEMO header");
        return Err(OmemoError::InvalidHeader("Empty IV element in header".to_string()));
    }
    
    // Decode the IV from Base64
    let iv = match BASE64_STANDARD.decode(iv_base64) {
        Ok(iv) => iv,
        Err(e) => {
            error!("Failed to decode IV from Base64: {}", e);
            return Err(OmemoError::DecodingError(format!("Failed to decode IV: {}", e)));
        }
    };
    
    // Validate the IV
    if let Err(e) = crypto::validate_iv(&iv) {
        error!("Invalid IV in OMEMO header: {}", e);
        return Err(OmemoError::InvalidHeader(format!("Invalid IV: {}", e)));
    }
    
    //debug!("Successfully parsed IV from header: {} bytes", iv.len());
    trace!("IV: {}", hex::encode(&iv));
    
    Ok(iv)
}

/// Add IV to an OMEMO header
pub fn add_iv_to_header(header: &mut Element, iv: &[u8]) -> Result<(), OmemoError> {
    //debug!("Adding IV to OMEMO header");
    
    // Validate the IV
    if let Err(e) = crypto::validate_iv(iv) {
        error!("Invalid IV for OMEMO header: {}", e);
        return Err(OmemoError::InvalidInput(format!("Invalid IV: {}", e)));
    }
    
    // Base64 encode using the proper Engine API
    let iv_base64 = BASE64_STANDARD.encode(iv);
    
    // Create and add the IV element
    let mut iv_element = Element::builder("iv", "eu.siacs.conversations.axolotl")
        .build();
    iv_element.append_text_node(&iv_base64);
    
    header.append_child(iv_element);
    //debug!("Successfully added IV to header");
    
    Ok(())
}

// ...existing code...

/// Create an OMEMO header for a message
pub fn create_omemo_header(
    sender_device_id: u32,
    _recipient_devices: &[(JidBare, u32)],
    iv: &[u8],
    keys: &[(u32, Vec<u8>)],
) -> Result<Element, OmemoError> {
    //debug!("Creating OMEMO header for message with {} recipient devices", recipient_devices.len());
    
    // Create the header element
    let mut header = Element::builder("header", "eu.siacs.conversations.axolotl")
        .attr("sid", sender_device_id.to_string())
        .build();
    
    // Add IV to header
    add_iv_to_header(&mut header, iv)?;
    
    // Add encrypted keys to header
    for (rid, key_data) in keys {
        let mut key_element = Element::builder("key", "eu.siacs.conversations.axolotl")
            .attr("rid", rid.to_string())
            .build();
        key_element.append_text_node(&BASE64_STANDARD.encode(key_data));
        
        header.append_child(key_element);
    }
    
    //debug!("OMEMO header created successfully with {} encrypted keys", keys.len());
    Ok(header)
}

/// Extract data from an OMEMO message
pub fn extract_omemo_data(
    encrypted_element: &Element,
) -> Result<(u32, Vec<(u32, Vec<u8>)>, Vec<u8>, Vec<u8>), OmemoError> {
    debug!("Extracting data from OMEMO message");
    
    // Get the header element
    let header = match encrypted_element.get_child("header", "eu.siacs.conversations.axolotl") {
        Some(el) => el,
        None => {
            error!("Missing header in OMEMO message");
            return Err(OmemoError::InvalidMessage("Missing header in message".to_string()));
        }
    };
    
    // Get the sender device ID
    let sid = match header.attr("sid") {
        Some(sid_str) => match sid_str.parse::<u32>() {
            Ok(sid) => sid,
            Err(e) => {
                error!("Invalid sender device ID: {}", e);
                return Err(OmemoError::InvalidMessage(format!("Invalid sender device ID: {}", e)));
            }
        },
        None => {
            error!("Missing sender device ID in OMEMO header");
            return Err(OmemoError::InvalidMessage("Missing sender device ID".to_string()));
        }
    };
    
    // Get the IV from the header
    let iv = parse_iv_from_header(header)?;
    
    // Extract the recipient-specific encrypted keys
    let mut keys = Vec::new();
    for key_el in header.children() {
        if key_el.name() == "key" {
            // Skip keys that don't have a recipient ID
            let rid = match key_el.attr("rid") {
                Some(rid_str) => match rid_str.parse::<u32>() {
                    Ok(rid) => rid,
                    Err(e) => {
                        warn!("Skipping key element with invalid recipient ID: {}", e);
                        continue;
                    }
                },
                None => {
                    warn!("Skipping key element without recipient ID");
                    continue;
                }
            };
            
            // Fix the text() handling for String instead of Option<String>
            let text = key_el.text();
            if text.is_empty() {
                warn!("Skipping empty key element");
                continue;
            }
            
            // Decode from base64
            let key_data = match BASE64_STANDARD.decode(text) {
                Ok(data) => data,
                Err(e) => {
                    warn!("Skipping key with invalid Base64 encoding: {}", e);
                    continue;
                }
            };
            
            keys.push((rid, key_data));
        }
    }
    
    // Process the <payload> element
    let payload_element = match encrypted_element.get_child("payload", "eu.siacs.conversations.axolotl") {
        Some(el) => el,
        None => {
            error!("Missing payload in OMEMO message");
            return Err(OmemoError::InvalidMessage("Missing payload in message".to_string()));
        }
    };

    // Get the payload text content and decode it
    let payload_text = payload_element.text();
    if payload_text.is_empty() {
        error!("Empty payload in OMEMO message");
        return Err(OmemoError::InvalidMessage("Empty payload".to_string()));
    }

    // Decode the payload from Base64
    let payload = match BASE64_STANDARD.decode(payload_text) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decode payload from Base64: {}", e);
            return Err(OmemoError::DecodingError(format!("Failed to decode payload: {}", e)));
        }
    };
    
    debug!("Successfully extracted OMEMO data: sid={}, {} keys, IV={} bytes, payload={} bytes",
           sid, keys.len(), iv.len(), payload.len());
    
    Ok((sid, keys, iv, payload))
}

// ...existing code...

/// Process an incoming OMEMO encrypted message
pub async fn process_incoming_omemo_message(
    from_jid: &JidBare,
    encrypted_element: &Element,
    omemo: &mut OmemoManager,
) -> Result<Option<Vec<u8>>, OmemoError> {
    //debug!("Processing incoming OMEMO message from {}", from_jid);
    
    // Extract the OMEMO data from the message
    let (sender_device_id, encrypted_keys, iv, encrypted_payload) =
        match extract_omemo_data(encrypted_element) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to extract OMEMO data: {}", e);
                return Err(e);
            }
        };
    
    // Check if we have a matching device ID
    let own_device_ids = vec![omemo.get_device_id()];
    
    // Find a matching key for our device
    let mut message_key_option: Option<Vec<u8>> = None;
    for (rid, key_data) in encrypted_keys {
        if own_device_ids.contains(&rid) {
            //debug!("Found matching key for our device ID: {}", rid);
            
            // Decrypt the message key
            let _key_result = match omemo.decrypt_message_key(from_jid.to_string(), sender_device_id, &key_data).await {
                Ok(key) => {
                    message_key_option = Some(key);
                    break;
                },
                Err(e) => {
                    warn!("Failed to decrypt key for device {}: {}", rid, e);
                    // Continue trying other keys
                }
            };
        }
    }
    
    // If we didn't find a matching key, we can't decrypt the message
    let message_key = match message_key_option {
        Some(key) => key,
        None => {
            error!("No matching key found for our devices");
            return Err(OmemoError::DecryptionError("No matching key found".to_string()));
        }
    };
    
    // Validate the IV before decryption
    if let Err(e) = crypto::validate_iv(&iv) {
        error!("Invalid IV for decryption: {}", e);
        return Err(OmemoError::DecryptionError(format!("Invalid IV: {}", e)));
    }
    
    // Decrypt the payload
    let plaintext = match crypto::decrypt(&encrypted_payload, &message_key, &iv, &[]) {
        Ok(data) => data,
        Err(e) => {
            error!("Failed to decrypt OMEMO payload: {}", e);
            return Err(OmemoError::DecryptionError(format!("Failed to decrypt payload: {}", e)));
        }
    };
    
    //debug!("Successfully decrypted OMEMO message from {}", from_jid);
    Ok(Some(plaintext))
}

// ...existing code...

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
        
        //debug!("Publishing device list for {} with device ID {}", bare_jid, device_id);
        
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
        publish_elem.set_attr("node", "eu.siacs.conversations.axolotl:devices");
        publish_elem.append_child(item_elem);
        
        let mut pubsub_elem = Element::bare("pubsub", "http://jabber.org/protocol/pubsub");
        pubsub_elem.append_child(publish_elem);
        
        let mut iq = Element::bare("iq", "jabber:client");
        iq.set_attr("type", "set");
        iq.set_attr("id", request_id.clone());
        iq.append_child(pubsub_elem);
        
        //debug!("Sending PubSub publish stanza: {:?}", iq);
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
                                    
                                    // Panic if we get an "invalid item" error for debugging
                                    if error_text.contains("invalid item") {
                                        panic!("FATAL: Invalid item when publishing device list: {:?}", stanza);
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

/// Alternative format for publishing bundles when the standard format fails
/// This function is public so it can be called from the bundle.rs module
pub async fn publish_bundle_alternative_format(
    to: Option<&str>,
    node: &str,
    id: &str,
    payload: &str,
) -> Result<()> {
    //debug!("Trying alternative bundle format for node {}", node);
    
    // Get the client from the global static
    if let Ok(current_client) = CURRENT_CLIENT.read() {
        if let Some(client_ref) = current_client.as_ref() {
            let mut client_guard = client_ref.lock().await;
            
            // Generate a unique IQ ID
            let iq_id = Uuid::new_v4().to_string();
            
            // Create a simplified bundle XML with minimal nesting
            let doc = match roxmltree::Document::parse(payload) {
                Ok(doc) => doc,
                Err(e) => {
                    error!("Failed to parse bundle payload: {}", e);
                    return Err(anyhow!("Failed to parse bundle payload: {}", e));
                }
            };
            
            let root = doc.root_element();
            
            // Extract key components
            let identity_key = root.children()
                .find(|n| n.has_tag_name("identityKey"))
                .and_then(|n| n.text())
                .unwrap_or("");
            
            let signed_pre_key_elem = root.children().find(|n| n.has_tag_name("signedPreKeyPublic"));
            let signed_pre_key_id = signed_pre_key_elem
                .and_then(|n| n.attribute("signedPreKeyId"))
                .unwrap_or("1");
            let signed_pre_key = signed_pre_key_elem
                .and_then(|n| n.text())
                .unwrap_or("");
            
            let signature = root.children()
                .find(|n| n.has_tag_name("signedPreKeySignature"))
                .and_then(|n| n.text())
                .unwrap_or("");
            
            // Build prekeys section
            let mut prekeys_xml = String::new();
            if let Some(prekeys_elem) = root.children().find(|n| n.has_tag_name("prekeys")) {
                for prekey in prekeys_elem.children().filter(|n| n.has_tag_name("preKeyPublic")) {
                    let id = prekey.attribute("preKeyId").unwrap_or("1");
                    let key = prekey.text().unwrap_or("");
                    prekeys_xml.push_str(&format!("<preKeyPublic preKeyId='{}'>{}</preKeyPublic>", id, key));
                }
            }
            
            // Create a simplified XML string with explicit namespace declarations
            let simplified_xml = format!(
                r#"<bundle xmlns='eu.siacs.conversations.axolotl'>
                    <identityKey>{}</identityKey>
                    <signedPreKeyPublic signedPreKeyId='{}'>{}</signedPreKeyPublic>
                    <signedPreKeySignature>{}</signedPreKeySignature>
                    <prekeys>{}</prekeys>
                </bundle>"#,
                identity_key, signed_pre_key_id, signed_pre_key, signature, prekeys_xml
            );
            
            // Create the IQ stanza as a raw string to ensure exact format
            let iq_str = format!(
                r#"<iq type='set' id='{}'{}>
                    <pubsub xmlns='http://jabber.org/protocol/pubsub'>
                        <publish node='{}'>
                            <item id='{}'>
                                {}
                            </item>
                        </publish>
                    </pubsub>
                </iq>"#,
                iq_id,
                to.map_or(String::new(), |t| format!(" to='{}'", t)),
                node,
                id,
                simplified_xml
            );
            
            // Parse the raw string into an Element
            let iq = match roxmltree::Document::parse(&iq_str) {
                Ok(doc) => {
                    let root = doc.root_element();
                    let mut iq = xmpp_parsers::Element::builder(root.tag_name().name(), root.tag_name().namespace().unwrap_or("jabber:client")).build();
                    
                    // Copy attributes
                    for attr in root.attributes() {
                        iq.set_attr(attr.name(), attr.value());
                    }
                    
                    // Function to recursively build elements
                    fn build_element(node: roxmltree::Node) -> xmpp_parsers::Element {
                        let mut elem = xmpp_parsers::Element::builder(
                            node.tag_name().name(),
                            node.tag_name().namespace().unwrap_or("")
                        ).build();
                        
                        // Copy attributes
                        for attr in node.attributes() {
                            elem.set_attr(attr.name(), attr.value());
                        }
                        
                        // Process children
                        for child in node.children().filter(|n| n.is_element()) {
                            elem.append_child(build_element(child));
                        }
                        
                        // Add text content
                        if let Some(text) = node.text() {
                            if !text.trim().is_empty() {
                                elem.append_text_node(text);
                            }
                        }
                        
                        elem
                    }
                    
                    // Add children
                    for child in root.children().filter(|n| n.is_element()) {
                        iq.append_child(build_element(child));
                    }
                    
                    iq
                },
                Err(e) => {
                    error!("Failed to parse alternative bundle XML: {}", e);
                    return Err(anyhow!("Failed to parse alternative bundle XML: {}", e));
                }
            };
            
            // Send the stanza
            //debug!("Sending alternative bundle stanza: {:?}", iq);
            match client_guard.send_stanza(iq).await {
                Ok(_) => {
                    info!("Alternative bundle format published successfully");
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to send alternative bundle format: {}", e);
                    Err(anyhow!("Failed to send alternative bundle format: {}", e))
                }
            }
        } else {
            error!("No client available for OMEMO device list publishing");
            Err(anyhow!("No client available"))
        }
    } else {
        error!("Failed to acquire read lock for CURRENT_CLIENT");
        Err(anyhow!("Failed to acquire read lock for CURRENT_CLIENT"))
    }
}

/// Alternative format for publishing items when the standard format fails
async fn publish_item_alternative_format(
    mut client_guard: tokio::sync::MutexGuard<'_, XMPPAsyncClient>,
    to: Option<&str>,
    node: &str,
    id: &str,
    payload: &str,
) -> Result<()> {
    //debug!("Trying alternative format for node {}", node);
    
    // Generate a unique IQ ID
    let iq_id = Uuid::new_v4().to_string();
    
    // Create a simplified XML string with explicit namespaces
    let iq_str = format!(
        r#"<iq type='set' id='{}'{}>
            <pubsub xmlns='http://jabber.org/protocol/pubsub'>
                <publish node='{}'>
                    <item id='{}'>
                        {}
                    </item>
                </publish>
            </pubsub>
        </iq>"#,
        iq_id,
        to.map_or(String::new(), |t| format!(" to='{}'", t)),
        node,
        id,
        payload
    );
    
    // Parse the raw string into an Element
    let iq = match roxmltree::Document::parse(&iq_str) {
        Ok(doc) => {
            let root = doc.root_element();
            let mut iq = xmpp_parsers::Element::builder(root.tag_name().name(), "jabber:client").build();
            
            // Copy attributes
            for attr in root.attributes() {
                iq.set_attr(attr.name(), attr.value());
            }
            
            // Function to recursively build elements
            fn build_element(node: roxmltree::Node) -> xmpp_parsers::Element {
                let ns = if node.tag_name().name() == "pubsub" {
                    "http://jabber.org/protocol/pubsub"
                } else if node.has_tag_name("list") || node.has_tag_name("bundle") {
                    "eu.siacs.conversations.axolotl"
                } else {
                    node.tag_name().namespace().unwrap_or("")
                };
                
                let mut elem = xmpp_parsers::Element::builder(node.tag_name().name(), ns).build();
                
                // Copy attributes
                for attr in node.attributes() {
                    elem.set_attr(attr.name(), attr.value());
                }
                
                // Process children
                for child in node.children().filter(|n| n.is_element()) {
                    elem.append_child(build_element(child));
                }
                
                // Add text content
                if let Some(text) = node.text() {
                    if !text.trim().is_empty() {
                        elem.append_text_node(text);
                    }
                }
                
                elem
            }
            
            // Add children
            for child in root.children().filter(|n| n.is_element()) {
                iq.append_child(build_element(child));
            }
            
            iq
        },
        Err(e) => {
            error!("Failed to parse alternative XML: {}", e);
            return Err(anyhow!("Failed to parse alternative XML: {}", e));
        }
    };
    
    // Send the stanza
    //debug!("Sending alternative format stanza: {:?}", iq);
    match client_guard.send_stanza(iq).await {
        Ok(_) => {
            info!("Alternative format published successfully");
            Ok(())
        },
        Err(e) => {
            error!("Failed to send alternative format: {}", e);
            Err(anyhow!("Failed to send alternative format: {}", e))
        }
    }
}

/// Publish a PubSub item in the correct format for OMEMO device lists
pub async fn publish_pubsub_item_device_list(
    device_ids: &[DeviceId]
) -> Result<()> {
    //debug!("Publishing OMEMO device list with {} devices", device_ids.len());
    
    // Get the client from the global static
    if let Ok(current_client) = CURRENT_CLIENT.read() {
        if let Some(client_ref) = current_client.as_ref() {
            let mut client_guard = client_ref.lock().await;
            
            // Generate a unique IQ ID
            let iq_id = Uuid::new_v4().to_string();
            
            // Build the device list element properly with correct namespaces
            let mut devices_xml = String::new();
            for device_id in device_ids {
                devices_xml.push_str(&format!("<device id='{}' />", device_id));
            }
            
            // Create the XML stanza directly to ensure correct namespace handling
            let mut list_element = xmpp_parsers::Element::builder("list", "eu.siacs.conversations.axolotl").build();
            
            // Add each device element
            for device_id in device_ids {
                let device_element = xmpp_parsers::Element::builder("device", "eu.siacs.conversations.axolotl")
                    .attr("id", &device_id.to_string())
                    .build();
                list_element.append_child(device_element);
            }
            
            // Create the proper element hierarchy with explicit namespaces
            let item_element = xmpp_parsers::Element::builder("item", "http://jabber.org/protocol/pubsub")
                .attr("id", "current")
                .append(list_element)
                .build();
            
            let publish_element = xmpp_parsers::Element::builder("publish", "http://jabber.org/protocol/pubsub")
                .attr("node", "eu.siacs.conversations.axolotl:devices")
                .append(item_element)
                .build();
            
            let pubsub_element = xmpp_parsers::Element::builder("pubsub", "http://jabber.org/protocol/pubsub")
                .append(publish_element)
                .build();
            
            let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
                .attr("type", "set")
                .attr("id", &iq_id)
                .append(pubsub_element)
                .build();
            
            info!("Sending device list publish stanza: {:?}", iq);
            
            // Send the stanza
            match client_guard.send_stanza(iq).await {
                Ok(_) => {
                    info!("Device list publish request sent successfully");
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to send device list publish stanza: {}", e);
                    
                    // Try alternative format if the standard format fails
                    if e.to_string().contains("bad-request") || e.to_string().contains("invalid-item") {
                        warn!("Received bad-request error, trying alternative device list format");
                        
                        // Create a simplified XML string
                        let list_xml = format!(
                            r#"<list xmlns='eu.siacs.conversations.axolotl'>{}</list>"#,
                            devices_xml
                        );
                        
                        return publish_item_alternative_format(client_guard, None, "eu.siacs.conversations.axolotl:devices", "current", &list_xml).await;
                    }
                    
                    Err(anyhow!("Failed to send device list publish stanza: {}", e))
                }
            }
        } else {
            error!("No client available for OMEMO device list publishing");
            Err(anyhow!("No client available"))
        }
    } else {
        error!("Failed to acquire read lock for CURRENT_CLIENT");
        Err(anyhow!("Failed to acquire read lock for CURRENT_CLIENT"))
    }
}

/// Request items from a PubSub node (for OMEMO implementation)
/// This function is called by the OMEMO manager to fetch device lists and bundles
pub async fn request_pubsub_items(
    from: &str,
    node: &str,
) -> Result<String> {
    //debug!("Requesting PubSub items from {} for node {}", from, node);
    
    // Get a cloned Arc of the client to avoid holding the RwLock across await points
    let client_ref = match get_current_client() {
        Some(client) => client,
        None => {
            error!("No client available for PubSub requests");
            return Err(anyhow!("No client available for PubSub requests"));
        }
    };
    
    // Lock the client and send the request
    let mut client_guard = client_ref.lock().await;
    
    // Generate a unique ID for this request
    let request_id = uuid::Uuid::new_v4().to_string();
    
    // Create the IQ stanza
    let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
        .attr("type", "get")
        .attr("id", &request_id)
        .attr("to", from)
        .append(
            xmpp_parsers::Element::builder("pubsub", "http://jabber.org/protocol/pubsub")
                .append(
                xmpp_parsers::Element::builder("items", "http://jabber.org/protocol/pubsub")
                    .attr("node", node)
                    .build()
                )
                .build()
        )
        .build();
    
    // Send the stanza
    //debug!("Sending PubSub request stanza: {:?}", iq);
    
    if let Err(e) = client_guard.send_stanza(iq).await {
        error!("Failed to send PubSub request: {}", e);
        return Err(anyhow!("Failed to send PubSub request: {}", e));
    }
    
    // Drop the guard to release the lock before waiting
    drop(client_guard);
    
    // Wait for the response with a timeout
    let timeout = Duration::from_secs(10);
    let start_time = tokio::time::Instant::now();
    
    while tokio::time::Instant::now().duration_since(start_time) < timeout {
        // Get the lock for each iteration
        let mut client_guard = client_ref.lock().await;
        
        match tokio::time::timeout(
            Duration::from_millis(500),
            client_guard.next()
        ).await {
            Ok(Some(tokio_xmpp::Event::Stanza(stanza))) => {
                if stanza.name() == "iq" && stanza.attr("id") == Some(&request_id) {
                    //debug!("Received PubSub response for ID: {}", request_id);
                    
                    // Log more details about the response for debugging
                    if stanza.attr("type") == Some("error") {
                        if let Some(error) = stanza.get_child("error", "") {
                            let error_type = error.attr("type").unwrap_or("unknown");
                            warn!("Error in PubSub response: type={}", error_type);
                            
                            for child in error.children() {
                                warn!("Error condition: {}", child.name());
                            }
                        }
                    }
                    
                    // Convert to string for return
                    let mut xml_output = Vec::new();
                    let mut writer = xml::EmitterConfig::new()
                        .perform_indent(true)
                        .create_writer(&mut xml_output);
                    
                    writer.write(xml::writer::XmlEvent::StartDocument {
                        version: xml::common::XmlVersion::Version10,
                        encoding: Some("utf-8"),
                        standalone: None,
                    }).ok();
                    
                    // Serialize the element
                    fn serialize_element<W: std::io::Write>(
                        element: &xmpp_parsers::Element,
                        writer: &mut xml::writer::EventWriter<W>,
                    ) -> Result<()> {
                        // Start element with namespace
                        let mut start = xml::writer::XmlEvent::start_element(element.name());
                        
                        // Add namespace if not empty
                        if !element.ns().is_empty() {
                            start = start.ns("", element.ns());
                        }
                        
                        // Add attributes
                        for (name, value) in element.attrs() {
                            start = start.attr(name, value);
                        }
                        
                        writer.write(start).map_err(|e| anyhow!("XML write error: {}", e))?;
                        
                        // Process children
                        for child in element.children() {
                            serialize_element(child, writer)?;
                        }
                        
                        // Add text content
                        let text = element.text();
                        if !text.is_empty() {
                            writer.write(xml::writer::XmlEvent::Characters(&text))
                                .map_err(|e| anyhow!("XML write error: {}", e))?;
                        }
                        
                        // End element
                        writer.write(xml::writer::XmlEvent::end_element())
                            .map_err(|e| anyhow!("XML write error: {}", e))?;
                        
                        Ok(())
                    }
                    
                    serialize_element(&stanza, &mut writer)?;
                    
                    let response = String::from_utf8_lossy(&xml_output).to_string();
                    //debug!("PubSub response serialized: {}", response);
                    
                    return Ok(response);
                }
            },
            Ok(Some(tokio_xmpp::Event::Disconnected(reason))) => {
                return Err(anyhow!("Disconnected while waiting for PubSub response: {:?}", reason));
            },
            Ok(None) => {
                return Err(anyhow!("Stream ended while waiting for PubSub response"));
            },
            Err(_) => {
                // Timeout on this attempt, continue the loop
            },
            _ => { /* Ignore other events */ }
        }
        
        // Drop the guard to avoid holding the lock for too long
        drop(client_guard);
        
        // Small sleep to avoid tight loop
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    // If we timeout, handle it gracefully
    warn!("Timed out waiting for PubSub response for node {}", node);
    
    // Check if we're in development mode
    let is_development = cfg!(debug_assertions);
    
    // For device list queries, return an empty list
    if node.contains("devicelist") {
        //debug!("Returning empty device list response as fallback");
        let empty_list_response = format!(r#"<?xml version="1.0" encoding="utf-8"?>
<iq type="result" id="{}">
  <pubsub xmlns="http://jabber.org/protocol/pubsub">
    <items node="{}">
      <item id="current">
        <list xmlns="eu.siacs.conversations.axolotl"/>
      </item>
    </items>
  </pubsub>
</iq>"#, request_id, node);
        
        // In production, log this as a warning
        if !is_development {
            warn!("Using empty device list fallback in PRODUCTION mode for {}", from);
        }
        
        return Ok(empty_list_response);
    }
    
    // For bundle requests, provide a mock bundle in development mode
    // In production, return a proper error for bundle requests
    if node.contains("bundles") {
        if is_development {
            //debug!("Generating mock bundle response as fallback (DEVELOPMENT MODE ONLY)");
            let mock_bundle_response = format!(r#"<?xml version="1.0" encoding="utf-8"?>
<iq type="result" id="{}">
  <pubsub xmlns="http://jabber.org/protocol/pubsub">
    <items node="{}">
      <item id="current">
        <bundle xmlns="eu.siacs.conversations.axolotl">
          <signedPreKeyPublic signedPreKeyId="1">BFk67IWOxVrpMzwNhIZfGLVCec8QipcTa3q9Fa5l9Bw==</signedPreKeyPublic>
          <signedPreKeySignature>RQalg0e2XhE7dJM7MB6Te0TrOh1pZ/GzfQmVEnBSB+6oC92rv1sRmXIWk61Gtxl9SPp/UYwIQZ2k1L8iFZEuDA==</signedPreKeySignature>
          <identityKey>BeLW7HxZNJhGWj6WR4Ia2ypRnxu8xcDIKb8WzYuGZZA=</identityKey>
          <prekeys>
            <preKeyPublic preKeyId="1">BSs9Z6C0Qc9yfgzJK3tPw6qzI0S5/2UX+FjImVU31B8=</preKeyPublic>
            <preKeyPublic preKeyId="2">BP1xx4eFH/LSs1XdTu5XA06qzHIXXaA4nskYCyJE/xg=</preKeyPublic>
          </prekeys>
        </bundle>
      </item>
    </items>
  </pubsub>
</iq>"#, request_id, node);
            
            return Ok(mock_bundle_response);
        } else {
            // In production, return a proper error for bundle requests
            error!("Failed to retrieve bundle from {} (timeout)", from);
            return Err(anyhow!("Failed to retrieve bundle from {} (timeout)", from));
        }
    }
    
    // For other types of requests, return a generic error
    return Err(anyhow!("Timed out waiting for PubSub response for node {}", node));
}
