use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use tokio::time::Duration;
use uuid::Uuid;

use xmpp_parsers::BareJid as JidBare;

use crate::models::{Message, DeliveryStatus};
use crate::xmpp::custom_ns;
use crate::omemo::device_id::DeviceId;

/// Implementation of XEP-0384 OMEMO Encryption
impl crate::xmpp::XMPPClient {

    /// Send an OMEMO encrypted message
    pub async fn send_omemo_encrypted_message(&self, recipient: &str, plaintext: &str) -> Result<()> {
        let _client = self.client.as_ref().ok_or_else(|| {
            error!("XMPP client not initialized when trying to send encrypted message");
            anyhow!("XMPP client not initialized")
        })?;
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
            carbons_enabled: self.carbons_enabled.clone(),
            iq_registry: self.iq_registry.clone(),
            pubsub_responses: self.pubsub_responses.clone(),
            shared_self: self.shared_self.clone(),
            typing_tx: self.typing_tx.clone(),
        };
        
        match temp_client.send_encrypted_message(recipient, plaintext).await {
            Ok(_) => {
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
    
    /// Request an OMEMO device list from a peer
    /// This is the first step in the key discovery process
    pub async fn request_omemo_devicelist(&self, peer_jid: &str) -> Result<()> {
        debug!("Sending OMEMO device list request to {}", peer_jid);
        
        // For device list queries, we must use the BARE JID (without resource)
        // According to XEP-0384, device lists are stored under the bare JID
        let bare_jid = if peer_jid.contains('/') {
            // Extract bare JID by removing resource
            peer_jid.split('/').next().unwrap_or(peer_jid).to_string()
        } else {
            // Already a bare JID, validate it has domain
            if !peer_jid.contains('@') {
                error!("Invalid JID format for device list request: {} (missing domain)", peer_jid);
                return Err(anyhow!("Invalid JID format: {} (missing domain)", peer_jid));
            }
            peer_jid.to_string()
        };
        
        info!("Requesting device list for bare JID: {}", bare_jid);
        
        // Try with Conversations format first (dot + devicelist)
        let conversations_result = crate::xmpp::omemo_integration::request_pubsub_items(&bare_jid, &format!("{}.devicelist", custom_ns::OMEMO)).await;
        
        if conversations_result.is_ok() {
            info!("Successfully retrieved device list with Conversations format ({}.devicelist)", custom_ns::OMEMO);
            return Ok(());
        }
        
        // Try with colon separator format
        let standard_result = crate::xmpp::omemo_integration::request_pubsub_items(&bare_jid, &format!("{}:devices", custom_ns::OMEMO)).await;
        
        if standard_result.is_ok() {
            info!("Successfully retrieved device list with colon format ({}:devices)", custom_ns::OMEMO);
            return Ok(());
        }
        
        // Try with legacy colon+devicelist format
        let legacy_result = crate::xmpp::omemo_integration::request_pubsub_items(&bare_jid, &format!("{}:devicelist", custom_ns::OMEMO)).await;
        
        if let Err(e) = &legacy_result {
            warn!("Failed to retrieve device list with all node format combinations: {}", e);
            return Err(anyhow!("Failed to retrieve device list: {}", e));
        }
        
        info!("Successfully retrieved device list with legacy format ({}:devicelist)", custom_ns::OMEMO);
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
            Ok(jid) => jid,
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
        let client = self.client.as_ref().ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        let node_name = format!("{}.devicelist", custom_ns::OMEMO);
        
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
                            .attr("node", &format!("{}.devicelist", custom_ns::OMEMO))
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
        let client = self.client.as_ref().ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        
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
                // First, mark the device as trusted in the database directly
                if let Err(e) = storage.set_device_trust(contact, device_id, true) {
                    error!("Failed to mark device as trusted in database: {}", e);
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
                }
                
                Ok(())
            },
            "__KEY_REJECTED__" => {
                // First, mark the device as explicitly untrusted in the database directly
                if let Err(e) = storage.set_device_trust(contact, device_id, false) {
                    error!("Failed to mark device as untrusted in database: {}", e);
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
        // Format a reasonable MUC JID based on the room name
        let jid_str = self.jid.to_string();
        let server_domain = match jid_str.split('@').collect::<Vec<&str>>().get(1) {
            Some(domain) => *domain,
            None => "example.org"
        };
        
        let muc_domain = format!("conference.{}", server_domain);
        let muc_jid = format!("{}@{}", room_name, muc_domain);
        
        info!("Using MUC room: {}", muc_jid);
        
        Ok(muc_jid)
    }

    /// Send an encrypted message to a group chat
    pub async fn send_encrypted_group_message(&mut self, muc_jid: &str, content: &str) -> Result<()> {
        info!("Sending encrypted message to MUC: {}", muc_jid);
        self.send_encrypted_message(muc_jid, content).await
    }

    /// Configure a PubSub node for open access (required for OMEMO)
    async fn configure_node_for_open_access(&self, node_name: &str) -> Result<()> {
        let client = self.client.as_ref().ok_or_else(|| anyhow!("XMPP client not initialized"))?;
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
