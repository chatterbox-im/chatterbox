use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use uuid::Uuid;

use crate::jid::BareJid;
use crate::models::Message;
use crate::omemo::device_id::DeviceId;
use crate::xmpp::custom_ns;
use crate::xmpp::transport;

/// Implementation of XEP-0384 OMEMO Encryption
impl crate::xmpp::XMPPClient {
    /// Send an OMEMO encrypted message
    /// Check if an OMEMO element is related to PubSub
    pub fn is_omemo_pubsub(pubsub: &xmpp_parsers::minidom::Element) -> bool {
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
                error!(
                    "Invalid JID format for device list request: {} (missing domain)",
                    peer_jid
                );
                return Err(anyhow!("Invalid JID format: {} (missing domain)", peer_jid));
            }
            peer_jid.to_string()
        };

        info!("Requesting device list for bare JID: {}", bare_jid);

        // Try with Conversations format first (dot + devicelist)
        let conversations_result = crate::xmpp::omemo_integration::request_pubsub_items(
            &bare_jid,
            &format!("{}.devicelist", custom_ns::OMEMO),
        )
        .await;

        if conversations_result.is_ok() {
            info!(
                "Successfully retrieved device list with Conversations format ({}.devicelist)",
                custom_ns::OMEMO
            );
            return Ok(());
        }

        // Try with colon separator format
        let standard_result = crate::xmpp::omemo_integration::request_pubsub_items(
            &bare_jid,
            &format!("{}:devices", custom_ns::OMEMO),
        )
        .await;

        if standard_result.is_ok() {
            info!(
                "Successfully retrieved device list with colon format ({}:devices)",
                custom_ns::OMEMO
            );
            return Ok(());
        }

        // Try with legacy colon+devicelist format
        let legacy_result = crate::xmpp::omemo_integration::request_pubsub_items(
            &bare_jid,
            &format!("{}:devicelist", custom_ns::OMEMO),
        )
        .await;

        if let Err(e) = &legacy_result {
            warn!(
                "Failed to retrieve device list with all node format combinations: {}",
                e
            );
            return Err(anyhow!("Failed to retrieve device list: {}", e));
        }

        info!(
            "Successfully retrieved device list with legacy format ({}:devicelist)",
            custom_ns::OMEMO
        );
        Ok(())
    }

    /// Request an OMEMO device bundle from a peer
    /// This is the second step in the key discovery process, after getting the device list
    pub async fn request_omemo_bundle(&self, peer_jid: &str, device_id: DeviceId) -> Result<()> {
        let stanza_tx = self
            .stanza_tx
            .as_ref()
            .ok_or_else(|| anyhow!("XMPP client not initialized"))?;

        // Validate and normalize the JID first
        let _normalized_jid = match self.ensure_full_jid(peer_jid).await {
            Ok(jid) => jid,
            Err(e) => {
                error!("Invalid JID format for bundle request: {}: {}", peer_jid, e);
                return Err(anyhow!("Invalid JID format: {}: {}", peer_jid, e));
            }
        };

        // Generate a unique ID for this request
        let request_id = Uuid::new_v4().to_string();

        // Create the PubSub IQ request for the device bundle
        let node = format!("{}.bundles:{}", custom_ns::OMEMO_V1, device_id);

        // Build the IQ stanza
        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "get")
            .attr("id".try_into().unwrap(), &request_id)
            .attr("to".try_into().unwrap(), peer_jid)
            .append(
                xmpp_parsers::minidom::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(
                        xmpp_parsers::minidom::Element::builder("items", custom_ns::PUBSUB)
                            .attr("node".try_into().unwrap(), &node)
                            .build(),
                    )
                    .build(),
            )
            .build();

        transport::send_stanza(stanza_tx, iq)
            .map_err(|e| anyhow!("Failed to send OMEMO bundle request: {}", e))
    }

    /// Publish your OMEMO device list to the server
    /// This advertises which devices you have available for OMEMO encryption
    pub async fn publish_omemo_devicelist(&self, device_ids: &[DeviceId]) -> Result<()> {
        let stanza_tx = self
            .stanza_tx
            .as_ref()
            .ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        let node_name = format!("{}.devicelist", custom_ns::OMEMO);

        // First, try to configure the node for open access
        if let Err(e) = self.configure_node_for_open_access(&node_name).await {
            warn!(
                "Could not configure device list node for open access: {}",
                e
            );
            // Continue anyway - the node might already exist with correct permissions
        }

        // Generate a unique ID for this publish request
        let publish_id = Uuid::new_v4().to_string();

        // Create the device list XML content
        let mut list_element =
            xmpp_parsers::minidom::Element::builder("list", custom_ns::OMEMO).build();

        // Add device elements
        for device_id in device_ids {
            let device_element = xmpp_parsers::minidom::Element::builder("device", "")
                .attr("id".try_into().unwrap(), &device_id.to_string())
                .build();
            list_element.append_child(device_element);
        }

        // Build the IQ stanza for publishing
        let publish_elem = xmpp_parsers::minidom::Element::builder("publish", custom_ns::PUBSUB)
            .attr(
                "node".try_into().unwrap(),
                &format!("{}.devicelist", custom_ns::OMEMO),
            )
            .append(
                xmpp_parsers::minidom::Element::builder("item", custom_ns::PUBSUB)
                    .attr("id".try_into().unwrap(), "current")
                    .append(list_element)
                    .build(),
            )
            .build();

        // Publish-options for open access
        let publish_options =
            xmpp_parsers::minidom::Element::builder("publish-options", custom_ns::PUBSUB)
                .append(
                    xmpp_parsers::minidom::Element::builder("x", "jabber:x:data")
                        .attr("type".try_into().unwrap(), "submit")
                        .append(
                            xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                                .attr("var".try_into().unwrap(), "FORM_TYPE")
                                .attr("type".try_into().unwrap(), "hidden")
                                .append({
                                    let mut v = xmpp_parsers::minidom::Element::builder(
                                        "value",
                                        "jabber:x:data",
                                    )
                                    .build();
                                    v.append_text_node(
                                        "http://jabber.org/protocol/pubsub#publish-options",
                                    );
                                    v
                                })
                                .build(),
                        )
                        .append(
                            xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                                .attr("var".try_into().unwrap(), "pubsub#access_model")
                                .append({
                                    let mut v = xmpp_parsers::minidom::Element::builder(
                                        "value",
                                        "jabber:x:data",
                                    )
                                    .build();
                                    v.append_text_node("open");
                                    v
                                })
                                .build(),
                        )
                        .build(),
                )
                .build();

        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), &publish_id)
            .append(
                xmpp_parsers::minidom::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(publish_elem)
                    .append(publish_options)
                    .build(),
            )
            .build();

        // Send the publish request
        transport::send_stanza(stanza_tx, iq)
            .map_err(|e| anyhow!("Failed to publish OMEMO device list: {}", e))?;

        info!("OMEMO device list published successfully");
        Ok(())
    }

    /// Publish your OMEMO device bundle to the server
    /// This advertises your keys for encryption
    pub async fn publish_omemo_bundle(&self, device_id: DeviceId, bundle_data: &str) -> Result<()> {
        let stanza_tx = self
            .stanza_tx
            .as_ref()
            .ok_or_else(|| anyhow!("XMPP client not initialized"))?;

        // Configure the bundle node for open access before publishing
        let bundle_node_name = format!("{}.bundles:{}", custom_ns::OMEMO_V1, device_id);
        if let Err(e) = self.configure_node_for_open_access(&bundle_node_name).await {
            warn!(
                "Failed to configure bundle node {} for open access: {}",
                bundle_node_name, e
            );
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
                let mut bundle =
                    xmpp_parsers::minidom::Element::builder("bundle", custom_ns::OMEMO).build();

                // Process each child element of the bundle
                for child in root.children().filter(|n| n.is_element()) {
                    let child_name = child.tag_name().name();
                    let mut child_elem =
                        xmpp_parsers::minidom::Element::builder(child_name, "").build();

                    // Copy all attributes
                    for attr in child.attributes() {
                        child_elem.set_attr(
                            xmpp_parsers::minidom::rxml::Namespace::NONE,
                            attr.name().try_into().unwrap(),
                            attr.value(),
                        );
                    }

                    // Handle child elements differently based on their type
                    if child_name == "prekeys" {
                        // Special handling for prekeys which has its own children
                        for prekey in child.children().filter(|n| n.is_element()) {
                            let mut prekey_elem = xmpp_parsers::minidom::Element::builder(
                                prekey.tag_name().name(),
                                "",
                            )
                            .build();

                            // Copy prekey attributes
                            for attr in prekey.attributes() {
                                prekey_elem.set_attr(
                                    xmpp_parsers::minidom::rxml::Namespace::NONE,
                                    attr.name().try_into().unwrap(),
                                    attr.value(),
                                );
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
            }
            Err(e) => {
                error!("Failed to parse bundle data as XML: {}", e);
                // Create a simple element with the data as text as a fallback
                let mut bundle =
                    xmpp_parsers::minidom::Element::builder("bundle", custom_ns::OMEMO).build();
                bundle.append_text_node(bundle_data);
                bundle
            }
        };

        // Create the item element and append the bundle element
        let item_element = xmpp_parsers::minidom::Element::builder("item", custom_ns::PUBSUB)
            .attr("id".try_into().unwrap(), "current")
            .append(bundle_element)
            .build();

        // Build the IQ stanza for publishing
        let publish_elem = xmpp_parsers::minidom::Element::builder("publish", custom_ns::PUBSUB)
            .attr(
                "node".try_into().unwrap(),
                &format!("{}.bundles:{}", custom_ns::OMEMO_V1, device_id),
            )
            .append(item_element)
            .build();

        // Publish-options for open access
        let publish_options =
            xmpp_parsers::minidom::Element::builder("publish-options", custom_ns::PUBSUB)
                .append(
                    xmpp_parsers::minidom::Element::builder("x", "jabber:x:data")
                        .attr("type".try_into().unwrap(), "submit")
                        .append(
                            xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                                .attr("var".try_into().unwrap(), "FORM_TYPE")
                                .attr("type".try_into().unwrap(), "hidden")
                                .append({
                                    let mut v = xmpp_parsers::minidom::Element::builder(
                                        "value",
                                        "jabber:x:data",
                                    )
                                    .build();
                                    v.append_text_node(
                                        "http://jabber.org/protocol/pubsub#publish-options",
                                    );
                                    v
                                })
                                .build(),
                        )
                        .append(
                            xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                                .attr("var".try_into().unwrap(), "pubsub#access_model")
                                .append({
                                    let mut v = xmpp_parsers::minidom::Element::builder(
                                        "value",
                                        "jabber:x:data",
                                    )
                                    .build();
                                    v.append_text_node("open");
                                    v
                                })
                                .build(),
                        )
                        .build(),
                )
                .build();

        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), &publish_id)
            .append(
                xmpp_parsers::minidom::Element::builder("pubsub", custom_ns::PUBSUB)
                    .append(publish_elem)
                    .append(publish_options)
                    .build(),
            )
            .build();

        // Send the publish request
        transport::send_stanza(stanza_tx, iq)
            .map_err(|e| anyhow!("Failed to publish OMEMO bundle: {}", e))?;

        info!(
            "OMEMO bundle published successfully for device {}",
            device_id
        );
        Ok(())
    }

    /// Detect an unrecognized OMEMO key and request verification
    pub async fn detect_unrecognized_omemo_key(
        &self,
        sender: &str,
        key_fingerprint: &str,
        device_id: Option<DeviceId>,
    ) -> Result<()> {
        // Log the detection of an unrecognized key
        info!(
            "Detected unrecognized OMEMO key from {} with fingerprint: {}",
            sender, key_fingerprint
        );

        // Format the device ID for display
        let device_id_str = device_id.map(|id| id.to_string());

        // Create a special system message to trigger the verification UI
        let special_message = Message::system(
            "me",
            format!(
                "__OMEMO_KEY_VERIFY__:{}:{}:{}",
                sender,
                key_fingerprint,
                device_id_str.as_deref().unwrap_or("")
            ),
        );

        // Send the special message to the UI
        if let Err(e) = self.msg_tx.send(special_message).await {
            error!("Failed to send key verification request to UI: {}", e);
            return Err(anyhow!(
                "Failed to send key verification request to UI: {}",
                e
            ));
        }

        Ok(())
    }

    /// Process OMEMO key verification response from user
    pub async fn process_omemo_verification_response(
        &self,
        contact: &str,
        response: &str,
    ) -> Result<()> {
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
        let device_id = match storage.get_pending_device_verification(&BareJid::from_raw_lossy(contact)) {
            Ok(Some((device_id, _fingerprint))) => device_id,
            Ok(None) => {
                warn!(
                    "No pending verification found for {}, cannot process response",
                    contact
                );
                return Err(anyhow!("No pending verification found for {}", contact));
            }
            Err(e) => {
                warn!("Error retrieving pending verification: {}", e);
                return Err(anyhow!("Error retrieving pending verification: {}", e));
            }
        };

        match response {
            "__KEY_ACCEPTED__" => {
                // First, mark the device as trusted in the database directly
                if let Err(e) = storage.set_device_trust(&BareJid::from_raw_lossy(contact), device_id, true) {
                    error!("Failed to mark device as trusted in database: {}", e);
                }

                // Mark the device as trusted in the OMEMO manager
                let mut manager_guard = omemo_manager.lock().await;
                if let Err(e) = manager_guard
                    .trust_device_identity(contact, device_id)
                    .await
                {
                    error!("Failed to mark device as trusted in OMEMO manager: {}", e);
                    return Err(anyhow!("Failed to mark device as trusted: {}", e));
                }

                info!(
                    "Successfully marked device {}:{} as trusted",
                    contact, device_id
                );

                // Clear the pending verification since it's been processed
                if let Err(e) = storage.remove_pending_device_verification(&BareJid::from_raw_lossy(contact), device_id) {
                    warn!("Failed to remove pending verification: {}", e);
                }

                Ok(())
            }
            "__KEY_REJECTED__" => {
                // First, mark the device as explicitly untrusted in the database directly
                if let Err(e) = storage.set_device_trust(&BareJid::from_raw_lossy(contact), device_id, false) {
                    error!("Failed to mark device as untrusted in database: {}", e);
                }

                // Mark the device as untrusted in the OMEMO manager
                let manager_guard = omemo_manager.lock().await;
                if let Err(e) = manager_guard
                    .untrust_device_identity(contact, device_id)
                    .await
                {
                    error!("Failed to mark device as untrusted in OMEMO manager: {}", e);
                    return Err(anyhow!("Failed to mark device as untrusted: {}", e));
                }

                info!(
                    "Successfully marked device {}:{} as untrusted",
                    contact, device_id
                );

                // Clear the pending verification since it's been processed
                if let Err(e) = storage.remove_pending_device_verification(&BareJid::from_raw_lossy(contact), device_id) {
                    warn!("Failed to remove pending verification: {}", e);
                }

                Ok(())
            }
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
            Ok(manager.get_device_id().get())
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
                Err(e) => Err(anyhow!("Failed to get own fingerprint: {}", e)),
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
                Err(e) => Err(anyhow!("Failed to check device trust status: {}", e)),
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Mark a device as trusted
    pub async fn mark_device_trusted(&self, jid: &str, device_id: DeviceId) -> Result<()> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let mut manager = omemo_manager.lock().await;
            match manager.trust_device_identity(jid, device_id).await {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("Failed to mark device as trusted: {}", e)),
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
                Err(e) => Err(anyhow!("Failed to mark device as untrusted: {}", e)),
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
                Err(e) => Err(anyhow!("Failed to get contact devices: {}", e)),
            }
        } else {
            Err(anyhow!("OMEMO manager not initialized"))
        }
    }

    /// Publish device list to the server (fetches existing list and merges our device ID)
    pub async fn publish_device_list(&self) -> Result<()> {
        if let Some(omemo_manager) = &self.omemo_manager {
            let manager = omemo_manager.lock().await;
            manager
                .ensure_device_list_published()
                .await
                .map_err(|e| anyhow!("Failed to publish device list: {}", e))
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
        self.request_omemo_bundle(jid, DeviceId::from(device_id)).await
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
                }
                Err(e) => Err(anyhow!("Failed to rotate OMEMO keys: {}", e)),
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
            None => "example.org",
        };

        let muc_domain = format!("conference.{}", server_domain);
        let muc_jid = format!("{}@{}", room_name, muc_domain);

        info!("Using MUC room: {}", muc_jid);

        Ok(muc_jid)
    }

    /// Send an encrypted message to a group chat
    pub async fn send_encrypted_group_message(
        &mut self,
        muc_jid: &str,
        content: &str,
    ) -> Result<()> {
        info!("Sending encrypted message to MUC: {}", muc_jid);
        self.send_encrypted_message(muc_jid, content).await
    }

    /// Configure a PubSub node for open access (required for OMEMO)
    async fn configure_node_for_open_access(&self, node_name: &str) -> Result<()> {
        let stanza_tx = self
            .stanza_tx
            .as_ref()
            .ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        let config_id = Uuid::new_v4().to_string();

        // Create configuration form for open access
        let config_iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), &config_id)
            .append(
                xmpp_parsers::minidom::Element::builder(
                    "pubsub",
                    "http://jabber.org/protocol/pubsub#owner",
                )
                .append(
                    xmpp_parsers::minidom::Element::builder("configure", "")
                        .attr("node".try_into().unwrap(), node_name)
                        .append(
                            xmpp_parsers::minidom::Element::builder("x", "jabber:x:data")
                                .attr("type".try_into().unwrap(), "submit")
                                .append(
                                    xmpp_parsers::minidom::Element::builder("field", "")
                                        .attr("var".try_into().unwrap(), "FORM_TYPE")
                                        .attr("type".try_into().unwrap(), "hidden")
                                        .append({
                                            let mut value_elem =
                                                xmpp_parsers::minidom::Element::builder(
                                                    "value", "",
                                                )
                                                .build();
                                            value_elem.append_text_node(
                                                "http://jabber.org/protocol/pubsub#node_config",
                                            );
                                            value_elem
                                        })
                                        .build(),
                                )
                                .append(
                                    xmpp_parsers::minidom::Element::builder("field", "")
                                        .attr("var".try_into().unwrap(), "pubsub#access_model")
                                        .append({
                                            let mut value_elem =
                                                xmpp_parsers::minidom::Element::builder(
                                                    "value", "",
                                                )
                                                .build();
                                            value_elem.append_text_node("open");
                                            value_elem
                                        })
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build(),
            )
            .build();

        // Send the configuration request
        match transport::send_stanza(stanza_tx, config_iq) {
            Ok(_) => {
                info!("Successfully configured node {} for open access", node_name);
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to configure node {} for open access: {}",
                    node_name, e
                );
                // Don't fail the entire operation if configuration fails
                Ok(())
            }
        }
    }
}
