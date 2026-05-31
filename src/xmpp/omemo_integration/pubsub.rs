use anyhow::{anyhow, Result};
use log::{error, info, warn};
use tokio::time::Duration;
use uuid::Uuid;

use crate::omemo::device_id::DeviceId;
use crate::xmpp::transport::{self, StanzaTx};

use super::PubSubResponses;

/// Publish an item to a PubSub node (for OMEMO implementation)
/// This function is called by the OMEMO manager to publish key bundles and device lists
pub async fn publish_pubsub_item(
    _to: Option<&str>,
    _node: &str,
    _id: &str,
    _payload: &str,
) -> Result<()> {
    // Legacy wrapper — uses the PUBSUB_RESPONSES global to find the client
    // The bridge path (publish_pubsub_item_with_client) is preferred
    error!("publish_pubsub_item called without explicit client — this path is deprecated");
    Err(anyhow!("No client available (legacy global path removed)"))
}

/// Publish an item to a PubSub node using an explicit client reference
pub async fn publish_pubsub_item_with_client(
    stanza_tx: &StanzaTx,
    to: Option<&str>,
    node: &str,
    id: &str,
    payload: &str,
) -> Result<()> {
    info!("PubSub payload: {}", payload);
    
    {
            // Generate a unique IQ ID different from the item ID
            let iq_id = Uuid::new_v4().to_string();
            
            // Check which type of OMEMO item we're publishing
            let is_devicelist = node.contains("devicelist");
            let is_bundle = node.contains("bundles");
            
            // If we're publishing a device list, we need to handle it specially due to namespace issues
            if is_devicelist {
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
                
                // Create the device list stanza correctly
                let iq = xmpp_parsers::Element::builder("iq", "jabber:client")
                    .attr("type", "set")
                    .attr("id", &iq_id)
                    .attr("to", to.unwrap_or(""))
                    .append(
                        xmpp_parsers::Element::builder("pubsub", "http://jabber.org/protocol/pubsub")
                            .append(
                                xmpp_parsers::Element::builder("publish", "http://jabber.org/protocol/pubsub")
                                    .attr("node", node)
                                    .append(
                                        xmpp_parsers::Element::builder("item", "http://jabber.org/protocol/pubsub")
                                            .attr("id", id)
                                            .append(
                                                {
                                                    let mut list_elem = xmpp_parsers::Element::builder("list", "eu.siacs.conversations.axolotl").build();
                                                    
                                                    // Add each device with the proper namespace handling
                                                    for device_id in device_ids {
                                                        let device_elem = xmpp_parsers::Element::builder("device", "")
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
                
                // Send the stanza
                match transport::send_stanza(stanza_tx, iq) {
                    Ok(_) => {
                        return Ok(());
                    },
                    Err(e) => {
                        error!("Failed to send device list stanza: {}", e);
                        return Err(anyhow!("Failed to send device list stanza: {}", e));
                    }
                }
            } else if is_bundle {
                // Handle bundle publishing with proper XML preservation
                
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
                match transport::send_stanza(stanza_tx, iq) {
                    Ok(_) => {
                        return Ok(());
                    },
                    Err(e) => {
                        error!("Failed to send bundle stanza: {}", e);
                        
                        // If the error contains "invalid-item" or "bad-request", try the alternative format
                        if e.to_string().contains("invalid-item") || e.to_string().contains("bad-request") {
                            warn!("Received bad-request error, trying alternative bundle format");
                            return publish_bundle_alternative_format_with_client(stanza_tx, to, node, id, payload).await;
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
                .attr("id", &iq_id)
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
            match transport::send_stanza(stanza_tx, iq) {
                Ok(_) => {
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to send PubSub stanza: {}", e);
                    Err(anyhow!("Failed to send PubSub stanza: {}", e))
                }
            }
    }
}

/// Alternative format for publishing bundles when the standard format fails
/// This function is public so it can be called from the bundle.rs module
pub async fn publish_bundle_alternative_format(
    _to: Option<&str>,
    _node: &str,
    _id: &str,
    _payload: &str,
) -> Result<()> {
    error!("publish_bundle_alternative_format called without explicit client — this path is deprecated");
    Err(anyhow!("No client available (legacy global path removed)"))
}

/// Alternative format for publishing bundles — uses explicit client reference
pub async fn publish_bundle_alternative_format_with_client(
    stanza_tx: &StanzaTx,
    to: Option<&str>,
    node: &str,
    id: &str,
    payload: &str,
) -> Result<()> {
    {
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
            match transport::send_stanza(stanza_tx, iq) {
                Ok(_) => {
                    info!("Alternative bundle format published successfully");
                    Ok(())
                },
                Err(e) => {
                    error!("Failed to send alternative bundle format: {}", e);
                    Err(anyhow!("Failed to send alternative bundle format: {}", e))
                }
            }
    }
}

/// Alternative format for publishing items when the standard format fails
fn publish_item_alternative_format(
    stanza_tx: &StanzaTx,
    to: Option<&str>,
    node: &str,
    id: &str,
    payload: &str,
) -> Result<()> {
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
    match transport::send_stanza(stanza_tx, iq) {
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
    _device_ids: &[DeviceId]
) -> Result<()> {
    error!("publish_pubsub_item_device_list called without explicit client — this path is deprecated");
    Err(anyhow!("No client available (legacy global path removed)"))
}

/// Publish a PubSub item in the correct format for OMEMO device lists — uses explicit client
pub async fn publish_pubsub_item_device_list_with_client(
    stanza_tx: &StanzaTx,
    device_ids: &[DeviceId]
) -> Result<()> {
    {
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
                .attr("node", "eu.siacs.conversations.axolotl.devicelist")
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
            match transport::send_stanza(stanza_tx, iq) {
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
                        
                        return publish_item_alternative_format(stanza_tx, None, "eu.siacs.conversations.axolotl.devicelist", "current", &list_xml).map_err(|e| anyhow!("Alternative format failed: {}", e));
                    }
                    
                    Err(anyhow!("Failed to send device list publish stanza: {}", e))
                }
            }
    }
}

/// Request items from a PubSub node (for OMEMO implementation)
/// This function is called by the OMEMO manager to fetch device lists and bundles
pub async fn request_pubsub_items(
    _from: &str,
    _node: &str,
) -> Result<String> {
    error!("request_pubsub_items called without explicit client — this path is deprecated");
    Err(anyhow!("No client available (legacy global path removed)"))
}

/// Request items from a PubSub node — uses explicit client and response map
pub async fn request_pubsub_items_with_client(
    stanza_tx: &StanzaTx,
    responses_map: &PubSubResponses,
    from: &str,
    node: &str,
) -> Result<String> {
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
    if let Err(e) = transport::send_stanza(stanza_tx, iq) {
        error!("Failed to send PubSub request: {}", e);
        return Err(anyhow!("Failed to send PubSub request: {}", e));
    }
    
    // Wait for the response with a timeout
    let timeout = Duration::from_secs(10);
    let start_time = tokio::time::Instant::now();
    
    while tokio::time::Instant::now().duration_since(start_time) < timeout {
        // Check if we have the response in our map
        if let Some(response) = get_pubsub_response_from(responses_map, &request_id).await {
            return Ok(response);
        }
        
        // Sleep briefly before checking again
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    // Clean up: remove the entry in case a late response arrives after we give up
    get_pubsub_response_from(responses_map, &request_id).await;
    
    error!("Timeout waiting for PubSub response for request {}", request_id);
    Err(anyhow!("Timeout waiting for PubSub response"))
}

/// Store a pubsub response into a specific response map
pub async fn store_pubsub_response_to(responses_map: &PubSubResponses, request_id: String, xml_response: String) {
    let mut responses = responses_map.lock().await;
    // Cap the map size to prevent unbounded growth from orphaned responses
    if responses.len() > 100 {
        // Remove some old entries (HashMap order is arbitrary but sufficient for eviction)
        let keys_to_remove: Vec<String> = responses.keys().take(20).cloned().collect();
        for key in keys_to_remove {
            responses.remove(&key);
        }
    }
    responses.insert(request_id, xml_response);
}

/// Retrieve a pubsub response from a specific response map
pub async fn get_pubsub_response_from(responses_map: &PubSubResponses, request_id: &str) -> Option<String> {
    let mut responses = responses_map.lock().await;
    responses.remove(request_id)
}

/// Convert an Element to XML string
pub fn element_to_xml_string(element: &xmpp_parsers::Element) -> String {
    // Convert to proper XML string manually since Element doesn't implement Display
    fn element_to_xml_recursive(element: &xmpp_parsers::Element) -> String {
        let mut xml = String::new();
        
        // Start tag with namespace
        xml.push('<');
        xml.push_str(element.name());
        
        // Add namespace if present
        if !element.ns().is_empty() {
            xml.push_str(&format!(" xmlns=\"{}\"", element.ns()));
        }
        
        // Add attributes
        for (name, value) in element.attrs() {
            xml.push_str(&format!(" {}=\"{}\"", name, value));
        }
        xml.push('>');
        
        // Add text content
        let text_content = element.text();
        if !text_content.is_empty() {
            xml.push_str(&text_content);
        }
        
        // Add child elements
        for child in element.children() {
            xml.push_str(&element_to_xml_recursive(child));
        }
        
        // End tag
        xml.push_str("</");
        xml.push_str(element.name());
        xml.push('>');
        
        xml
    }
    
    element_to_xml_recursive(element)
}
