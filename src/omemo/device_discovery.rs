// src/omemo/device_discovery.rs
//! OMEMO device discovery utilities
//!
//! This module provides enhanced device discovery functionality for OMEMO encryption.
//! It includes various methods for fetching and parsing device lists from different
//! XMPP server implementations, accounting for variations in how servers implement
//! the XEP-0384 specification.

use anyhow::Result;
use log::{debug, error, info, warn};
use tokio::time::timeout;
use tokio::time::Duration;

use crate::omemo::OmemoError;
use crate::omemo::device_id::DeviceId;
use crate::omemo::OMEMO_NAMESPACE;

/// Default timeout for device list retrieval
const DEVICE_LIST_TIMEOUT_SECS: u64 = 5;

/// Static function to parse device list response without requiring locks
/// This is a duplicate of the logic in OmemoManager to avoid deadlock situations
fn parse_device_list_response_static(response: &str) -> Result<Vec<u32>, OmemoError> {
    debug!("Static parsing device list response - starting");
    debug!("Raw XML response (first 500 chars): {}", 
           if response.len() > 500 { &response[..500] } else { response });
    
    // Check if the response is empty or whitespace only
    if response.trim().is_empty() {
        debug!("Empty response received, returning empty device list");
        return Ok(Vec::new());
    }
    
    // Check for item-not-found error before attempting to parse
    if response.contains("item-not-found") {
        debug!("Response contains 'item-not-found', returning empty device list");
        return Ok(Vec::new());
    }
    
    debug!("Static parsing device list response - starting XML parsing");
    
    // Parse the XML response
    let document = match roxmltree::Document::parse(response) {
        Ok(doc) => doc,
        Err(e) => {
            error!("Failed to parse device list XML: {}", e);
            return Err(OmemoError::ProtocolError(format!("XML parsing error: {}", e)));
        }
    };
    
    debug!("Static parsing device list response - XML parsed successfully, checking for errors");
    
    // Check for error responses first
    if let Some(error) = document.descendants().find(|n| n.has_tag_name("error")) {
        let error_type = error.attribute("type").unwrap_or("unknown");
        
        // Find the error condition
        let error_condition = error.children()
            .find(|n| n.is_element() && n.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas"))
            .map(|n| n.tag_name().name())
            .unwrap_or("unknown");
        
        warn!("Error in device list response: type={}, condition={}", error_type, error_condition);
        
        match error_condition {
            "item-not-found" => {
                // This means no device list exists yet, return empty list
                debug!("No device list found (item-not-found)");
                return Ok(Vec::new());
            },
            _ => {
                return Err(OmemoError::ProtocolError(
                    format!("XMPP error in device list response: {}", error_condition)
                ));
            }
        }
    }
    
    debug!("Static parsing device list response - no errors found, extracting device IDs");
    
    // Extract device IDs from the response
    let mut device_ids = Vec::new();
    
    // Approach 1: Find <list> element by namespace
    let list_elements: Vec<_> = document.descendants()
        .filter(|n| n.has_tag_name("list") && 
              (n.attribute("xmlns") == Some(OMEMO_NAMESPACE) || 
               n.tag_name().namespace() == Some(OMEMO_NAMESPACE)))
        .collect();
    
    if !list_elements.is_empty() {
        debug!("Found {} list elements with OMEMO namespace", list_elements.len());
        
        for list in list_elements {
            for device in list.children().filter(|n| n.has_tag_name("device") && n.has_attribute("id")) {
                if let Some(id_str) = device.attribute("id") {
                    if let Ok(id) = id_str.parse::<u32>() {
                        debug!("Found device ID: {}", id);
                        if !device_ids.contains(&id) {
                            device_ids.push(id);
                        }
                    } else {
                        warn!("Invalid device ID '{}' in device list", id_str);
                    }
                }
            }
        }
    } else {
        // Approach 2: Try to find <list> inside <item id='current'> (PubSub format)
        debug!("No direct list elements found, trying PubSub item structure");
        
        let item_elements: Vec<_> = document.descendants()
            .filter(|n| n.has_tag_name("item") && n.attribute("id") == Some("current"))
            .collect();
        
        if !item_elements.is_empty() {
            debug!("Found {} item elements with id='current'", item_elements.len());
            
            for item in item_elements {
                if let Some(list) = item.children().find(|n| n.has_tag_name("list")) {
                    for device in list.children().filter(|n| n.has_tag_name("device") && n.has_attribute("id")) {
                        if let Some(id_str) = device.attribute("id") {
                            if let Ok(id) = id_str.parse::<u32>() {
                                debug!("Found device ID: {}", id);
                                if !device_ids.contains(&id) {
                                    device_ids.push(id);
                                }
                            } else {
                                warn!("Invalid device ID '{}' in device list", id_str);
                            }
                        }
                    }
                }
            }
        } else {
            // Approach 3: Search any <device> elements with "id" attributes anywhere
            debug!("No PubSub item structure found, looking for any device elements");
            
            for device in document.descendants().filter(|n| n.has_tag_name("device") && n.has_attribute("id")) {
                if let Some(id_str) = device.attribute("id") {
                    if let Ok(id) = id_str.parse::<u32>() {
                        debug!("Found device ID: {}", id);
                        if !device_ids.contains(&id) {
                            device_ids.push(id);
                        }
                    } else {
                        warn!("Invalid device ID '{}' in device list", id_str);
                    }
                }
            }
        }
    }
    
    // If we found device IDs with any approach, return them
    if !device_ids.is_empty() {
        info!("Found {} OMEMO device IDs: {:?}", device_ids.len(), device_ids);
        return Ok(device_ids);
    }
    
    // If we reach here, we found no device IDs. This could mean no devices exist yet
    // Return an empty list as this is a valid state for a new user
    debug!("No device IDs found in response, returning empty list");
    Ok(Vec::new())
}

/// Known OMEMO namespace variations
pub const OMEMO_NAMESPACES: [&str; 1] = [
    "eu.siacs.conversations.axolotl"    // Legacy namespace that actually works
];

/// Known node format patterns
pub const NODE_FORMATS: [&str; 8] = [
    "{}.devicelist",        // Dino/Conversations format (dot + devicelist)
    "{}:devices",           // Standard format with colon (XEP-0384)
    "{}devices",            // No separator
    "{}/devices",           // Slash separator
    "{}:devicelist",        // Legacy format used by some implementations
    "{}/devicelist",        // Slash separator with legacy name
    "{}.devices",           // Dot separator with devices
    "{}",                   // Just the namespace (some servers)
];

/// Attempt to fetch a device list using multiple namespace and node format combinations
pub async fn fetch_device_list_with_fallbacks(jid: &str) -> Result<Vec<DeviceId>, OmemoError> {
    info!("[OMEMO] Attempting to fetch OMEMO device list for {} with fallbacks", jid);
    
    // Try to get the client and omemo manager
    let client_opt = crate::xmpp::get_global_xmpp_client().await;
    let client = match client_opt {
        Some(c) => c,
        None => return Err(OmemoError::MissingDataError("No XMPP client available".to_string())),
    };
    
    let omemo_manager_opt = crate::xmpp::XMPPClient::get_global_omemo_manager().await;
    let omemo_manager = match omemo_manager_opt {
        Some(m) => m,
        None => return Err(OmemoError::MissingDataError("No OMEMO manager available".to_string())),
    };
    
    let client_guard = client.lock().await;
    let mut combined_devices = Vec::new();
    let mut any_success = false;
    
    // Try each namespace
    for namespace in &OMEMO_NAMESPACES {
        debug!("[OMEMO] Trying with namespace: {}", namespace);
        
        // Track if we got any valid response (even empty) for this namespace
        let mut namespace_had_valid_response = false;
        
        // Try each node format
        for format in &NODE_FORMATS {
            let node = format.replace("{}", namespace);
            debug!("[OMEMO] Attempting to fetch device list with node: {}", node);
            
            // Set a timeout to avoid hanging on unresponsive servers
            match timeout(
                Duration::from_secs(DEVICE_LIST_TIMEOUT_SECS), 
                client_guard.request_pubsub_items(jid, &node)
            ).await {
                Ok(Ok(xml)) => {
                    debug!("[OMEMO] Got response for node {}, parsing...", node);
                    
                    // Parse directly without acquiring lock (avoid deadlock)
                    let parsed_devices = parse_device_list_response_static(&xml);
                    
                    match parsed_devices {
                        Ok(devices) if !devices.is_empty() => {
                            info!("[OMEMO] Found {} devices using node {}", devices.len(), node);
                            
                            // Add any new devices to our combined list
                            for device_id in devices {
                                if !combined_devices.contains(&device_id) {
                                    combined_devices.push(device_id);
                                }
                            }
                            
                            any_success = true;
                            
                            // Return immediately when we find devices to avoid unnecessary delays
                            drop(client_guard);
                            info!("[OMEMO] Successfully found devices for {}: {:?}", jid, combined_devices);
                            return Ok(combined_devices);
                        },
                        Ok(_) => {
                            debug!("[OMEMO] No devices found with node {} (empty list or item-not-found)", node);
                            // This is a valid response but with no devices - continue to next namespace
                            namespace_had_valid_response = true;
                        },
                        Err(e) => {
                            debug!("[OMEMO] Error parsing device list response from node {}: {}", node, e);
                            
                            // If we get feature-not-implemented, the server doesn't support OMEMO at all
                            // Stop trying and return empty list immediately
                            if e.to_string().contains("feature-not-implemented") {
                                warn!("[OMEMO] Server {} doesn't support OMEMO (feature-not-implemented)", jid);
                                drop(client_guard);
                                return Ok(Vec::new());
                            }
                        }
                    }
                },
                Ok(Err(e)) => {
                    debug!("[OMEMO] Failed to fetch from node {}: {}", node, e);
                    
                    // If we get feature-not-implemented, the server doesn't support OMEMO at all
                    // Stop trying and return empty list immediately
                    if e.to_string().contains("feature-not-implemented") {
                        warn!("[OMEMO] Server {} doesn't support OMEMO (feature-not-implemented)", jid);
                        drop(client_guard);
                        return Ok(Vec::new());
                    }
                },
                Err(_) => {
                    debug!("[OMEMO] Timeout while fetching from node {}", node);
                }
            }
        }
        
        // If this namespace had a valid response but no devices, we tried the server
        // and it doesn't have devices for this namespace - continue to the next one
        if namespace_had_valid_response {
            debug!("[OMEMO] Namespace {} had valid response but no devices, trying next namespace", namespace);
        }
    }
    
    // If we found any devices with any of the methods, return them
    if any_success {
        // Sort for consistent order
        combined_devices.sort();
        info!("[OMEMO] Combined device list after trying all methods: {:?}", combined_devices);
        return Ok(combined_devices);
    }
    
    // If we didn't find any devices, try the standard node as a final attempt
    let standard_node = format!("{}:devices", OMEMO_NAMESPACE);
    match client_guard.request_pubsub_items(jid, &standard_node).await {
        Ok(xml) => {
            let parsed_devices = {
                let manager_guard = omemo_manager.lock().await;
                manager_guard.parse_device_list_response(&xml)
            };
            if let Ok(devices) = parsed_devices {
                if !devices.is_empty() {
                    return Ok(devices);
                }
            }
        },
        Err(e) => {
            // Try legacy format as final attempt
            let legacy_node = format!("{}:devicelist", OMEMO_NAMESPACE);
            match client_guard.request_pubsub_items(jid, &legacy_node).await {
                Ok(xml) => {
                    let parsed_devices = {
                        let manager_guard = omemo_manager.lock().await;
                        manager_guard.parse_device_list_response(&xml)
                    };
                    if let Ok(devices) = parsed_devices {
                        if !devices.is_empty() {
                            return Ok(devices);
                        }
                    }
                },
                Err(e_legacy) => {
                    warn!("[OMEMO] Final attempts to fetch device list failed: {} and {}", e, e_legacy);
                }
            }
        }
    }
    
    // If we still have no devices, try an additional fallback for servers that might store
    // device information under a different node or using a different format
    // This could involve checking the vcard, looking for a specific feature, or other custom logic
    
    // For now, as a last resort, we'll try to fetch bundle information for device ID 1
    // Many clients use device ID 1 as their first/primary device
    try_fetch_bundle_for_common_device_ids(jid, &client_guard).await
}

/// Try to fetch bundles for common device IDs as a last resort
async fn try_fetch_bundle_for_common_device_ids(
    jid: &str, 
    client_guard: &crate::xmpp::XMPPClient
) -> Result<Vec<DeviceId>, OmemoError> {
    let common_device_ids = [1, 2, 3, 4, 5]; // Most common device IDs
    let mut found_devices = Vec::new();
    
    for &device_id in &common_device_ids {
        let bundle_node = format!("{}.bundles:{}", OMEMO_NAMESPACE, device_id);
        match client_guard.request_pubsub_items(jid, &bundle_node).await {
            Ok(_) => {
                // If we can fetch a bundle, this device likely exists
                info!("[OMEMO] Found device {} for {} by directly checking bundle", device_id, jid);
                found_devices.push(device_id);
            },
            Err(_) => {
                // Try alternative format (legacy with colon)
                let alt_bundle_node = format!("{}:bundles:{}", OMEMO_NAMESPACE, device_id);
                if let Ok(_) = client_guard.request_pubsub_items(jid, &alt_bundle_node).await {
                    info!("[OMEMO] Found device {} for {} by checking legacy bundle format", device_id, jid);
                    found_devices.push(device_id);
                }
            }
        }
    }
    
    if !found_devices.is_empty() {
        info!("[OMEMO] Found devices by checking bundles directly: {:?}", found_devices);
        return Ok(found_devices);
    }
    
    // If we still have no devices, return an empty list
    // This will let the client show an appropriate error
    Err(OmemoError::NoDeviceError(format!("No OMEMO devices found for {}", jid)))
}
