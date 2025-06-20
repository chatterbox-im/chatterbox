// src/omemo/device_discovery.rs
//! OMEMO device discovery utilities
//!
//! This module provides enhanced device discovery functionality for OMEMO encryption.
//! It includes various methods for fetching and parsing device lists from different
//! XMPP server implementations, accounting for variations in how servers implement
//! the XEP-0384 specification.

use anyhow::Result;
use log::{debug, info, warn};
use tokio::time::timeout;
use tokio::time::Duration;

use crate::omemo::OmemoError;
use crate::omemo::device_id::DeviceId;
use crate::omemo::OMEMO_NAMESPACE;

/// Default timeout for device list retrieval
const DEVICE_LIST_TIMEOUT_SECS: u64 = 5;

/// Known OMEMO namespace variations
pub const OMEMO_NAMESPACES: [&str; 2] = [
    "eu.siacs.conversations.axolotl",   // Original/legacy namespace
    "urn:xmpp:omemo:1"                  // Official XEP-0384 namespace
];

/// Known node format patterns
pub const NODE_FORMATS: [&str; 6] = [
    "{}:devices",           // Standard format with colon (XEP-0384)
    "{}devices",            // No separator
    "{}/devices",           // Slash separator
    "{}:devicelist",        // Legacy format used by some implementations
    "{}/devicelist",        // Slash separator with legacy name
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
                    
                    // Parse with the OMEMO manager
                    let manager_guard = omemo_manager.lock().await;
                    match manager_guard.parse_device_list_response(&xml).await {
                        Ok(devices) if !devices.is_empty() => {
                            info!("[OMEMO] Found {} devices using node {}", devices.len(), node);
                            
                            // Add any new devices to our combined list
                            for device_id in devices {
                                if !combined_devices.contains(&device_id) {
                                    combined_devices.push(device_id);
                                }
                            }
                            
                            any_success = true;
                        },
                        Ok(_) => {
                            debug!("[OMEMO] No devices found with node {}", node);
                        },
                        Err(e) => {
                            debug!("[OMEMO] Error parsing device list response from node {}: {}", node, e);
                        }
                    }
                },
                Ok(Err(e)) => {
                    debug!("[OMEMO] Failed to fetch from node {}: {}", node, e);
                },
                Err(_) => {
                    debug!("[OMEMO] Timeout while fetching from node {}", node);
                }
            }
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
            let manager_guard = omemo_manager.lock().await;
            if let Ok(devices) = manager_guard.parse_device_list_response(&xml).await {
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
                    let manager_guard = omemo_manager.lock().await;
                    if let Ok(devices) = manager_guard.parse_device_list_response(&xml).await {
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
        let bundle_node = format!("{}:bundles:{}", OMEMO_NAMESPACE, device_id);
        match client_guard.request_pubsub_items(jid, &bundle_node).await {
            Ok(_) => {
                // If we can fetch a bundle, this device likely exists
                info!("[OMEMO] Found device {} for {} by directly checking bundle", device_id, jid);
                found_devices.push(device_id);
            },
            Err(_) => {
                // Try alternative format
                let alt_bundle_node = format!("{}bundles:{}", OMEMO_NAMESPACE, device_id);
                if let Ok(_) = client_guard.request_pubsub_items(jid, &alt_bundle_node).await {
                    info!("[OMEMO] Found device {} for {} by checking alternative bundle format", device_id, jid);
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
