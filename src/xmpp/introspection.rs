// XMPP Introspection and XML Inspection utilities for Sermo
// Contains XML inspection, introspection, and OMEMO stanza verification helpers

use log::{debug, trace, info, error};
use tokio::sync::mpsc;
use std::sync::RwLock;
use std::collections::VecDeque;
use xmpp_parsers::Element;
use base64::Engine;

// For OMEMO stanza verification
use crate::xmpp::custom_ns;

// XML Inspector state
lazy_static::lazy_static! {
    static ref INSPECTORS: RwLock<Vec<mpsc::Sender<String>>> = RwLock::new(Vec::new());
    static ref RECENT_STANZAS: RwLock<VecDeque<String>> = RwLock::new(VecDeque::with_capacity(20));
}

/// Register an XML inspector to receive stanzas
pub fn register_inspector(tx: mpsc::Sender<String>) {
    if let Ok(mut inspectors) = INSPECTORS.write() {
        info!("Registering XML inspector");
        inspectors.push(tx.clone());
        let stanzas_to_send = if let Ok(recent_stanzas) = RECENT_STANZAS.read() {
            recent_stanzas.iter().cloned().collect::<Vec<String>>()
        } else {
            Vec::new()
        };
        if !stanzas_to_send.is_empty() {
            info!("Sending {} buffered stanzas to new inspector", stanzas_to_send.len());
            tokio::spawn(async move {
                for stanza in stanzas_to_send {
                    if let Err(e) = tx.send(stanza).await {
                        trace!("Failed to send buffered stanza to inspector: {}", e.to_string());
                        break;
                    }
                }
            });
        }
    } else {
        error!("Failed to acquire write lock for XML inspectors");
    }
}

/// Unregister an XML inspector
pub fn unregister_inspector(tx: &mpsc::Sender<String>) {
    if let Ok(mut inspectors) = INSPECTORS.write() {
        inspectors.retain(|i| !std::ptr::eq(i, tx));
        //debug!("Unregistered XML inspector. Remaining inspectors: {}", inspectors.len());
    } else {
        //debug!("Failed to acquire write lock for XML inspectors");
    }
}

/// Inspect outbound XML stanzas
pub fn inspect_outbound_xml(xml: &str) {
    trace!("OUTBOUND XML: {}", xml);
    if let Ok(mut recent_stanzas) = RECENT_STANZAS.write() {
        recent_stanzas.push_back(xml.to_string());
        if recent_stanzas.len() > 20 {
            recent_stanzas.pop_front();
        }
    }
    let has_inspectors = if let Ok(inspectors) = INSPECTORS.read() {
        !inspectors.is_empty()
    } else {
        false
    };
    if has_inspectors {
        if let Ok(inspectors) = INSPECTORS.read() {
            let xml_cloned = xml.to_string();
            let senders = inspectors.iter().cloned().collect::<Vec<_>>();
            info!("Sending XML to {} inspectors", senders.len());
            tokio::spawn(async move {
                for tx in senders {
                    let xml_clone = xml_cloned.clone();
                    info!("Sending XML to inspector: {}", xml_clone.chars().take(50).collect::<String>());
                    if let Err(e) = tx.send(xml_clone).await {
                        error!("Failed to send XML to inspector: {}", e);
                    } else {
                        info!("Successfully sent XML to inspector");
                    }
                }
            });
        }
    } else {
        //debug!("No XML inspectors registered, but stanza was buffered");
    }
}

/// Inspect inbound XML stanzas
pub fn inspect_inbound_xml(xml: &str) {
    trace!("INBOUND XML: {}", xml);
    // Currently only handling outbound for testing purposes
}

/// Helper function to convert Element to String
pub fn stanza_to_string(stanza: &Element) -> String {
    // Convert Element to actual XML string instead of debug format
    let mut xml_bytes = Vec::new();
    if let Err(e) = stanza.write_to(&mut xml_bytes) {
        error!("Failed to serialize stanza to XML: {}", e);
        // Fallback to debug format if serialization fails
        return format!("{:?}", stanza);
    }
    
    match String::from_utf8(xml_bytes) {
        Ok(xml_string) => xml_string,
        Err(e) => {
            error!("Failed to convert XML bytes to string: {}", e);
            // Fallback to debug format if conversion fails
            format!("{:?}", stanza)
        }
    }
}

/// Helper function to verify OMEMO stanza structure
pub fn verify_omemo_stanza(stanza: &Element, content: &str) -> Result<(), String> {
    //debug!("Starting OMEMO stanza verification...");
    //debug!("Stanza name: {}, namespace: {}", stanza.name(), stanza.ns());
    let stanza_str = format!("{:?}", stanza);
    if stanza_str.contains(content) {
        error!("SECURITY VIOLATION: Plaintext content found in encrypted message");
        return Err(format!("SECURITY VIOLATION: Plaintext content found in encrypted message"));
    }
    let mut missing_elements = Vec::new();
    if stanza.name() != "message" || stanza.ns() != "jabber:client" {
        missing_elements.push("message element with jabber:client namespace");
        error!("Message element namespace issue: expected 'jabber:client', got '{}'", stanza.ns());
        return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", missing_elements.join(", ")));
    }
    
    trace!("Message attributes:");
    for (name, value) in stanza.attrs() {
        trace!("  - {}: {}", name, value);
    }
    // Check for encrypted element with either the standard or legacy OMEMO namespace
    let encrypted = match stanza.get_child("encrypted", custom_ns::OMEMO) {
        Some(elem) => {
            //debug!("Found encrypted element with standard OMEMO namespace: {}", elem.ns());
            elem
        },
        None => {
            // Try with the legacy namespace
            match stanza.get_child("encrypted", custom_ns::OMEMO_V1) {
                Some(elem) => {
                    //debug!("Found encrypted element with legacy OMEMO namespace: {}", elem.ns());
                    elem
                },
                None => {
                    // Try with the namespace from the element itself
                    match stanza.children().find(|e| e.name() == "encrypted") {
                        Some(elem) => {
                            debug!("Found encrypted element with namespace: {}", elem.ns());
                            elem
                        },
                        None => {
                            error!("Missing encrypted element with proper namespace");
                            //debug!("Direct children of message element:");
                            for _child in stanza.children() {
                                //debug!("  - {} (ns: {})", child.name(), child.ns());
                            }
                            missing_elements.push("OMEMO namespace, encrypted element");
                            return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", missing_elements.join(", ")));
                        }
                    }
                }
            }
        }
    };
    // Check for header element with either namespace or empty namespace (inherited)
    let header = match encrypted.get_child("header", custom_ns::OMEMO) {
        Some(elem) => {
            //debug!("Found header element with explicit standard OMEMO namespace: {}", elem.ns());
            elem
        },
        None => {
            match encrypted.get_child("header", custom_ns::OMEMO_V1) {
                Some(elem) => {
                    //debug!("Found header element with explicit legacy OMEMO namespace: {}", elem.ns());
                    elem
                },
                None => {
                    match encrypted.get_child("header", "") {
                        Some(elem) => {
                            //debug!("Found header element with inherited namespace from parent: {}", elem.ns());
                            elem
                        },
                        None => {
                            error!("Missing header element in encrypted element");
                            //debug!("Direct children of encrypted element:");
                            for _child in encrypted.children() {
                                //debug!("  - {} (ns: {})", child.name(), child.ns());
                            }
                            missing_elements.push("header element");
                            return Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", missing_elements.join(", ")));
                        }
                    }
                }
            }
        }
    };
    if let Some(_sid) = header.attr("sid") {
        //debug!("Found sender device ID: {}", sid);
    } else {
        error!("Missing sender device ID in header element");
        missing_elements.push("sender device ID");
    }
    // Check for IV element with any of the possible namespaces
    let iv = header.get_child("iv", custom_ns::OMEMO)
        .or_else(|| header.get_child("iv", custom_ns::OMEMO_V1))
        .or_else(|| header.get_child("iv", ""));
    if let Some(iv_elem) = iv {
        //debug!("Found IV element with namespace: {}", iv_elem.ns());
        let iv_text = iv_elem.text();
        //debug!("IV content length: {}", iv_text.len());
        match base64::engine::general_purpose::STANDARD.decode(iv_text.trim()) {
            Ok(decoded) => debug!("Valid base64 IV content, decoded length: {} bytes", decoded.len()),
            Err(e) => error!("Invalid base64 in IV element: {}", e),
        }
    } else {
        error!("Missing initialization vector (iv) element in header");
        //debug!("Header children:");
        for _child in header.children() {
            //debug!("  - {} (ns: {})", child.name(), child.ns());
        }
        missing_elements.push("initialization vector");
    }
    let key_elements: Vec<_> = header.children()
        .filter(|child| child.name() == "key")
        .collect();
    if key_elements.is_empty() {
        error!("No key elements found in header");
        missing_elements.push("encrypted key");
    } else {
        //debug!("Found {} key elements", key_elements.len());
        for (_i, key) in key_elements.iter().enumerate() {
            let _rid = key.attr("rid").unwrap_or("missing-rid");
            //debug!("Key {}: rid={}, namespace={}, content_length={}", i, rid, key.ns(), key.text().len());
            match base64::engine::general_purpose::STANDARD.decode(key.text().trim()) {
                Ok(decoded) => debug!("Valid base64 key content, decoded length: {} bytes", decoded.len()),
                Err(e) => error!("Invalid base64 in key element: {}", e),
            }
        }
    }
    // Check for payload element with any of the possible namespaces
    let payload = encrypted.get_child("payload", custom_ns::OMEMO)
        .or_else(|| encrypted.get_child("payload", custom_ns::OMEMO_V1))
        .or_else(|| encrypted.get_child("payload", ""));
    if let Some(payload_elem) = payload {
        //debug!("Found payload element with namespace: {}", payload_elem.ns());
        let payload_text = payload_elem.text();
        //debug!("Payload content length: {}", payload_text.len());
        match base64::engine::general_purpose::STANDARD.decode(payload_text.trim()) {
            Ok(decoded) => debug!("Valid base64 payload content, decoded length: {} bytes", decoded.len()),
            Err(e) => error!("Invalid base64 in payload element: {}", e),
        }
    } else {
        error!("Missing payload element in encrypted element");
        trace!("Encrypted element children:");
        for child in encrypted.children() {
            trace!("  - {} (ns: {})", child.name(), child.ns());
        }
        missing_elements.push("encrypted payload");
    }
    if missing_elements.is_empty() {
        //debug!("OMEMO stanza verification successful - all required elements present");
        Ok(())
    } else {
        error!("OMEMO stanza verification failed - missing elements: {}", missing_elements.join(", "));
        Err(format!("SECURITY VIOLATION: Message missing required OMEMO elements: {}", missing_elements.join(", ")))
    }
}
