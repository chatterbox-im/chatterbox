use anyhow::{anyhow, Result};
use log::{debug, error, info, warn, trace};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};

use xmpp_parsers::BareJid as JidBare;
use tokio_xmpp::Element;

use crate::omemo::{OmemoManager, OMEMO_NAMESPACE};
use crate::omemo::crypto;
use crate::omemo::OmemoError;

/// Handle an incoming OMEMO message
pub async fn handle_omemo_message(
    manager: Arc<TokioMutex<OmemoManager>>,
    sender: &str,
    stanza: &str,
) -> Result<String> {
    // Parse the stanza to extract the OMEMO message
    let message = {
        let manager_guard = manager.lock().await;
        manager_guard.process_message_xml(stanza)?
    };
    
    // Extract the sender device ID
    let device_id = message.sender_device_id;
    
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

/// Publish device list to the XMPP server (fetches existing list and merges our device ID)
pub async fn publish_device_list(
    manager: Arc<TokioMutex<OmemoManager>>,
    _xmpp_client: &impl XmppClient,
) -> Result<()> {
    let manager_guard = manager.lock().await;
    manager_guard.ensure_device_list_published().await
        .map_err(|e| anyhow::anyhow!("Failed to publish device list: {}", e))
}

/// Publish key bundle to the XMPP server
pub async fn publish_key_bundle(
    manager: Arc<TokioMutex<OmemoManager>>,
    xmpp_client: &impl XmppClient,
) -> Result<()> {
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

/// Parse the IV from an OMEMO header
pub fn parse_iv_from_header(header: &Element) -> Result<Vec<u8>, OmemoError> {
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
    
    trace!("IV: {}", hex::encode(&iv));
    
    Ok(iv)
}

/// Add IV to an OMEMO header
pub fn add_iv_to_header(header: &mut Element, iv: &[u8]) -> Result<(), OmemoError> {
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
    
    Ok(())
}

/// Create an OMEMO header for a message
pub fn create_omemo_header(
    sender_device_id: u32,
    _recipient_devices: &[(JidBare, u32)],
    iv: &[u8],
    keys: &[(u32, Vec<u8>)],
) -> Result<Element, OmemoError> {
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

/// Process an incoming OMEMO encrypted message
pub async fn process_incoming_omemo_message(
    from_jid: &JidBare,
    encrypted_element: &Element,
    omemo: &mut OmemoManager,
) -> Result<Option<Vec<u8>>, OmemoError> {
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
    
    Ok(Some(plaintext))
}
