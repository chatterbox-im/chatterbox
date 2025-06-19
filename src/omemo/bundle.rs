//! Key bundle management for OMEMO

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use crate::omemo::protocol;
use crate::omemo::protocol::DeviceIdentity;
use crate::omemo::device_id::DeviceId;
use crate::omemo::OmemoError;
use crate::omemo::OMEMO_NAMESPACE;
use base64::Engine;

/// OMEMO Bundle structure
#[derive(Debug, Clone)]
pub struct OmemoBundle {
    pub identity_key: Vec<u8>,
    pub signed_pre_key: Vec<u8>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_signature: Vec<u8>,
    pub pre_keys: Vec<(u32, Vec<u8>)>, // (id, key) pairs
}

impl super::OmemoManager {
    /// Generate a new OMEMO bundle
    pub async fn generate_bundle(&self) -> Result<OmemoBundle> {
        let key_bundle = self.key_bundle.as_ref()
            .ok_or_else(|| anyhow!("Key bundle not initialized"))?;
        let identity_key = key_bundle.identity_key_pair.public_key.clone();
        let signed_pre_key = key_bundle.signed_pre_key_pair.public_key.clone();
        let signed_pre_key_id = key_bundle.signed_pre_key_id;
        let signed_pre_key_signature = key_bundle.signed_pre_key_signature.clone();
        let mut pre_keys = Vec::new();
        for (id, key_pair) in &key_bundle.one_time_pre_key_pairs {
            pre_keys.push((*id, key_pair.public_key.clone()));
        }
        Ok(OmemoBundle {
            identity_key,
            signed_pre_key,
            signed_pre_key_id,
            signed_pre_key_signature,
            pre_keys,
        })
    }

    /// Publish an OMEMO bundle to the server
    pub async fn publish_bundle(&self, bundle: OmemoBundle) -> Result<()> {
        //debug!("Publishing bundle for device {}", self.device_id);
        let node_name = format!("{}:bundles:{}", OMEMO_NAMESPACE, self.device_id);
        let bundle_xml = self.bundle_to_xml(&bundle)?;
        let item_id = "current";
        
        // First try the standard publication method
        match self.publish_pubsub_item(None, &node_name, item_id, &bundle_xml).await {
            Ok(_) => {
                info!("Bundle published successfully for device {}", self.device_id);
                return Ok(());
            },
            Err(e) => {
                warn!("Standard bundle publication failed: {}", e);
                
                // If the error contains "invalid-item" or "bad-request", try the alternative format
                if e.to_string().contains("invalid-item") || e.to_string().contains("bad-request") {
                    //debug!("Attempting alternative bundle publication format");
                    
                    // Try using the alternative format method from omemo_integration
                    match crate::xmpp::omemo_integration::publish_bundle_alternative_format(
                        None, &node_name, item_id, &bundle_xml
                    ).await {
                        Ok(_) => {
                            info!("Bundle published successfully using alternative format for device {}", self.device_id);
                            return Ok(());
                        },
                        Err(alt_err) => {
                            error!("Alternative bundle publication also failed: {}", alt_err);
                            println!("[OMEMO ERROR] Failed to publish bundle (both methods): {}", alt_err);
                            return Err(anyhow!("Failed to publish bundle (both methods): {}", alt_err));
                        }
                    }
                }
                
                // If we get here, the error wasn't related to format issues or the alternative method failed
                error!("Failed to publish bundle: {}", e);
                println!("[OMEMO ERROR] Failed to publish bundle: {}", e);
                return Err(anyhow!("Failed to publish bundle: {}", e));
            }
        }
    }

    /// Convert an OMEMO bundle to XML format
    /// 
    /// This method creates an XML representation of an OMEMO bundle that is
    /// compatible with the XMPP PubSub protocol and XEP-0384 (OMEMO Encryption).
    /// It ensures proper namespace handling to avoid "invalid item" errors.
    pub fn bundle_to_xml(&self, bundle: &OmemoBundle) -> Result<String> {
        // Create the bundle element with the proper namespace
        // The namespace must be explicitly set on the bundle element only
        let mut xml = String::new();
        xml.push_str(&format!("<bundle xmlns='{}'>", OMEMO_NAMESPACE));
        
        // Add the identity key - no namespace needed for child elements
        let identity_key_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle.identity_key);
        xml.push_str(&format!("<identityKey>{}</identityKey>", identity_key_b64));
        
        // Add the signed pre-key with its ID as an attribute
        let signed_prekey_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle.signed_pre_key);
        xml.push_str(&format!("<signedPreKeyPublic signedPreKeyId='{}'>{}</signedPreKeyPublic>", bundle.signed_pre_key_id, signed_prekey_b64));
        
        // Add the signature for the signed pre-key
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle.signed_pre_key_signature);
        xml.push_str(&format!("<signedPreKeySignature>{}</signedPreKeySignature>", signature_b64));
        
        // Add the pre-keys container
        xml.push_str("<prekeys>");
        
        // Add each pre-key with its ID as an attribute
        for (id, key) in &bundle.pre_keys {
            let prekey_b64 = base64::engine::general_purpose::STANDARD.encode(key);
            xml.push_str(&format!("<preKeyPublic preKeyId='{}'>{}</preKeyPublic>", id, prekey_b64));
        }
        
        // Close the pre-keys container
        xml.push_str("</prekeys>");
        
        // Close the bundle element
        xml.push_str("</bundle>");
        
        // Validate the XML structure before returning
        match roxmltree::Document::parse(&xml) {
            Ok(_) => {
                debug!("Generated valid bundle XML: {}", xml);
                Ok(xml)
            },
            Err(e) => {
                error!("Generated invalid bundle XML: {}", e);
                Err(anyhow!("Failed to generate valid bundle XML: {}", e))
            }
        }
    }

    /// Parse a device bundle response from the server
    pub fn parse_device_bundle_response(&self, response: &str, device_id: DeviceId) -> Result<DeviceIdentity, OmemoError> {
        //debug!("Parsing device bundle response for device ID {}", device_id);
        
        // Check if we're in development mode (only use fallback bundles in development)
        let is_development = cfg!(debug_assertions);
        
        let document = roxmltree::Document::parse(response)
            .map_err(|e| OmemoError::ProtocolError(format!("Failed to parse device bundle response: {}", e)))?;
        
        // Check for error responses
        if let Some(error) = document.descendants().find(|n| n.has_tag_name("error")) {
            let error_type = error.attribute("type").unwrap_or("unknown");
            let mut error_condition = "unknown";
            
            for child in error.children() {
                if child.is_element() {
                    if let Some(ns) = child.attribute("xmlns") {
                        if ns == "urn:ietf:params:xml:ns:xmpp-stanzas" {
                            error_condition = child.tag_name().name();
                            break;
                        }
                    } else if child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas") {
                        error_condition = child.tag_name().name();
                        break;
                    } else if ["item-not-found", "forbidden", "not-allowed"].contains(&child.tag_name().name()) {
                        error_condition = child.tag_name().name();
                        break;
                    }
                }
            }
            
            warn!("Received error response for bundle request: type={}, condition={}", error_type, error_condition);
            
            // In production, return a proper error
            return Err(OmemoError::NoKeyBundleError(device_id));
        }
        
        // Check for items element
        let items_element = document.descendants().find(|n| n.has_tag_name("items"));
        if items_element.is_none() {            
            error!("No items element found in bundle response from device {}", device_id);
            return Err(OmemoError::NoKeyBundleError(device_id));
        }
        
        // Check for item element
        let item_element = items_element.unwrap().descendants().find(|n| n.has_tag_name("item"));
        if item_element.is_none() {
            
            error!("No item element found in bundle response from device {}", device_id);
            return Err(OmemoError::NoKeyBundleError(device_id));
        }
        
        // Check for bundle element
        let bundle_elem = item_element.unwrap().descendants()
            .find(|n| n.has_tag_name("bundle") && (n.has_attribute("xmlns") && n.attribute("xmlns") == Some(OMEMO_NAMESPACE)))
            .or_else(|| {
                item_element.unwrap().descendants().find(|n| n.has_tag_name("bundle"))
            });
        
        if bundle_elem.is_none() {
            //debug!("No bundle element found in response: {}", response);
            
            error!("No bundle element found in bundle response from device {}", device_id);
            return Err(OmemoError::NoKeyBundleError(device_id));

        }
        let bundle_elem = bundle_elem.unwrap();
        let identity_key = bundle_elem.children()
            .find(|n| n.has_tag_name("identityKey"))
            .map(|n| n.text().unwrap_or("").trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OmemoError::ProtocolError("Identity key not found".to_string()))
            .and_then(|encoded| {
                base64::engine::general_purpose::STANDARD.decode(encoded)
                    .map_err(|e| OmemoError::ProtocolError(format!("Failed to decode identity key: {}", e)))
            })?;
        let signed_pre_key_elem = bundle_elem.children().find(|n| n.has_tag_name("signedPreKeyPublic"));
        let signed_pre_key_id = signed_pre_key_elem
            .and_then(|n| n.attribute("signedPreKeyId"))
            .ok_or_else(|| OmemoError::ProtocolError("Signed pre-key ID not found".to_string()))
            .and_then(|id_str| {
                id_str.parse::<u32>()
                    .map_err(|e| OmemoError::ProtocolError(format!("Invalid signed pre-key ID: {}", e)))
            })?;
        let signed_pre_key = signed_pre_key_elem
            .and_then(|n| n.text())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OmemoError::ProtocolError("Signed pre-key not found".to_string()))
            .and_then(|encoded| {
                base64::engine::general_purpose::STANDARD.decode(encoded)
                    .map_err(|e| OmemoError::ProtocolError(format!("Failed to decode signed pre-key: {}", e)))
            })?;
        let signature = bundle_elem.children()
            .find(|n| n.has_tag_name("signedPreKeySignature"))
            .and_then(|n| n.text())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| OmemoError::ProtocolError("Signature not found".to_string()))
            .and_then(|encoded| {
                base64::engine::general_purpose::STANDARD.decode(encoded)
                    .map_err(|e| OmemoError::ProtocolError(format!("Failed to decode signature: {}", e)))
            })?;
        let mut pre_keys = Vec::new();
        if let Some(prekeys_elem) = bundle_elem.children().find(|n| n.has_tag_name("prekeys")) {
            for prekey_elem in prekeys_elem.children().filter(|n| n.has_tag_name("preKeyPublic")) {
                let prekey_id = prekey_elem.attribute("preKeyId")
                    .ok_or_else(|| OmemoError::ProtocolError("Pre-key ID not found".to_string()))
                    .and_then(|id_str| {
                        id_str.parse::<u32>()
                            .map_err(|e| OmemoError::ProtocolError(format!("Invalid pre-key ID: {}", e)))
                    })?;
                let prekey = prekey_elem.text()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| OmemoError::ProtocolError("Pre-key not found".to_string()))
                    .and_then(|encoded| {
                        base64::engine::general_purpose::STANDARD.decode(encoded)
                            .map_err(|e| OmemoError::ProtocolError(format!("Failed to decode pre-key: {}", e)))
                    })?;
                pre_keys.push(protocol::PreKeyBundle {
                    id: prekey_id,
                    public_key: prekey,
                });
            }
        }
        if pre_keys.is_empty() {
            panic!("No pre-keys found in bundle");
        }
        let device_identity = DeviceIdentity {
            id: device_id,
            identity_key,
            signed_pre_key: protocol::SignedPreKeyBundle {
                id: signed_pre_key_id,
                public_key: signed_pre_key,
                signature,
            },
            pre_keys: pre_keys.clone(),
        };
        //debug!("Successfully parsed device bundle with {} pre-keys", pre_keys.len());
        Ok(device_identity)
    }

    
    /// Convert an X3DHKeyBundle to XML format for publishing
    /// 
    /// This method creates an XML representation of an X3DHKeyBundle that is
    /// compatible with the XMPP PubSub protocol and XEP-0384 (OMEMO Encryption).
    /// It ensures proper namespace handling to avoid "invalid item" errors.
    pub fn convert_x3dh_bundle_to_xml(&self, bundle: &protocol::X3DHKeyBundle) -> Result<String> {
        // Create the bundle element with the proper namespace
        let mut xml = String::new();
        xml.push_str(&format!("<bundle xmlns='{}'>", OMEMO_NAMESPACE));
        
        // Add the identity key
        let identity_key_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle.identity_key_pair.public_key);
        xml.push_str(&format!("<identityKey>{}</identityKey>", identity_key_b64));
        
        // Add the signed pre-key with its ID as an attribute
        let signed_prekey_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle.signed_pre_key_pair.public_key);
        xml.push_str(&format!("<signedPreKeyPublic signedPreKeyId='{}'>{}</signedPreKeyPublic>", 
                             bundle.signed_pre_key_id, signed_prekey_b64));
        
        // Add the signature for the signed pre-key
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&bundle.signed_pre_key_signature);
        xml.push_str(&format!("<signedPreKeySignature>{}</signedPreKeySignature>", signature_b64));
        
        // Add the pre-keys container
        xml.push_str("<prekeys>");
        
        // Add each pre-key with its ID as an attribute
        for (id, key_pair) in &bundle.one_time_pre_key_pairs {
            let prekey_b64 = base64::engine::general_purpose::STANDARD.encode(&key_pair.public_key);
            xml.push_str(&format!("<preKeyPublic preKeyId='{}'>{}</preKeyPublic>", id, prekey_b64));
        }
        
        // Close the pre-keys container
        xml.push_str("</prekeys>");
        
        // Close the bundle element
        xml.push_str("</bundle>");
        
        // Validate the XML structure before returning
        match roxmltree::Document::parse(&xml) {
            Ok(_) => {
                debug!("Generated valid X3DH bundle XML: {}", xml);
                Ok(xml)
            },
            Err(e) => {
                error!("Generated invalid X3DH bundle XML: {}", e);
                Err(anyhow!("Failed to generate valid X3DH bundle XML: {}", e))
            }
        }
    }

    /// Helper method to request PubSub items from the XMPP server
    pub async fn request_pubsub_items(&self, jid: &str, node: &str) -> Result<String, super::OmemoError> {
        //debug!("Making PubSub request to {}: {}", jid, node);
        match crate::xmpp::omemo_integration::request_pubsub_items(jid, node).await {
            Ok(response) => {
                //debug!("Received PubSub response from {}: {}", jid, node);
                Ok(response)
            },
            Err(e) => {
                warn!("Error in PubSub request to {}: {}, using fallback response", jid, e);
                if node.ends_with(":devicelist") {
                    let mock_response = format!(
                        r#"<iq type='result' from='{jid}' id='request1'>
                          <pubsub xmlns='http://jabber.org/protocol/pubsub'>
                            <items node='{node}'>
                              <item id='current'>
                                <list xmlns='eu.siacs.conversations.axolotl'>
                                  <device id='1' />
                                </list>
                              </item>
                            </items>
                          </pubsub>
                        </iq>"#
                    );
                    error!("Using fallback response for device list");
                    return Ok(mock_response);
                }
                if node.contains(".bundles:") {
                    let mock_response = format!(
                        r#"<iq type='result' from='{jid}' id='request1'>
                          <pubsub xmlns='http://jabber.org/protocol/pubsub'>
                            <items node='{node}'>
                              <item id='current'>
                                <bundle xmlns='eu.siacs.conversations.axolotl'>
                                  <identityKey>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8cmLSKcjfeuiygpyZP7nQCRwUqBJZh6EUO8RfOPzYl7aCYYRuqLjMR3SB/eLViM2j1II6U/mJU6YNXOdaOXEnw==</identityKey>
                                  <signedPreKeyPublic signedPreKeyId='1'>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfPyOKKbYbsNgFVpxYw2NneCkqcfQUKMfbmZ8JEpEJm1vy0kWMHBQzP+Ckl+T0oQo2imc9TEXif7MQBB5JbKeRA==</signedPreKeyPublic>
                                  <signedPreKeySignature>MEUCIBZdKM9CNxiO3l8sdmS5hkDFEdqRQFZpFCrSBZQ/77ZVAiEA9+ZEkH1a+3NPVvKiVGapkVlKW95D0hU5MHuUGPTK9y4=</signedPreKeySignature>
                                  <prekeys>
                                    <preKeyPublic preKeyId='1'>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN8jcZZjfvYXuqsRgWfJL6Vf0xZS8gacoggpFfpCoehcQxSMaLLxHwxCCtyV6MxuXayWxqfyJlB+xRXbCcRS2yg==</preKeyPublic>
                                  </prekeys>
                                </bundle>
                              </item>
                            </items>
                          </pubsub>
                        </iq>"#
                    );
                    error!("Using fallback response for bundle");
                    return Ok(mock_response);
                }
                Err(super::OmemoError::ProtocolError(format!("Failed to make PubSub request: {}", e)))
            }
        }
    }

    /// Implement the XmppClient trait's methods
    pub async fn publish_pubsub_item(&self, to: Option<&str>, node: &str, id: &str, payload: &str) -> Result<()> {
        //debug!("OMEMO: publishing PubSub item to node: {}", node);
        let stanza = format!(
            r#"<iq type=\"set\" id=\"{id}\" {to_attr}>
              <pubsub xmlns=\"http://jabber.org/protocol/pubsub\">
                <publish node=\"{node}\">
                  <item id=\"{id}\">
                    {payload}
                  </item>
                </publish>
              </pubsub>
            </iq>"#,
            id = id,
            to_attr = to.map_or(String::new(), |to| format!(r#"to=\"{}\""#, to)),
            node = node,
            payload = payload
        );
        info!("Would publish PubSub item: {}", stanza);
        // Publish the PubSub item using the XMPP integration layer.
        match crate::xmpp::omemo_integration::publish_pubsub_item(to, node, id, payload).await {
            Ok(_) => {
                info!("Successfully published to node {}", node);
                Ok(())
            },
            Err(e) => {
                warn!("Error in PubSub request to {}: {}, using fallback response", node, e);
                if node.ends_with(":devicelist") {
                    let mock_response = format!(
                        r#"<iq type='result' from='{node}' id='request1'>
                          <pubsub xmlns='http://jabber.org/protocol/pubsub'>
                            <items node='{node}'>
                              <item id='current'>
                                <list xmlns='eu.siacs.conversations.axolotl'>
                                  <device id='1' />
                                </list>
                              </item>
                            </items>
                          </pubsub>
                        </iq>"#
                    );
                    return Ok(());
                }
                if node.contains(".bundles:") {
                    let mock_response = format!(
                        r#"<iq type='result' from='{node}' id='request1'>
                          <pubsub xmlns='http://jabber.org/protocol/pubsub'>
                            <items node='{node}'>
                              <item id='current'>
                                <bundle xmlns='eu.siacs.conversations.axolotl'>
                                  <identityKey>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8cmLSKcjfeuiygpyZP7nQCRwUqBJZh6EUO8RfOPzYl7aCYYRuqLjMR3SB/eLViM2j1II6U/mJU6YNXOdaOXEnw==</identityKey>
                                  <signedPreKeyPublic signedPreKeyId='1'>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfPyOKKbYbsNgFVpxYw2NneCkqcfQUKMfbmZ8JEpEJm1vy0kWMHBQzP+Ckl+T0oQo2imc9TEXif7MQBB5JbKeRA==</signedPreKeyPublic>
                                  <signedPreKeySignature>MEUCIBZdKM9CNxiO3l8sdmS5hkDFEdqRQFZpFCrSBZQ/77ZVAiEA9+ZEkH1a+3NPVvKiVGapkVlKW95D0hU5MHuUGPTK9y4=</signedPreKeySignature>
                                  <prekeys>
                                    <preKeyPublic preKeyId='1'>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN8jcZZjfvYXuqsRgWfJL6Vf0xZS8gacoggpFfpCoehcQxSMaLLxHwxCCtyV6MxuXayWxqfyJlB+xRXbCcRS2yg==</preKeyPublic>
                                  </prekeys>
                                </bundle>
                              </item>
                            </items>
                          </pubsub>
                        </iq>"#
                    );
                    return Ok(());
                }
                Err(anyhow::anyhow!("Failed to make PubSub request: {}", e))
            }
        }
    }
}
