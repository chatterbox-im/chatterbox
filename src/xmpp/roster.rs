// XMPP Roster management for Sermo
// Contains all roster-related methods for XMPPClient

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use std::time::Duration;
use uuid::Uuid;
use xmpp_parsers::Element;
use crate::xmpp::XMPPClient;
use tokio_xmpp::Event as XMPPEvent;
use futures_util::StreamExt; // Import for next() method on event stream

impl XMPPClient {
    /// Get the roster (contact list) from the XMPP server
    pub async fn get_roster(&self) -> Result<Option<Vec<String>>> {
        if !self.is_client_accessible() {
            return Err(anyhow!("XMPP client not initialized or unavailable"));
        }

        //debug!("Requesting roster (contact list)");
        let id = Uuid::new_v4().to_string();
        let query = Element::builder("query", "jabber:iq:roster").build();
        let iq = Element::builder("iq", "jabber:client")
            .attr("type", "get")
            .attr("id", &id)
            .append(query)
            .build();
        info!("Sending roster request with ID: {}", id);
        
        // Get client reference
        let client = self.client.as_ref().ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        
        // Send the roster request
        let send_result = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(iq).await
            }
        ).await;
        
        // Handle send errors
        if let Err(e) = send_result {
            error!("Timed out sending roster request: {}", e);
            return Err(anyhow!("Timed out sending roster request"));
        }
        if let Err(e) = send_result.unwrap() {
            error!("Failed to send roster request: {}", e);
            return Err(anyhow!("Failed to send roster request: {}", e));
        }
        
        info!("Roster request sent, waiting for response...");
        
        // Wait for the response with a timeout
        let response_timeout = Duration::from_secs(10);
        let start_time = tokio::time::Instant::now();
        let mut roster_contacts = Vec::new();
        
        // Process events until we get the roster response or timeout
        while tokio::time::Instant::now() - start_time < response_timeout {
            // Wait for the next event with a short timeout
            let event_result = tokio::time::timeout(
                Duration::from_millis(500),
                async {
                    if let Some(client_ref) = &self.client {
                        let mut client_guard = client_ref.lock().await;
                        client_guard.next().await
                    } else {
                        return None;
                    }
                }
            ).await;
            
            // Process the event if we got one
            match event_result {
                Ok(Some(XMPPEvent::Stanza(stanza))) => {
                    // Check if this is our roster response
                    if stanza.name() == "iq" && stanza.attr("id") == Some(&id) {
                        info!("Received roster response for ID: {}", id);
                        
                        // Handle different response types
                        match stanza.attr("type") {
                            Some("result") => {
                                // Process the roster items if we have a query
                                if let Some(query) = stanza.get_child("query", "jabber:iq:roster") {
                                    for item in query.children() {
                                        if item.name() == "item" {
                                            if let Some(jid) = item.attr("jid") {
                                                info!("Found contact: {}", jid);
                                                roster_contacts.push(jid.to_string());
                                            }
                                        }
                                    }
                                    
                                    info!("Found {} contacts in roster", roster_contacts.len());
                                    
                                    // Return the contacts immediately
                                    if roster_contacts.is_empty() {
                                        info!("No contacts found in roster");
                                    } else {
                                        info!("Returning {} contacts from roster", roster_contacts.len());
                                    }
                                    
                                    return Ok(Some(roster_contacts));
                                } else {
                                    info!("Roster response contains no query element");
                                    return Ok(Some(Vec::new()));
                                }
                            },
                            Some("error") => {
                                error!("Server returned error for roster request");
                                if let Some(error) = stanza.get_child("error", "") {
                                    let error_type = error.attr("type").unwrap_or("unknown");
                                    error!("Error type: {}", error_type);
                                    for child in error.children() {
                                        error!("Error condition: {}", child.name());
                                    }
                                }
                                return Ok(Some(Vec::new()));
                            },
                            _ => {
                                //debug!("Unexpected IQ type in roster response: {:?}", stanza.attr("type"));
                            }
                        }
                    }
                },
                Ok(Some(XMPPEvent::Disconnected(e))) => {
                    error!("Disconnected while waiting for roster: {:?}", e);
                    return Err(anyhow!("Disconnected while waiting for roster: {:?}", e));
                },
                Ok(None) => {
                    error!("Connection closed while waiting for roster");
                    return Err(anyhow!("Connection closed while waiting for roster"));
                },
                Err(_) => {
                    // Timeout on the event, continue the loop
                    continue;
                },
                _ => {
                    // Other event, continue the loop
                    continue;
                }
            }
        }
        
        // If we reach here, we timed out waiting for the roster response
        warn!("Timed out waiting for roster response, returning empty roster");
        
        Ok(Some(roster_contacts))
    }

    /// Add a contact to the roster
    pub async fn add_contact_to_roster(&self, jid: &str) -> Result<()> {
        if !self.is_client_accessible() {
            return Err(anyhow!("XMPP client not initialized or unavailable"));
        }
        let full_jid = self.ensure_full_jid(jid).await?;
        //debug!("Adding contact to roster: {} (full JID: {})", jid, full_jid);
        let id = Uuid::new_v4().to_string();
        let item = Element::builder("item", "jabber:iq:roster")
            .attr("jid", &full_jid)
            .build();
        let query = Element::builder("query", "jabber:iq:roster")
            .append(item)
            .build();
        let iq = Element::builder("iq", "jabber:client")
            .attr("type", "set")
            .attr("id", &id)
            .append(query)
            .build();
        info!("Sending add contact request with ID: {}", id);
        let client = self.client.as_ref().ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        let send_result = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(iq).await
            }
        ).await;
        if let Err(e) = send_result {
            error!("Timed out sending add contact request: {}", e);
            return Err(anyhow!("Timed out sending add contact request"));
        }
        if let Err(e) = send_result.unwrap() {
            error!("Failed to send add contact request: {}", e);
            return Err(anyhow!("Failed to send add contact request: {}", e));
        }
        info!("Add contact request sent successfully for {}", full_jid);
        let subscribe = Element::builder("presence", "jabber:client")
            .attr("type", "subscribe")
            .attr("to", &full_jid)
            .build();
        let subscribe_result = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(subscribe).await
            }
        ).await;
        if let Err(e) = subscribe_result {
            error!("Timed out sending subscription request: {}", e);
            return Err(anyhow!("Timed out sending subscription request"));
        }
        if let Err(e) = subscribe_result.unwrap() {
            error!("Failed to send subscription request: {}", e);
            return Err(anyhow!("Failed to send subscription request: {}", e));
        }
        info!("Subscription request sent successfully for {}", full_jid);
        Ok(())
    }

    /// Remove a contact from the roster
    pub async fn remove_contact_from_roster(&self, jid: &str) -> Result<()> {
        if !self.is_client_accessible() {
            return Err(anyhow!("XMPP client not initialized or unavailable"));
        }
        let roster = self.get_roster().await?;
        let exact_jid = if let Some(contacts) = &roster {
            let normalized_input = jid.to_lowercase();
            let mut found_jid = None;
            for contact in contacts {
                if contact == jid {
                    //debug!("Found direct JID match in roster: {}", contact);
                    found_jid = Some(contact.clone());
                    break;
                }
                if contact.to_lowercase() == normalized_input {
                    //debug!("Found case-insensitive JID match in roster: {}", contact);
                    found_jid = Some(contact.clone());
                    break;
                }
                let domain_added_jid = if !jid.contains('@') {
                    format!("{}@{}", jid, self.get_server_domain().await.unwrap_or_default())
                } else {
                    jid.to_string()
                };
                let domain_removed_jid = if jid.contains('@') {
                    jid.split('@').next().unwrap_or(jid).to_string()
                } else {
                    jid.to_string()
                };
                if contact.to_lowercase() == domain_added_jid.to_lowercase() {
                    //debug!("Found JID match with domain added: {}", contact);
                    found_jid = Some(contact.clone());
                    break;
                }
                if contact.to_lowercase() == domain_removed_jid.to_lowercase() {
                    //debug!("Found JID match with domain removed: {}", contact);
                    found_jid = Some(contact.clone());
                    break;
                }
            }
            found_jid.unwrap_or_else(|| {
                warn!("Could not find exact JID match in roster, using original: {}", jid);
                jid.to_string()
            })
        } else {
            warn!("Could not fetch roster, using provided JID: {}", jid);
            jid.to_string()
        };
        info!("Removing contact from roster using exact JID: {}", exact_jid);
        let id = Uuid::new_v4().to_string();
        let item = Element::builder("item", "jabber:iq:roster")
            .attr("jid", &exact_jid)
            .attr("subscription", "remove")
            .build();
        let query = Element::builder("query", "jabber:iq:roster")
            .append(item)
            .build();
        let iq = Element::builder("iq", "jabber:client")
            .attr("type", "set")
            .attr("id", &id)
            .append(query)
            .build();
        info!("Sending remove contact request with ID: {}", id);
        let client = self.client.as_ref().ok_or_else(|| anyhow!("XMPP client not initialized"))?;
        let send_result = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(iq).await
            }
        ).await;
        if let Err(e) = send_result {
            error!("Timed out sending remove contact request: {}", e);
            return Err(anyhow!("Timed out sending remove contact request"));
        }
        if let Err(e) = send_result.unwrap() {
            error!("Failed to send remove contact request: {}", e);
            return Err(anyhow!("Failed to send remove contact request: {}", e));
        }
        info!("Remove contact request sent successfully for {}", exact_jid);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let unsubscribe = Element::builder("presence", "jabber:client")
            .attr("type", "unsubscribe")
            .attr("to", &exact_jid)
            .attr("id", &format!("{}", rand::random::<u64>()))
            .build();
        let unsubscribe_result = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(unsubscribe).await
            }
        ).await;
        if let Err(e) = unsubscribe_result {
            warn!("Timed out sending unsubscription request: {}", e);
        } else if let Err(e) = unsubscribe_result.unwrap() {
            warn!("Failed to send unsubscription request: {}", e);
        } else {
            //debug!("Unsubscription request sent successfully for {}", exact_jid);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let unsubscribed = Element::builder("presence", "jabber:client")
            .attr("type", "unsubscribed")
            .attr("to", &exact_jid)
            .attr("id", &format!("{}", rand::random::<u64>()))
            .build();
        let unsubscribed_result = tokio::time::timeout(
            Duration::from_secs(5),
            async {
                let mut client_guard = client.lock().await;
                client_guard.send_stanza(unsubscribed).await
            }
        ).await;
        if let Err(e) = unsubscribed_result {
            warn!("Timed out sending unsubscribed stanza: {}", e);
        } else if let Err(e) = unsubscribed_result.unwrap() {
            warn!("Failed to send unsubscribed stanza: {}", e);
        } else {
            //debug!("Unsubscribed stanza sent successfully for {}", exact_jid);
        }
        if let Ok(Some(_)) = self.get_roster().await {
            //debug!("Roster refreshed after removal");
        }
        Ok(())
    }

    /// Validate a JID format
    /// 
    /// This function checks if a JID is properly formatted according to the XMPP spec.
    /// A valid JID must have a local part, a domain part, and optionally a resource part.
    /// 
    /// Returns true if the JID is valid, false otherwise.
    pub fn validate_jid(jid: &str) -> bool {
        // Basic JID regex pattern: localpart@domainpart[/resourcepart]
        // This is a simplified version - a full implementation would be more complex
        let jid_regex = regex::Regex::new(r"^([^@/]+)@([^@/]+)(/([^@/]+))?$").unwrap();
        
        if !jid_regex.is_match(jid) {
            //debug!("[JID VALIDATION] Invalid JID format: {}", jid);
            return false;
        }
        
        // Additional validation for domain part
        if let Some(captures) = jid_regex.captures(jid) {
            if let Some(domain) = captures.get(2) {
                let domain_str = domain.as_str();
                
                // Domain must contain at least one dot
                if !domain_str.contains('.') {
                    //debug!("[JID VALIDATION] Invalid domain (missing dot): {}", domain_str);
                    return false;
                }
                
                // Domain must not start or end with a dot
                if domain_str.starts_with('.') || domain_str.ends_with('.') {
                    //debug!("[JID VALIDATION] Invalid domain (starts/ends with dot): {}", domain_str);
                    return false;
                }
                
                // Domain must not contain consecutive dots
                if domain_str.contains("..") {
                    //debug!("[JID VALIDATION] Invalid domain (consecutive dots): {}", domain_str);
                    return false;
                }
                
                // Domain parts must be valid (letters, digits, hyphens)
                let domain_part_regex = regex::Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$").unwrap();
                for part in domain_str.split('.') {
                    if part.is_empty() || !domain_part_regex.is_match(part) {
                        //debug!("[JID VALIDATION] Invalid domain part: {}", part);
                        return false;
                    }
                }
            }
        }
        
        true
    }

    /// Ensure a JID is fully qualified with a domain
    pub async fn ensure_full_jid(&self, jid: &str) -> Result<String> {
        //debug!("[JID DEBUG] ensure_full_jid: input jid = {}", jid);
        let user_jid = self.get_jid();
        //debug!("[JID DEBUG] ensure_full_jid: user_jid = {}", user_jid);
        
        // If the JID already contains @, validate it
        if jid.contains('@') {
            //debug!("[JID DEBUG] ensure_full_jid: jid already contains @, validating: {}", jid);
            
            if Self::validate_jid(jid) {
                //debug!("[JID DEBUG] ensure_full_jid: jid is valid: {}", jid);
                return Ok(jid.to_string());
            } else {
                warn!("[JID DEBUG] ensure_full_jid: jid is invalid: {}", jid);
                // Continue to try to fix it by adding domain
            }
        }
        
        // Try to extract domain from user's JID
        if let Some(domain_start) = user_jid.find('@') {
            let domain_end = user_jid.find('/').unwrap_or(user_jid.len());
            if domain_start < domain_end {
                let domain = &user_jid[domain_start+1..domain_end];
                //debug!("[JID DEBUG] ensure_full_jid: Adding domain '{}' to bare JID '{}'", domain, jid);
                
                // Create the full JID
                let full = if jid.contains('@') {
                    // If it already has @ but was invalid, try to extract the local part
                    if let Some(local_part) = jid.split('@').next() {
                        format!("{}@{}", local_part, domain)
                    } else {
                        format!("{}@{}", jid, domain) // Fallback
                    }
                } else {
                    format!("{}@{}", jid, domain)
                };
                
                // Validate the constructed JID
                if Self::validate_jid(&full) {
                    //debug!("[JID DEBUG] ensure_full_jid: returning valid JID: {}", full);
                    return Ok(full);
                } else {
                    warn!("[JID DEBUG] ensure_full_jid: constructed JID is invalid: {}", full);
                }
            }
        }
        
        // Try with server domain
        if let Some(domain) = self.get_server_domain().await {
            //debug!("[JID DEBUG] ensure_full_jid: Using server domain '{}' for bare JID '{}'", domain, jid);
            
            // Create the full JID
            let full = if jid.contains('@') {
                // If it already has @ but was invalid, try to extract the local part
                if let Some(local_part) = jid.split('@').next() {
                    format!("{}@{}", local_part, domain)
                } else {
                    format!("{}@{}", jid, domain) // Fallback
                }
            } else {
                format!("{}@{}", jid, domain)
            };
            
            // Validate the constructed JID
            if Self::validate_jid(&full) {
                //debug!("[JID DEBUG] ensure_full_jid: returning valid JID: {}", full);
                return Ok(full);
            } else {
                warn!("[JID DEBUG] ensure_full_jid: constructed JID is invalid: {}", full);
            }
        }
        
        error!("[JID DEBUG] ensure_full_jid: Cannot determine valid domain for JID: {}", jid);
        Err(anyhow!("Cannot determine valid domain for JID: {}", jid))
    }

    /// Get the server domain from the current JID
    pub async fn get_server_domain(&self) -> Option<String> {
        let jid = self.get_jid();
        //debug!("[JID DEBUG] get_server_domain: user_jid = {}", jid);
        if let Some(domain_end) = jid.find('/') {
            if let Some(domain_start) = jid.find('@') {
                if domain_start < domain_end {
                    let domain = jid[domain_start+1..domain_end].to_string();
                    //debug!("[JID DEBUG] get_server_domain: found domain = {}", domain);
                    return Some(domain);
                }
            }
        }
        if let Some(domain_start) = jid.find('@') {
            let domain = jid[domain_start+1..].to_string();
            //debug!("[JID DEBUG] get_server_domain: found domain = {}", domain);
            return Some(domain);
        }
        //debug!("[JID DEBUG] get_server_domain: no domain found");
        None
    }
}
