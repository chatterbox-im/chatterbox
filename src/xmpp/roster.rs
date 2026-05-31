// XMPP Roster management for Sermo
// Contains all roster-related methods for XMPPClient

use anyhow::{anyhow, Result};
use log::{error, info, warn};
use xmpp_parsers::Element;
use crate::xmpp::XMPPClient;

impl XMPPClient {
    /// Get the roster (contact list) from the XMPP server
    pub async fn get_roster(&self) -> Result<Option<Vec<String>>> {
        if !self.is_client_accessible() {
            return Err(anyhow!("XMPP client not initialized or unavailable"));
        }

        let query = Element::builder("query", "jabber:iq:roster").build();

        match self.send_iq_and_await("get", query, 10).await {
            Ok(stanza) => {
                let mut roster_contacts = Vec::new();
                if let Some(query) = stanza.get_child("query", "jabber:iq:roster") {
                    for item in query.children() {
                        if item.name() == "item" {
                            if let Some(jid) = item.attr("jid") {
                                info!("Found contact: {}", jid);
                                roster_contacts.push(jid.to_string());
                            }
                        }
                    }
                }
                info!("Found {} contacts in roster", roster_contacts.len());
                Ok(Some(roster_contacts))
            }
            Err(e) => {
                warn!("Failed to get roster: {}", e);
                Ok(Some(Vec::new()))
            }
        }
    }

    /// Add a contact to the roster
    pub async fn add_contact_to_roster(&self, jid: &str) -> Result<()> {
        if !self.is_client_accessible() {
            return Err(anyhow!("XMPP client not initialized or unavailable"));
        }
        let full_jid = self.ensure_full_jid(jid).await?;

        let item = Element::builder("item", "jabber:iq:roster")
            .attr("jid", &full_jid)
            .build();
        let query = Element::builder("query", "jabber:iq:roster")
            .append(item)
            .build();

        match self.send_iq_and_await("set", query, 10).await {
            Ok(_) => {
                info!("Server confirmed roster add for {}", full_jid);
            }
            Err(e) => {
                // If it's an actual IQ error (server rejection), propagate it
                if e.to_string().contains("IQ error") {
                    return Err(anyhow!("Server rejected roster add for {}: {}", full_jid, e));
                }
                // Timeout or channel errors are non-fatal — the server may have processed it
                warn!("Roster add response issue for {}: {}", full_jid, e);
            }
        }

        // Send presence subscription request
        let subscribe = Element::builder("presence", "jabber:client")
            .attr("type", "subscribe")
            .attr("to", &full_jid)
            .build();
        self.send_stanza(subscribe)
            .map_err(|e| anyhow!("Failed to send subscription request: {}", e))?;
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

        let item = Element::builder("item", "jabber:iq:roster")
            .attr("jid", &exact_jid)
            .attr("subscription", "remove")
            .build();
        let query = Element::builder("query", "jabber:iq:roster")
            .append(item)
            .build();

        match self.send_iq_and_await("set", query, 10).await {
            Ok(_) => {
                info!("Server confirmed roster removal for {}", exact_jid);
            }
            Err(e) => {
                // For removal, treat timeout/channel errors as non-fatal but propagate real errors
                if e.to_string().contains("IQ error") {
                    return Err(anyhow!("Server rejected roster removal for {}: {}", exact_jid, e));
                }
                warn!("Roster removal response issue for {}: {}", exact_jid, e);
            }
        }

        let unsubscribe = Element::builder("presence", "jabber:client")
            .attr("type", "unsubscribe")
            .attr("to", &exact_jid)
            .attr("id", &format!("{}", rand::random::<u64>()))
            .build();
        if let Err(e) = self.send_stanza(unsubscribe) {
            warn!("Failed to send unsubscription request: {}", e);
        }
        let unsubscribed = Element::builder("presence", "jabber:client")
            .attr("type", "unsubscribed")
            .attr("to", &exact_jid)
            .attr("id", &format!("{}", rand::random::<u64>()))
            .build();
        if let Err(e) = self.send_stanza(unsubscribed) {
            warn!("Failed to send unsubscribed stanza: {}", e);
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
