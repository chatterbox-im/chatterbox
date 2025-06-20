use anyhow::Result;
use log::{info, warn};
use xmpp_parsers::Element;
use tokio_xmpp::AsyncClient;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use std::collections::HashSet;

/// Represents a discovered feature or capability
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Feature {
    pub namespace: String,
}

/// Represents a discovered identity (client type, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    pub category: String,
    pub type_: String,
    pub name: Option<String>,
}

/// Handles XEP-0030: Service Discovery
#[derive(Clone)]
pub struct ServiceDiscovery {
    client: Arc<TokioMutex<AsyncClient>>,
    discovered_features: Arc<TokioMutex<std::collections::HashMap<String, HashSet<Feature>>>>,
    discovered_identities: Arc<TokioMutex<std::collections::HashMap<String, HashSet<Identity>>>>,
}

impl ServiceDiscovery {
    /// Creates a new ServiceDiscovery instance
    pub fn new(client: Arc<TokioMutex<AsyncClient>>) -> Self {
        Self { 
            client, 
            discovered_features: Arc::new(TokioMutex::new(std::collections::HashMap::new())),
            discovered_identities: Arc::new(TokioMutex::new(std::collections::HashMap::new())),
        }
    }

    /// Sends a service discovery info request to a JID
    pub async fn send_disco_info_request(&self, jid: &str) -> Result<()> {
        let mut client = self.client.lock().await;

        let iq_id = format!("disco_info_{}", uuid::Uuid::new_v4());
        let mut iq = Element::builder("iq", "jabber:client").build();
        iq.set_attr("type", "get");
        iq.set_attr("to", jid);
        iq.set_attr("id", &iq_id);

        let query = Element::builder("query", "http://jabber.org/protocol/disco#info").build();
        iq.append_child(query);

        client.send_stanza(iq).await?;
        info!("Sent service discovery info request to {}", jid);

        Ok(())
    }

    /// Sends a service discovery items request to a JID
    pub async fn send_disco_items_request(&self, jid: &str) -> Result<()> {
        let mut client = self.client.lock().await;

        let iq_id = format!("disco_items_{}", uuid::Uuid::new_v4());
        let mut iq = Element::builder("iq", "jabber:client").build();
        iq.set_attr("type", "get");
        iq.set_attr("to", jid);
        iq.set_attr("id", &iq_id);

        let query = Element::builder("query", "http://jabber.org/protocol/disco#items").build();
        iq.append_child(query);

        client.send_stanza(iq).await?;
        info!("Sent service discovery items request to {}", jid);

        Ok(())
    }

    /// Handles incoming service discovery responses
    pub async fn handle_disco_response(&self, stanza: &Element) -> Result<()> {
        if stanza.name() != "iq" {
            return Ok(()); // Not an IQ stanza
        }

        // Get the sender JID
        let from = match stanza.attr("from") {
            Some(jid) => jid,
            None => {
                //debug!("Received disco response without 'from' attribute");
                return Ok(());
            }
        };

        // Handle disco#info responses
        if let Some(query) = stanza.get_child("query", "http://jabber.org/protocol/disco#info") {
            //debug!("Received service discovery info response from {}", from);
            
            // Process the response to extract features
            let features = self.extract_features(query);
            let identities = self.extract_identities(query);
            
            // Store discovered features
            self.store_features(from, features.clone()).await;
            
            // Store discovered identities
            self.store_identities(from, identities.clone()).await;
            
            // Log capabilities
            self.log_capabilities(from, &features, &identities);
        } 
        // Handle disco#items responses
        else if let Some(query) = stanza.get_child("query", "http://jabber.org/protocol/disco#items") {
            //debug!("Received service discovery items response from {}", from);
            
            // Extract items (other entities that can be queried)
            let items = query.children()
                .filter(|child| child.name() == "item")
                .filter_map(|item| {
                    let jid = item.attr("jid")?;
                    let name = item.attr("name");
                    Some((jid, name))
                })
                .collect::<Vec<_>>();
            
            info!("Discovered {} items from {}", items.len(), from);
            
            // Log discovered items
            for (jid, name) in &items {
                if let Some(item_name) = name {
                    info!("Discovered item: {} ({})", jid, item_name);
                } else {
                    info!("Discovered item: {}", jid);
                }
            }
            
            // For servers, automatically query each discovered service
            if from.contains('.') && !from.contains('@') {
                //debug!("Auto-querying discovered services from server {}", from);
                for (jid, _) in items {
                    // Don't query ourselves
                    if jid.contains("@") {
                        continue;
                    }
                    
                    // Send a disco#info query to this item
                    if let Err(e) = self.send_disco_info_request(jid).await {
                        warn!("Failed to send disco query to service {}: {}", jid, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract features from a disco#info response
    fn extract_features(&self, query: &Element) -> HashSet<Feature> {
        let features = query.children()
            .filter(|child| child.name() == "feature")
            .filter_map(|feature| {
                feature.attr("var").map(|var| Feature { namespace: var.to_string() })
            })
            .collect();
        
        features
    }

    /// Extract identities from a disco#info response
    fn extract_identities(&self, query: &Element) -> HashSet<Identity> {
        let identities = query.children()
            .filter(|child| child.name() == "identity")
            .filter_map(|identity| {
                let category = identity.attr("category")?;
                let type_ = identity.attr("type")?;
                let name = identity.attr("name");
                
                Some(Identity {
                    category: category.to_string(),
                    type_: type_.to_string(),
                    name: name.map(ToString::to_string)
                })
            })
            .collect();
        
        identities
    }

    /// Store discovered features
    async fn store_features(&self, jid: &str, features: HashSet<Feature>) {
        let mut discovered_features = self.discovered_features.lock().await;
        discovered_features.insert(jid.to_string(), features);
    }

    /// Store discovered identities
    async fn store_identities(&self, jid: &str, identities: HashSet<Identity>) {
        let mut discovered_identities = self.discovered_identities.lock().await;
        discovered_identities.insert(jid.to_string(), identities);
    }

    /// Log capabilities of an entity
    fn log_capabilities(&self, jid: &str, features: &HashSet<Feature>, identities: &HashSet<Identity>) {
        // Determine if this is a server or a client
        let entity_type = if jid.contains('@') {
            "client"
        } else {
            "server"
        };

        info!("{} {} supports {} features and advertises {} identities", 
            entity_type, jid, features.len(), identities.len());
        
        // Log identities
        if !identities.is_empty() {
            info!("{} {} identities:", entity_type, jid);
            for identity in identities {
                if let Some(name) = &identity.name {
                    info!("  - {} / {} ({})", identity.category, identity.type_, name);
                } else {
                    info!("  - {} / {}", identity.category, identity.type_);
                }
            }
        }
        
        // Log supported features
        if !features.is_empty() {
            info!("{} {} features:", entity_type, jid);
            
            // Group features by category for cleaner logging
            let mut omemo_features = Vec::new();
            let mut xep_features = Vec::new();
            let mut pubsub_features = Vec::new();
            let mut other_features = Vec::new();
            
            for feature in features {
                let ns = &feature.namespace;
                if ns.contains("omemo") || ns.contains("axolotl") {
                    omemo_features.push(ns);
                } else if ns.starts_with("urn:xmpp:") {
                    xep_features.push(ns);
                } else if ns.contains("pubsub") {
                    pubsub_features.push(ns);
                } else {
                    other_features.push(ns);
                }
            }
            
            // Log OMEMO features first (they're most important for us)
            if !omemo_features.is_empty() {
                info!("  OMEMO features:");
                for ns in &omemo_features {
                    info!("    - {}", ns);
                }
            } else if entity_type == "server" {
                // Log explicitly when a server doesn't support OMEMO (important for compatibility)
                info!("  No OMEMO features found for {}", jid);
            }
            
            // Log XEP features
            if !xep_features.is_empty() {
                info!("  XEP features:");
                for ns in &xep_features {
                    info!("    - {}", ns);
                }
            }
            
            // Log PubSub features
            if !pubsub_features.is_empty() {
                info!("  PubSub features:");
                for ns in &pubsub_features {
                    info!("    - {}", ns);
                }
            }
            
            // Log other features
            if !other_features.is_empty() {
                info!("  Other features:");
                for ns in &other_features {
                    info!("    - {}", ns);
                }
            }
        }
    }

    /// Returns true if the entity supports OMEMO
    pub async fn supports_omemo(&self, jid: &str) -> bool {
        let discovered_features = self.discovered_features.lock().await;
        
        if let Some(features) = discovered_features.get(jid) {
            features.iter().any(|f| f.namespace == "urn:xmpp:omemo:1" || f.namespace == "eu.siacs.conversations.axolotl")
        } else {
            false
        }
    }

    /// Returns true if the entity supports message carbons
    pub async fn supports_carbons(&self, jid: &str) -> bool {
        let discovered_features = self.discovered_features.lock().await;
        
        if let Some(features) = discovered_features.get(jid) {
            features.iter().any(|f| f.namespace == "urn:xmpp:carbons:2")
        } else {
            false
        }
    }

    /// Advertises supported features for this client
    pub async fn advertise_features(&self) -> Result<()> {
        let mut client = self.client.lock().await;

        let mut iq = Element::builder("iq", "jabber:client").build();
        iq.set_attr("type", "set");
        iq.set_attr("id", "disco3");

        let mut query = Element::builder("query", "http://jabber.org/protocol/disco#info").build();

        // Add client identity
        let identity = Element::builder("identity", "")
            .attr("category", "client")
            .attr("type", "console")
            .attr("name", "Chatterbox XMPP Client")
            .build();
        query.append_child(identity);

        // Add supported features
        let features = vec![
            // Core XMPP and OMEMO
            "urn:xmpp:omemo:1",  // OMEMO encryption (standard namespace)
            "eu.siacs.conversations.axolotl", // Legacy OMEMO namespace for compatibility
            
            // Chat features
            "http://jabber.org/protocol/chatstates", // Chat states
            "urn:xmpp:receipts",  // Message receipts
            "urn:xmpp:carbons:2", // Message carbons
            
            // Service discovery
            "http://jabber.org/protocol/disco#info",
            "http://jabber.org/protocol/disco#items",
            
            // Message archive management
            "urn:xmpp:mam:2",     // Message Archive Management
            
            // PubSub related
            "http://jabber.org/protocol/pubsub", // PubSub core
        ];

        for feature in features {
            let feature_elem = Element::builder("feature", "").attr("var", feature).build();
            query.append_child(feature_elem);
        }

        iq.append_child(query);

        client.send_stanza(iq).await?;
        info!("Advertised supported features");

        Ok(())
    }

    /// Get all discovered features for a JID
    pub async fn get_features(&self, jid: &str) -> Option<Vec<String>> {
        let discovered_features = self.discovered_features.lock().await;
        
        if let Some(features) = discovered_features.get(jid) {
            Some(features.iter().map(|f| f.namespace.clone()).collect())
        } else {
            None
        }
    }

    /// Discover a roster contact's capabilities
    pub async fn discover_contact_capabilities(&self, contact_jid: &str) -> Result<()> {
        info!("Discovering capabilities for contact: {}", contact_jid);
        
        // Send a disco#info query to get contact's features
        self.send_disco_info_request(contact_jid).await?;
        
        // We won't wait for the response here, as it will be handled asynchronously
        // by the handle_disco_response method when it arrives
        
        Ok(())
    }

    /// Process a presence stanza that may contain entity capabilities
    pub async fn process_caps_in_presence(&self, presence: &Element) -> Result<()> {
        // Look for the 'c' element which indicates entity capabilities
        if let Some(caps) = presence.get_child("c", "http://jabber.org/protocol/caps") {
            // Get the sender JID
            let from = match presence.attr("from") {
                Some(jid) => jid,
                None => {
                    //debug!("Received presence without 'from' attribute");
                    return Ok(());
                }
            };
            
            // Extract the hash, node, and ver attributes
            let _node = caps.attr("node").unwrap_or("");
            let ver = caps.attr("ver").unwrap_or("");
            let _hash = caps.attr("hash").unwrap_or("");
            
            //debug!("Received entity capabilities from {}: node={}, ver={}, hash={}", from, node, ver, hash);
            
            // When we see a caps element, we should query the entity for its disco#info
            // This will help us determine what features they support
            if !ver.is_empty() {
                info!("Detected entity capabilities in presence from {}, querying for details", from);
                self.send_disco_info_request(from).await?;
            }
        }
        
        Ok(())
    }
}