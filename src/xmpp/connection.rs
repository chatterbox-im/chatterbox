// XMPP Connection management for Sermo
// Contains connect, disconnect, and connection helper methods for XMPPClient

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use std::time::Duration;
use std::str::FromStr;
use tokio_xmpp::{AsyncClient as XMPPAsyncClient, BareJid as TokioBareJid};
use crate::xmpp::XMPPClient;

/// Enum for representing client state
#[derive(Debug, Clone, PartialEq)]
pub enum ClientState {
    Connected,
    Disconnected,
    Connecting,
    Error,
    Unknown,
}

impl XMPPClient {
    pub async fn connect(&mut self, server: &str, username: &str, password: &str) -> Result<()> {
        let mut last_error = None;
        for attempt in 1..=3 {
            info!("Attempting to connect to XMPP server (attempt {}/3)...", attempt);
            
            // Check if the username already contains a domain part (has '@' character)
            let full_jid = if username.contains('@') {
                username.to_string()
            } else {
                format!("{}@{}", username, server)
            };
            
            // Store the JID we're using to connect
            self.jid = full_jid.clone();
            
            // Parse the JID using tokio-xmpp's BareJid type
            let tokio_jid = match TokioBareJid::from_str(&full_jid) {
                Ok(jid) => {
                    // Verify the JID has a node part
                    if jid.node_str().is_none() {
                        let err = anyhow!("Invalid JID format: Missing username part in '{}'", full_jid);
                        error!("{}", err);
                        return Err(err);
                    }
                    jid
                },
                Err(e) => {
                    let err = anyhow!("Invalid JID format: {}", e);
                    error!("Failed to parse JID '{}': {}", full_jid, e);
                    return Err(err);
                }
            };
            
            // Create the raw XMPP client
            let client = XMPPAsyncClient::new(tokio_jid, password);
            
            // Spawn the transport actor — it owns the AsyncClient exclusively.
            // No mutex needed: the transport multiplexes reads/writes via channels.
            let transport_handle = super::transport::spawn_transport(client);
            self.stanza_tx = Some(transport_handle.stanza_tx.clone());
            
            // Spawn the event processing loop (receives events from transport)
            let msg_tx_clone = self.msg_tx.clone();
            let pending_receipts_clone = self.pending_receipts.clone();
            let iq_registry_clone = self.iq_registry.clone();
            let shared_client_clone = self.shared_self.clone();
            let stanza_tx_clone = transport_handle.stanza_tx.clone();
            let (online_tx, online_rx) = tokio::sync::oneshot::channel();
            tokio::spawn(Self::handle_incoming_messages(
                stanza_tx_clone,
                transport_handle.event_rx,
                msg_tx_clone,
                pending_receipts_clone,
                iq_registry_clone,
                shared_client_clone,
                Some(online_tx),
            ));
            
            // Wait for connection
            match self.wait_for_connection(Duration::from_secs(10), online_rx).await {
                Ok(true) => {
                    info!("Connected to XMPP server successfully");
                    
                    // Perform XEP-0030 Service Discovery
                    if let Some(ref stanza_tx) = self.stanza_tx {
                        let service_discovery = crate::xmpp::discovery::ServiceDiscovery::new(stanza_tx.clone());
                        
                        // First, advertise our supported features
                        if let Err(e) = service_discovery.advertise_features().await {
                            warn!("Failed to advertise service discovery features: {}", e);
                        }
                        
                        // Query server domain for supported features
                        let server_domain = self.jid.split('@').nth(1).unwrap_or(server);
                        if let Err(e) = service_discovery.send_disco_info_request(server_domain).await {
                            warn!("Failed to query server features via Service Discovery: {}", e);
                        }
                        
                        // Query server for available items/services
                        if let Err(e) = service_discovery.send_disco_items_request(server_domain).await {
                            warn!("Failed to query server items via Service Discovery: {}", e);
                        }
                    }
                    
                    // Enable message carbons
                    match self.enable_carbons().await {
                        Ok(true) => info!("Message carbons enabled successfully during connect"),
                        Ok(false) => warn!("Message carbons enable request was sent but returned unexpected result"),
                        Err(e) => error!("Failed to enable message carbons during connect: {}", e),
                    }
                    
                    // Send initial presence to make client available for real-time message delivery
                    if let Err(e) = self.send_initial_presence().await {
                        error!("Failed to send initial presence: {}", e);
                    }
                    return Ok(());
                },
                Ok(false) => {
                    let err = anyhow!("Failed to establish connection with server");
                    error!("Failed to connect on attempt {}/3: Connection handshake failed", attempt);
                    last_error = Some(err);
                },
                Err(e) => {
                    error!("Failed to connect on attempt {}/3: {}", attempt, e);
                    last_error = Some(anyhow!("Connection error: {}", e));
                }
            }
            
            // Connection failed - clear the transport
            self.stanza_tx = None;
            
            // Implement backoff for retries
            if attempt < 3 {
                let backoff = Duration::from_millis(500 * 2u64.pow(attempt as u32));
                info!("Retrying connection in {:?}", backoff);
                tokio::time::sleep(backoff).await;
            }
        }
        
        // All attempts failed
        let err = last_error.unwrap_or_else(|| anyhow!("Failed to connect to XMPP server after 3 attempts"));
        error!("All connection attempts failed: {}", err);
        Err(err)
    }

    async fn wait_for_connection(&self, timeout: Duration, online_rx: tokio::sync::oneshot::Receiver<()>) -> Result<bool> {
        match tokio::time::timeout(timeout, online_rx).await {
            Ok(Ok(())) => Ok(true),
            Ok(Err(_)) => {
                error!("Connection event handler dropped before signaling online");
                Err(anyhow!("Connection handler terminated unexpectedly"))
            }
            Err(_) => {
                error!("Connection timed out after {:?}", timeout);
                Err(anyhow!("Connection timed out after {:?}", timeout))
            }
        }
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting from XMPP server");
        
        // Send unavailable presence before disconnecting
        if self.stanza_tx.is_some() {
            let presence = xmpp_parsers::Element::builder("presence", "jabber:client")
                .attr("type", "unavailable")
                .build();
            match self.send_stanza(presence) {
                Ok(_) => debug!("Sent unavailable presence"),
                Err(e) => warn!("Failed to send unavailable presence: {}", e),
            }
        }
        
        // Drop the sender — this signals the transport task to shut down
        self.stanza_tx = None;
        self.connected = false;
        
        Ok(())
    }
    
    /// Send initial presence to make the client available for receiving real-time messages
    pub async fn send_initial_presence(&self) -> Result<()> {
        let presence = xmpp_parsers::Element::builder("presence", "jabber:client").build();
        self.send_stanza(presence)
    }
}