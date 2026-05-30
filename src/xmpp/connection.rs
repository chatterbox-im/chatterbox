// XMPP Connection management for Sermo
// Contains connect, disconnect, and connection helper methods for XMPPClient

use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use std::str::FromStr;
use tokio::sync::Mutex as TokioMutex;
use tokio_xmpp::{AsyncClient as XMPPAsyncClient, Event as XMPPEvent, BareJid as TokioBareJid};
use crate::xmpp::XMPPClient;
use futures_util::Stream;
use futures_util::SinkExt; // For close() on AsyncClient

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
                //debug!("Username already contains domain part: {}", username);
                username.to_string()
            } else {
                //debug!("Adding server domain to username: {}@{}", username, server);
                format!("{}@{}", username, server)
            };
            
            // Store the JID we're using to connect
            self.jid = full_jid.clone();
            
            // Parse the JID using tokio-xmpp's BareJid type
            //debug!("Parsing JID: {}", full_jid);
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
            
            // Create client and spawn the event handler
            //debug!("Creating XMPP client with JID: {}", tokio_jid);
            let client = XMPPAsyncClient::new(tokio_jid, password);
            let client_arc = Arc::new(TokioMutex::new(client));
            let msg_tx_clone = self.msg_tx.clone();
            let pending_receipts_clone = self.pending_receipts.clone();
            tokio::spawn(Self::handle_incoming_messages(
                client_arc.clone(),
                msg_tx_clone,
                pending_receipts_clone,
            ));
            self.client = Some(client_arc);
            
            // Wait for connection
            match self.wait_for_connection(Duration::from_secs(10)).await {
                Ok(true) => {
                    info!("Connected to XMPP server successfully");
                    
                    // Perform XEP-0030 Service Discovery
                    if let Some(client_ref) = &self.client {
                        //debug!("Performing XEP-0030 Service Discovery");
                        let service_discovery = crate::xmpp::discovery::ServiceDiscovery::new(client_ref.clone());
                        
                        // First, advertise our supported features
                        if let Err(e) = service_discovery.advertise_features().await {
                            warn!("Failed to advertise service discovery features: {}", e);
                        } else {
                            //debug!("Successfully advertised client features via Service Discovery");
                        }
                        
                        // Query server domain for supported features
                        let server_domain = self.jid.split('@').nth(1).unwrap_or(server);
                        if let Err(e) = service_discovery.send_disco_info_request(server_domain).await {
                            warn!("Failed to query server features via Service Discovery: {}", e);
                        } else {
                            //debug!("Successfully sent Service Discovery info request to server");
                        }
                        
                        // Query server for available items/services
                        if let Err(e) = service_discovery.send_disco_items_request(server_domain).await {
                            warn!("Failed to query server items via Service Discovery: {}", e);
                        } else {
                            //debug!("Successfully sent Service Discovery items request to server");
                        }
                    }
                    
                    // After successful authentication and resource binding

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
            
            // Connection failed - clear the client
            self.client = None;
            
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

    async fn wait_for_connection(&self, timeout: Duration) -> Result<bool> {
        let client = self.client.as_ref().ok_or_else(|| anyhow!("Client not initialized"))?;
        let start_time = tokio::time::Instant::now();
        
        // Poll the stream non-blockingly until we see Online/Disconnected or timeout.
        // IMPORTANT: We must not drop a .next() future mid-poll as it corrupts
        // tokio_xmpp's internal state machine.
        while tokio::time::Instant::now() - start_time < timeout {
            let lock_result = tokio::time::timeout(
                Duration::from_millis(500),
                client.lock()
            ).await;
            
            match lock_result {
                Ok(mut client_guard) => {
                    let event = futures_util::future::poll_fn(|cx| {
                        match Pin::new(&mut *client_guard).poll_next(cx) {
                            Poll::Ready(event) => Poll::Ready(Some(event)),
                            Poll::Pending => Poll::Ready(None),
                        }
                    }).await;
                    
                    match event {
                        Some(Some(XMPPEvent::Online { .. })) => {
                            return Ok(true);
                        },
                        Some(Some(XMPPEvent::Disconnected(e))) => {
                            match e {
                                tokio_xmpp::Error::Auth(_) => {
                                    error!("Authentication failed - check username and password");
                                },
                                tokio_xmpp::Error::Io(ref io_err) => {
                                    error!("Network error during connection: {}", io_err);
                                    if io_err.kind() == std::io::ErrorKind::ConnectionRefused {
                                        error!("Connection refused - server may be down");
                                    } else if io_err.kind() == std::io::ErrorKind::TimedOut {
                                        error!("Connection timed out - check server address");
                                    }
                                },
                                tokio_xmpp::Error::Tls(ref err) => {
                                    error!("TLS error during connection: {}", err);
                                },
                                ref other => {
                                    error!("Connection error: {:?}", other);
                                }
                            }
                            return Err(anyhow!("Connection failed: {:?}", e));
                        },
                        Some(None) => {
                            error!("XMPP stream ended during connection attempt");
                            return Err(anyhow!("XMPP stream ended unexpectedly"));
                        },
                        Some(Some(_)) => {
                            // Other event (e.g. stanza arrived early), continue polling
                        },
                        None => {
                            // No event ready, sleep briefly
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                },
                Err(_) => {
                    // Lock acquisition timed out, retry
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        
        error!("Connection timed out after {:?}", timeout);
        Err(anyhow!("Connection timed out after {:?}", timeout))
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting from XMPP server");
        let client = match self.client.as_ref() {
            Some(c) => c,
            None => return Ok(()),
        };
        let mut _disconnect_result = Ok(());
        {
            let mut client_guard = match tokio::time::timeout(
                Duration::from_secs(5),
                client.lock()
            ).await {
                Ok(guard) => guard,
                Err(_) => return Err(anyhow!("Timed out acquiring client lock for disconnect")),
            };
            let presence = xmpp_parsers::Element::builder("presence", "jabber:client")
                .attr("type", "unavailable")
                .build();
            match client_guard.send_stanza(presence).await {
                Ok(_) => debug!("Sent unavailable presence"),
                Err(e) => warn!("Failed to send unavailable presence: {}", e),
            }
            _disconnect_result = match client_guard.close().await {
                Ok(_) => {
                    //debug!("Successfully closed XMPP stream");
                    Ok(())
                },
                Err(e) => {
                    error!("Error closing XMPP stream: {}", e);
                    Err(anyhow!("Error during disconnect: {}", e))
                },
            };
        }
        self.client = None;
        self.connected = false;
        _disconnect_result
    }
    
    /// Send initial presence to make the client available for receiving real-time messages
    pub async fn send_initial_presence(&self) -> Result<()> {
        if let Some(client) = &self.client {
            let mut client_guard = client.lock().await;
            super::presence::send_initial_presence(&mut *client_guard).await
        } else {
            Err(anyhow!("Client not initialized"))
        }
    }
}