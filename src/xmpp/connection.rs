// XMPP Connection management for Sermo
// Contains connect, disconnect, and connection helper methods for XMPPClient

use crate::xmpp::XMPPClient;
use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use std::str::FromStr;
use std::time::Duration;
use tokio_xmpp::{AsyncClient as XMPPAsyncClient, BareJid as TokioBareJid};

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
        info!("Connecting to XMPP server...");

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
                    let err = anyhow!(
                        "Invalid JID format: Missing username part in '{}'",
                        full_jid
                    );
                    error!("{}", err);
                    return Err(err);
                }
                jid
            }
            Err(e) => {
                let err = anyhow!("Invalid JID format: {}", e);
                error!("Failed to parse JID '{}': {}", full_jid, e);
                return Err(err);
            }
        };

        // Create a reconnecting transport. After the initial connection succeeds,
        // the transport automatically re-establishes the TCP/TLS/SASL session after
        // any mid-session drop, using exponential backoff.
        // Fatal errors (TLS cert, auth failure) are detected by the event loop:
        // it exits and drops event_rx, which causes the transport to shut down.
        let client = XMPPAsyncClient::new(tokio_jid.clone(), password);
        let reconnect_config = super::transport::ReconnectConfig {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            max_attempts: 0, // unlimited — fatal errors handled by event loop
            jid: tokio_jid,
            password: password.to_string(),
        };
        // Spawn the transport actor — it owns the AsyncClient exclusively.
        // No mutex needed: the transport multiplexes reads/writes via channels.
        let transport_handle =
            super::transport::spawn_transport_with_reconnect(client, reconnect_config);
        self.stanza_tx = Some(transport_handle.stanza_tx.clone());

        // Spawn the event processing loop — lives for the entire session,
        // surviving reconnects transparently.
        let msg_tx_clone = self.msg_tx.clone();
        let pending_receipts_clone = self.pending_receipts.clone();
        let iq_registry_clone = self.iq_registry.clone();
        let late_state_rx = self
            .late_state_tx
            .as_ref()
            .expect("late_state_tx must exist on the real client")
            .subscribe();
        let stanza_tx_clone = transport_handle.stanza_tx.clone();
        let (online_tx, online_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(Self::handle_incoming_messages(
            stanza_tx_clone,
            transport_handle.event_rx,
            msg_tx_clone,
            pending_receipts_clone,
            iq_registry_clone,
            late_state_rx,
            Some(online_tx),
        ));

        // Wait for the first Online event (or a fatal error / 20-second timeout).
        // Transient initial-connect failures are retried transparently by the transport.
        self.wait_for_connection(Duration::from_secs(20), online_rx)
            .await?;

        info!("Connected to XMPP server successfully");

        // Perform XEP-0030 Service Discovery
        if let Some(ref stanza_tx) = self.stanza_tx {
            let service_discovery =
                crate::xmpp::discovery::ServiceDiscovery::new(stanza_tx.clone());

            // First, advertise our supported features
            if let Err(e) = service_discovery.advertise_features().await {
                warn!("Failed to advertise service discovery features: {}", e);
            }

            // Query server domain for supported features
            let server_domain = self.jid.split('@').nth(1).unwrap_or(server);
            if let Err(e) = service_discovery
                .send_disco_info_request(server_domain)
                .await
            {
                warn!(
                    "Failed to query server features via Service Discovery: {}",
                    e
                );
            }

            // Query server for available items/services
            if let Err(e) = service_discovery
                .send_disco_items_request(server_domain)
                .await
            {
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

        Ok(())
    }

    async fn wait_for_connection(
        &self,
        timeout: Duration,
        online_rx: tokio::sync::oneshot::Receiver<Result<(), String>>,
    ) -> Result<()> {
        match tokio::time::timeout(timeout, online_rx).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(msg))) => {
                error!("Connection failed before online: {}", msg);
                Err(anyhow!("{}", msg))
            }
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
