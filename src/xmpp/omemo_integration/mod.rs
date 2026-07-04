// XEP-0384: OMEMO Encryption Implementation
// https://xmpp.org/extensions/xep-0384.html

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

use xmpp_parsers::minidom::Element;
use xmpp_parsers::jid::BareJid as JidBare;

use crate::omemo::device_id::DeviceId;
use crate::omemo::OmemoManager;
use crate::omemo::OmemoPubSub;
use crate::xmpp::iq_registry::IqResponseRegistry;
use crate::xmpp::transport::StanzaTx;

mod message;
mod pubsub;
mod xmpp_client_impl;

// Re-export public items that external code references via crate::xmpp::omemo_integration::*
pub use message::{
    add_iv_to_header, create_omemo_header, extract_omemo_data, handle_omemo_message,
    parse_iv_from_header, process_incoming_omemo_message, publish_device_list, publish_key_bundle,
    XmppClient,
};
pub use pubsub::{
    element_to_xml_string, get_pubsub_response_from, publish_bundle_alternative_format,
    publish_bundle_alternative_format_with_client, publish_pubsub_item,
    publish_pubsub_item_device_list, publish_pubsub_item_device_list_with_client,
    publish_pubsub_item_with_client, request_pubsub_items, request_pubsub_items_with_client,
    store_pubsub_response_to,
};

/// Shared map for storing pubsub responses by IQ request ID.
/// The event loop writes into this; the bridge polls from it.
pub type PubSubResponses = Arc<TokioMutex<std::collections::HashMap<String, String>>>;

/// Create a new empty PubSubResponses map.
pub fn new_pubsub_responses() -> PubSubResponses {
    Arc::new(TokioMutex::new(std::collections::HashMap::new()))
}

/// Implementation of OmemoPubSub that delegates to the XMPP connection.
/// Holds the transport channel sender and the shared pubsub response map.
#[derive(Clone)]
pub struct XmppPubSubBridge {
    pub(super) stanza_tx: StanzaTx,
    pub(super) responses: PubSubResponses,
    pub(super) iq_registry: Arc<TokioMutex<IqResponseRegistry>>,
}

impl XmppPubSubBridge {
    pub fn new(
        stanza_tx: StanzaTx,
        responses: PubSubResponses,
        iq_registry: Arc<TokioMutex<IqResponseRegistry>>,
    ) -> Self {
        Self {
            stanza_tx,
            responses,
            iq_registry,
        }
    }
}

#[async_trait]
impl OmemoPubSub for XmppPubSubBridge {
    async fn request_items(&self, from: &str, node: &str) -> Result<String> {
        request_pubsub_items_with_client(&self.stanza_tx, &self.responses, from, node).await
    }

    async fn publish_item(
        &self,
        to: Option<&str>,
        node: &str,
        id: &str,
        payload: &str,
    ) -> Result<()> {
        publish_pubsub_item_with_client(&self.stanza_tx, to, node, id, payload).await
    }

    async fn publish_item_alternative(
        &self,
        to: Option<&str>,
        node: &str,
        id: &str,
        payload: &str,
    ) -> Result<()> {
        publish_bundle_alternative_format_with_client(&self.stanza_tx, to, node, id, payload).await
    }

    async fn publish_device_list(&self, device_ids: &[DeviceId]) -> Result<()> {
        // Try with publish-options first, then retry without on error.
        // This mirrors Conversations' approach: when the server returns
        // precondition-not-met (node config doesn't match publish-options),
        // we retry without publish-options to just publish the item as-is.
        let result = self.send_device_list_iq(device_ids, true).await;
        if result.is_ok() {
            return result;
        }
        info!("Device list publish with publish-options failed, retrying without publish-options (node may already exist with different config)");
        self.send_device_list_iq(device_ids, false).await
    }

    async fn delete_bundle(&self, device_id: DeviceId) -> Result<()> {
        self.send_bundle_delete_iq(device_id).await
    }
}

impl XmppPubSubBridge {
    async fn send_device_list_iq(
        &self,
        device_ids: &[DeviceId],
        with_publish_options: bool,
    ) -> Result<()> {
        use crate::xmpp::transport;
        use tokio::time::Duration;
        use uuid::Uuid;

        let iq_id = Uuid::new_v4().to_string();

        // Register for the IQ response BEFORE sending
        let rx = {
            let mut registry = self.iq_registry.lock().await;
            registry.register(iq_id.clone())
        };

        // Build the device list stanza
        let mut list_element =
            xmpp_parsers::minidom::Element::builder("list", "eu.siacs.conversations.axolotl").build();
        for device_id in device_ids {
            let device_element =
                xmpp_parsers::minidom::Element::builder("device", "eu.siacs.conversations.axolotl")
                    .attr("id".try_into().unwrap(), &device_id.to_string())
                    .build();
            list_element.append_child(device_element);
        }

        let item_element =
            xmpp_parsers::minidom::Element::builder("item", "http://jabber.org/protocol/pubsub")
                .attr("id".try_into().unwrap(), "current")
                .append(list_element)
                .build();

        let publish_element =
            xmpp_parsers::minidom::Element::builder("publish", "http://jabber.org/protocol/pubsub")
                .attr("node".try_into().unwrap(), "eu.siacs.conversations.axolotl.devicelist")
                .append(item_element)
                .build();

        let mut pubsub_element =
            xmpp_parsers::minidom::Element::builder("pubsub", "http://jabber.org/protocol/pubsub")
                .append(publish_element)
                .build();

        if with_publish_options {
            let publish_options = xmpp_parsers::minidom::Element::builder(
                "publish-options",
                "http://jabber.org/protocol/pubsub",
            )
            .append(
                xmpp_parsers::minidom::Element::builder("x", "jabber:x:data")
                    .attr("type".try_into().unwrap(), "submit")
                    .append(
                        xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                            .attr("var".try_into().unwrap(), "FORM_TYPE")
                            .attr("type".try_into().unwrap(), "hidden")
                            .append({
                                let mut v =
                                    xmpp_parsers::minidom::Element::builder("value", "jabber:x:data")
                                        .build();
                                v.append_text_node(
                                    "http://jabber.org/protocol/pubsub#publish-options",
                                );
                                v
                            })
                            .build(),
                    )
                    .append(
                        xmpp_parsers::minidom::Element::builder("field", "jabber:x:data")
                            .attr("var".try_into().unwrap(), "pubsub#access_model")
                            .append({
                                let mut v =
                                    xmpp_parsers::minidom::Element::builder("value", "jabber:x:data")
                                        .build();
                                v.append_text_node("open");
                                v
                            })
                            .build(),
                    )
                    .build(),
            )
            .build();
            pubsub_element.append_child(publish_options);
        }

        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), &iq_id)
            .append(pubsub_element)
            .build();

        info!(
            "Sending device list publish stanza with ID: {} (publish-options: {})",
            iq_id, with_publish_options
        );

        transport::send_stanza(&self.stanza_tx, iq)
            .map_err(|e| anyhow!("Failed to send device list publish stanza: {}", e))?;

        // Wait for server acknowledgment
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(response)) => {
                match response.attr("type") {
                    Some("result") => {
                        debug!("Device list publish confirmed by server (ID: {})", iq_id);
                        Ok(())
                    }
                    Some("error") => {
                        // Log the error details like Conversations does
                        let error_xml = element_to_xml_string(&response);
                        let is_precondition_not_met = error_xml.contains("precondition-not-met");
                        // Use warn (not error) when publish-options are set, since we'll
                        // retry without them — this is expected on servers where the node
                        // already exists with a different access_model.
                        if with_publish_options {
                            warn!(
                                "Server returned error for device list publish (publish-options: {}, precondition-not-met: {}): {}",
                                with_publish_options,
                                is_precondition_not_met,
                                &error_xml[..error_xml.len().min(500)]
                            );
                        } else {
                            error!(
                                "Server returned error for device list publish (publish-options: {}, precondition-not-met: {}): {}",
                                with_publish_options,
                                is_precondition_not_met,
                                &error_xml[..error_xml.len().min(500)]
                            );
                        }
                        Err(anyhow!("Server rejected device list publish"))
                    }
                    other => {
                        debug!("Unexpected IQ type {:?} for device list publish", other);
                        Ok(()) // Treat as success
                    }
                }
            }
            Ok(Err(_)) => {
                error!("IQ response channel closed while waiting for device list publish ack");
                Err(anyhow!(
                    "Channel closed waiting for device list publish response"
                ))
            }
            Err(_) => {
                error!(
                    "Timeout waiting for device list publish acknowledgment (ID: {})",
                    iq_id
                );
                Err(anyhow!(
                    "Timeout waiting for device list publish acknowledgment"
                ))
            }
        }
    }

    /// Send a PubSub owner `<delete>` IQ to remove the bundle node for a device.
    async fn send_bundle_delete_iq(&self, device_id: DeviceId) -> Result<()> {
        use crate::xmpp::transport;
        use tokio::time::Duration;
        use uuid::Uuid;

        let node = format!(
            "eu.siacs.conversations.axolotl.bundles:{}",
            device_id
        );
        let iq_id = Uuid::new_v4().to_string();

        let rx = {
            let mut registry = self.iq_registry.lock().await;
            registry.register(iq_id.clone())
        };

        let delete_element =
            xmpp_parsers::minidom::Element::builder("delete", "http://jabber.org/protocol/pubsub#owner")
                .attr("node".try_into().unwrap(), &node)
                .build();

        let pubsub_element =
            xmpp_parsers::minidom::Element::builder("pubsub", "http://jabber.org/protocol/pubsub#owner")
                .append(delete_element)
                .build();

        let iq = xmpp_parsers::minidom::Element::builder("iq", "jabber:client")
            .attr("type".try_into().unwrap(), "set")
            .attr("id".try_into().unwrap(), &iq_id)
            .append(pubsub_element)
            .build();

        transport::send_stanza(&self.stanza_tx, iq)
            .map_err(|e| anyhow!("Failed to send bundle delete stanza: {}", e))?;

        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(response)) => {
                match response.attr("type") {
                    Some("result") => {
                        debug!("Bundle node {} deleted from server", node);
                        Ok(())
                    }
                    Some("error") => {
                        // item-not-found is fine — the node was already gone
                        let xml = element_to_xml_string(&response);
                        if xml.contains("item-not-found") {
                            debug!("Bundle node {} not found on server (already deleted)", node);
                            Ok(())
                        } else {
                            warn!("Server returned error deleting bundle node {}: {}", node, &xml[..xml.len().min(300)]);
                            Ok(()) // Non-fatal: best-effort cleanup
                        }
                    }
                    _ => Ok(()),
                }
            }
            Ok(Err(_)) => Ok(()), // Channel closed — non-fatal
            Err(_) => {
                warn!("Timeout waiting for bundle delete ack (node {})", node);
                Ok(()) // Non-fatal: best-effort cleanup
            }
        }
    }
}

// Define the OmemoIntegration struct that will be implemented below
pub struct OmemoIntegration {
    manager: Arc<TokioMutex<OmemoManager>>,
    // The JID field is used to identify the user in OMEMO operations,
    // though it's currently not directly accessed in the implementation
    jid: JidBare,
}

impl OmemoIntegration {
    /// Get the device ID for this OMEMO instance
    pub async fn get_device_id(&self) -> Result<DeviceId> {
        let manager_guard = self.manager.lock().await;
        Ok(manager_guard.get_device_id())
    }

    #[allow(dead_code)]
    pub fn publish_device_list_via(&self, stanza_tx: &StanzaTx, device_id: DeviceId) -> Result<()> {
        use crate::xmpp::transport;

        // Get the bare JID and device ID
        let _bare_jid = self.jid.to_string();

        // Generate a unique ID for the IQ stanza
        let request_id = uuid::Uuid::new_v4().to_string();

        // Create the element structure directly
        let mut device_elem = Element::bare("device", "eu.siacs.conversations.axolotl");
        device_elem.set_attr(xmpp_parsers::minidom::rxml::Namespace::NONE, "id".try_into().unwrap(), device_id.to_string());

        let mut list_elem = Element::bare("list", "eu.siacs.conversations.axolotl");
        list_elem.append_child(device_elem);

        let mut item_elem = Element::bare("item", "http://jabber.org/protocol/pubsub");
        item_elem.set_attr(xmpp_parsers::minidom::rxml::Namespace::NONE, "id".try_into().unwrap(), "current");
        item_elem.append_child(list_elem);

        let mut publish_elem = Element::bare("publish", "http://jabber.org/protocol/pubsub");
        publish_elem.set_attr(xmpp_parsers::minidom::rxml::Namespace::NONE, "node".try_into().unwrap(), "eu.siacs.conversations.axolotl.devicelist");
        publish_elem.append_child(item_elem);

        let mut pubsub_elem = Element::bare("pubsub", "http://jabber.org/protocol/pubsub");
        pubsub_elem.append_child(publish_elem);

        let mut iq = Element::bare("iq", "jabber:client");
        iq.set_attr(xmpp_parsers::minidom::rxml::Namespace::NONE, "type".try_into().unwrap(), "set");
        iq.set_attr(xmpp_parsers::minidom::rxml::Namespace::NONE, "id".try_into().unwrap(), request_id.clone());
        iq.append_child(pubsub_elem);

        info!("Publishing device list via transport channel");

        transport::send_stanza(stanza_tx, iq)
            .map_err(|e| anyhow!("Failed to publish device list: {}", e))
    }
}
