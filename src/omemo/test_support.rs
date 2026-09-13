//! Shared test helpers: RecordingPubSub + make_manager.
//!
//! Replaces the three divergent MockPubSub copies in encrypt_decrypt_test.rs,
//! security_tests.rs, and session_proptest.rs.

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tempfile::TempDir;
use tokio::sync::Mutex;

use crate::omemo::device_id::DeviceId;
use crate::omemo::protocol::X3DHKeyBundle;
use crate::omemo::storage::OmemoStorage;
use crate::omemo::{OmemoManager, OmemoPubSub, OMEMO_NAMESPACE};

// ── Recorded log ──────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
pub(crate) struct Recorded {
    pub device_lists:    Vec<Vec<DeviceId>>,
    /// (node, payload) per publish_item call
    pub bundles:         Vec<(String, String)>,
    pub deleted_bundles: Vec<DeviceId>,
    /// (jid, node) per request_items call
    pub item_requests:   Vec<(String, String)>,
}

// ── RecordingPubSub ───────────────────────────────────────────────────────────

pub(crate) struct RecordingPubSub {
    pub responses:    Mutex<HashMap<String, String>>,
    pub log:          Mutex<Recorded>,
    pub fail_publish: AtomicBool,
}

impl RecordingPubSub {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            responses:    Mutex::new(HashMap::new()),
            log:          Mutex::new(Recorded::default()),
            fail_publish: AtomicBool::new(false),
        })
    }

    pub(crate) async fn add_device_list(&self, jid: &str, ids: &[u32]) {
        let devs: String = ids.iter()
            .map(|id| format!("<device id=\"{}\"/>", id))
            .collect();
        let xml = format!(
            "<items node=\"{ns}.devicelist\"><item>\
             <list xmlns=\"{ns}\">{devs}</list></item></items>",
            ns = OMEMO_NAMESPACE,
            devs = devs
        );
        let mut r = self.responses.lock().await;
        for node in crate::omemo::devicelist_node_variants() {
            r.insert(format!("{}|{}", jid, node), xml.clone());
        }
    }

    pub(crate) async fn add_bundle(&self, jid: &str, did: u32, bundle: &X3DHKeyBundle) {
        let xml = self.bundle_xml(did, bundle, None);
        for node in crate::omemo::bundle_node_variants(DeviceId::from(did)) {
            self.responses.lock().await.insert(format!("{}|{}", jid, node), xml.clone());
        }
    }

    /// Zeroed SPK signature — simulates a MITM that replaces the bundle.
    pub(crate) async fn add_bundle_with_bad_sig(&self, jid: &str, did: u32, bundle: &X3DHKeyBundle) {
        let xml = self.bundle_xml(did, bundle, Some(&[0u8; 64]));
        for node in crate::omemo::bundle_node_variants(DeviceId::from(did)) {
            self.responses.lock().await.insert(format!("{}|{}", jid, node), xml.clone());
        }
    }

    fn bundle_xml(&self, did: u32, bundle: &X3DHKeyBundle, override_sig: Option<&[u8]>) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        let ik  = b64.encode(&bundle.identity_key_pair.public_key);
        let spk = b64.encode(&bundle.signed_pre_key_pair.public_key);
        let sig = override_sig.map(|s| b64.encode(s))
            .unwrap_or_else(|| b64.encode(&bundle.signed_pre_key_signature));
        let pks: String = bundle.one_time_pre_key_pairs.iter()
            .map(|(id, kp)| format!(
                "<preKeyPublic preKeyId=\"{}\">{}</preKeyPublic>",
                id, b64.encode(&kp.public_key)))
            .collect();
        format!(
            "<items node=\"{ns}.bundles:{did}\"><item id=\"current\">\
             <bundle xmlns=\"{ns}\"><identityKey>{ik}</identityKey>\
             <signedPreKeyPublic signedPreKeyId=\"{spkid}\">{spk}</signedPreKeyPublic>\
             <signedPreKeySignature>{sig}</signedPreKeySignature>\
             <prekeys>{pks}</prekeys></bundle></item></items>",
            ns = OMEMO_NAMESPACE, did = did, ik = ik,
            spkid = bundle.signed_pre_key_id, spk = spk, sig = sig, pks = pks
        )
    }
}

#[async_trait]
impl OmemoPubSub for RecordingPubSub {
    async fn request_items(&self, jid: &str, node: &str) -> Result<String> {
        self.log.lock().await.item_requests.push((jid.to_string(), node.to_string()));
        let key = format!("{}|{}", jid, node);
        Ok(self.responses.lock().await.get(&key).cloned().unwrap_or_else(||
            "<iq type=\"error\"><error type=\"cancel\">\
             <item-not-found xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>\
             </error></iq>".to_string()))
    }

    // Records publish AND updates stored state so post-restart replacements work.
    async fn publish_item(&self, _to: Option<&str>, node: &str, _id: &str, payload: &str) -> Result<()> {
        if self.fail_publish.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected publish failure"));
        }
        self.log.lock().await.bundles.push((node.to_string(), payload.to_string()));
        let xml = format!("<items node=\"{}\">{}</items>", node, payload);
        let mut r = self.responses.lock().await;
        let matching: Vec<String> = r.keys()
            .filter(|k| k.splitn(2, '|').nth(1) == Some(node))
            .cloned().collect();
        for key in matching { r.insert(key, xml.clone()); }
        Ok(())
    }

    async fn publish_item_alternative(&self, _: Option<&str>, _: &str, _: &str, _: &str) -> Result<()> { Ok(()) }

    async fn publish_device_list(&self, device_ids: &[DeviceId]) -> Result<()> {
        if self.fail_publish.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected publish failure"));
        }
        self.log.lock().await.device_lists.push(device_ids.to_vec());
        Ok(())
    }

    async fn delete_bundle(&self, device_id: DeviceId) -> Result<()> {
        self.log.lock().await.deleted_bundles.push(device_id);
        Ok(())
    }
}

// ── Manager helpers ───────────────────────────────────────────────────────────

pub(crate) async fn make_manager(
    jid: &str,
    device_id: u32,
    pubsub: Arc<dyn OmemoPubSub>,
) -> (OmemoManager, TempDir) {
    let dir = TempDir::new().unwrap();
    let storage = OmemoStorage::new(Some(dir.path().to_path_buf())).unwrap();
    let mgr = OmemoManager::new(storage, jid.to_string(), Some(device_id), pubsub)
        .await
        .expect("OmemoManager::new");
    (mgr, dir)
}

/// Two managers sharing one RecordingPubSub; device lists pre-populated.
pub(crate) async fn make_pair(
    a_jid: &str, a_did: u32,
    b_jid: &str, b_did: u32,
) -> (OmemoManager, TempDir, OmemoManager, TempDir, Arc<RecordingPubSub>) {
    let ps = RecordingPubSub::new();
    let (mgr_a, dir_a) = make_manager(a_jid, a_did, ps.clone()).await;
    let (mgr_b, dir_b) = make_manager(b_jid, b_did, ps.clone()).await;
    ps.add_device_list(a_jid, &[a_did]).await;
    ps.add_device_list(b_jid, &[b_did]).await;
    ps.add_bundle(a_jid, a_did, mgr_a.key_bundle.as_ref().unwrap()).await;
    ps.add_bundle(b_jid, b_did, mgr_b.key_bundle.as_ref().unwrap()).await;
    (mgr_a, dir_a, mgr_b, dir_b, ps)
}

