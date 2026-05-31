# Conversations Compatibility Checklist

Status of OMEMO interoperability with the [Conversations](https://conversations.im/) Android XMPP client.

## Protocol: Signal Wire Format

- [x] SignalMessage serialization: `version_byte (0x33) || protobuf || mac[8]`
- [x] PreKeySignalMessage serialization: `version_byte (0x33) || protobuf` (inner SignalMessage embedded as raw bytes)
- [x] Protobuf field tags match libsignal (ratchet_key=1, counter=2, prev_counter=3, ciphertext=4)
- [x] PreKey protobuf field tags match libsignal (pre_key_id=1, base_key=2, identity_key=3, message=4, registration_id=5, signed_pre_key_id=6)

## Protocol: X3DH Key Agreement

- [x] DH order: DH1=DH(IKa,SPKb), DH2=DH(EKa,IKb), DH3=DH(EKa,SPKb), DH4=DH(EKa,OPKb)
- [x] IKM = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4]
- [x] HKDF(salt=0x00*32, IKM, info="", L=32) for shared secret
- [x] Initiator performs sending DH ratchet step after X3DH (DH(new_ratchet, SPKb))

## Protocol: Double Ratchet

- [x] Chain key derivation: message_key=HMAC(CK, 0x01), next_CK=HMAC(CK, 0x02)
- [x] KDF_RK: HKDF(salt=root_key, IKM=dh_output, info="WhisperRatchet", L=64)
- [x] Message key expansion: HKDF(salt="", IKM=message_key, info="WhisperMessageKeys", L=80) → cipher_key[32] + mac_key[32] + iv[16]
- [x] DH ratchet: derive receive chain, generate new keypair, derive send chain
- [x] Skipped message keys with MAX_SKIP=1000

## Protocol: Inner Cipher (Key Transport)

- [x] AES-256-CBC with PKCS7 padding (cipher_key=expanded[0..32], iv=expanded[64..80])
- [x] MAC: HMAC-SHA256(mac_key, sender_ik || receiver_ik || version || proto), truncated to 8 bytes
- [x] MAC verification on received SignalMessages (before decryption)
- [x] PreKeySignalMessage embeds inner SignalMessage as raw bytes (no re-serialization/re-MAC)

## Protocol: OMEMO Bundle & Stanzas

- [x] Legacy OMEMO namespace: `eu.siacs.conversations.axolotl`
- [x] Bundle XML: `<bundle>` with `<identityKey>`, `<signedPreKeyPublic>`, `<signedPreKeySignature>`, `<prekeys>/<preKeyPublic>`
- [x] Message XML: `<encrypted>` → `<header sid="...">` → `<key rid="...">` + `<iv>` + `<payload>`
- [x] `prekey="true"` attribute on `<key>` elements containing PreKeySignalMessages
- [x] Base64 encoding for all key material in XML

## Protocol: Signed PreKey

- [x] XEdDSA signing (X25519 private key → Ed25519-compatible signature)
- [x] XEdDSA verification on received bundles
- [x] Hard failure on invalid or unverifiable signatures

## Protocol: One-Time PreKeys

- [x] OPK lookup by pre_key_id from received PreKeySignalMessage
- [x] OPK consumed (removed from local bundle) after session establishment
- [x] Republish bundle to server after OPK consumption
- [x] Replenish OPKs when supply drops below threshold

## Session Management

- [x] Initiator session creation (when sending to a new device)
- [x] Recipient session creation (when receiving a PreKeySignalMessage)
- [x] Session persistence to disk
- [x] Atomic session state persistence (crash-safe write-then-rename)
- [x] Session reset/rebuild on repeated decryption failures

## Device Discovery

- [x] Fetch device list via PEP (XEP-0163)
- [x] Publish own device to device list
- [x] Encrypt to all known devices of recipient
- [x] Encrypt to own other devices (message carbons)

## Remaining Work for Full Interop

- [x] Republish bundle after OPK consumption
- [x] OPK replenishment (generate + publish new OPKs)
- [x] Remove legacy AES-GCM decrypt fallback path (cleanup)
- [x] BTBV trust model: blind trust for first-seen devices, block after manual verification of any peer device
- [x] TrustLevel enum (Undecided/Trusted/Verified/Untrusted) with storage persistence
- [x] Skip encryption to explicitly untrusted devices
- [x] Integration test (`tests/conversations_compat_test.rs`): full round-trip + BTBV validation
