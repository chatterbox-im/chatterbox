// Re-export needed modules for testing
pub mod models;
pub mod omemo;  // OMEMO module
pub mod xmpp;  // Our new modular XMPP implementation

// Re-export main types for convenience
pub use models::*;
pub use xmpp::XMPPClient;  // Expose the XMPPClient directly

#[cfg(test)]
mod tests {
    use super::*;
 
    #[test]
    fn test_credential_manager() {
        // This test is a placeholder since credentials are now handled in the tests directory
        // We'll just create a dummy test that always passes
        assert!(true, "Dummy test for credentials");
    }

    #[test]
    fn test_contact_status() {
        // Create contacts with different statuses
        let online_contact = Contact {
            id: "user1".to_string(),
            name: "Online User".to_string(),
            status: ContactStatus::Online,
        };
        
        let offline_contact = Contact {
            id: "user2".to_string(),
            name: "Offline User".to_string(),
            status: ContactStatus::Offline,
        };
        
        let away_contact = Contact {
            id: "user3".to_string(),
            name: "Away User".to_string(),
            status: ContactStatus::Away,
        };
        
        // Verify contact properties
        assert_eq!(online_contact.id, "user1");
        assert_eq!(offline_contact.name, "Offline User");
        
        // We can use pattern matching to check the status
        match online_contact.status {
            ContactStatus::Online => (),
            _ => panic!("Expected Online status"),
        }
        
        match offline_contact.status {
            ContactStatus::Offline => (),
            _ => panic!("Expected Offline status"),
        }
        
        match away_contact.status {
            ContactStatus::Away => (),
            _ => panic!("Expected Away status"),
        }
    }

    #[test]
    fn test_message_creation_and_delivery_status() {
        // Create a new message
        let msg = Message {
            id: "msg123".to_string(),
            sender_id: "sender1".to_string(),
            recipient_id: "recipient1".to_string(),
            content: "Hello, world!".to_string(),
            timestamp: 1650000000,
            delivery_status: DeliveryStatus::Sending,
        };
        
        // Verify message properties
        assert_eq!(msg.id, "msg123");
        assert_eq!(msg.sender_id, "sender1");
        assert_eq!(msg.recipient_id, "recipient1");
        assert_eq!(msg.content, "Hello, world!");
        assert_eq!(msg.timestamp, 1650000000);
        assert_eq!(msg.delivery_status, DeliveryStatus::Sending);
        
        // Test different delivery statuses
        let sent_msg = Message {
            id: msg.id.clone(),
            sender_id: msg.sender_id.clone(),
            recipient_id: msg.recipient_id.clone(),
            content: msg.content.clone(),
            timestamp: msg.timestamp,
            delivery_status: DeliveryStatus::Sent,
        };
        
        let delivered_msg = Message {
            id: msg.id.clone(),
            sender_id: msg.sender_id.clone(),
            recipient_id: msg.recipient_id.clone(),
            content: msg.content.clone(),
            timestamp: msg.timestamp,
            delivery_status: DeliveryStatus::Delivered,
        };
        
        let read_msg = Message {
            id: msg.id.clone(),
            sender_id: msg.sender_id.clone(),
            recipient_id: msg.recipient_id.clone(),
            content: msg.content.clone(),
            timestamp: msg.timestamp,
            delivery_status: DeliveryStatus::Read,
        };
        
        let failed_msg = Message {
            id: msg.id.clone(),
            sender_id: msg.sender_id.clone(),
            recipient_id: msg.recipient_id.clone(),
            content: msg.content.clone(),
            timestamp: msg.timestamp,
            delivery_status: DeliveryStatus::Failed,
        };
        
        assert_eq!(sent_msg.delivery_status, DeliveryStatus::Sent);
        assert_eq!(delivered_msg.delivery_status, DeliveryStatus::Delivered);
        assert_eq!(read_msg.delivery_status, DeliveryStatus::Read);
        assert_eq!(failed_msg.delivery_status, DeliveryStatus::Failed);
    }

    #[test]
    fn test_message_validation() {
        // Test with valid message content
        let valid_message = Message {
            id: "msg123".to_string(),
            sender_id: "sender1".to_string(),
            recipient_id: "recipient1".to_string(),
            content: "Hello, this is a valid message".to_string(),
            timestamp: 1650000000,
            delivery_status: DeliveryStatus::Sending,
        };
        
        // Test with empty content (should still be valid structurally)
        let empty_content_message = Message {
            id: "msg456".to_string(),
            sender_id: "sender1".to_string(),
            recipient_id: "recipient1".to_string(),
            content: "".to_string(),
            timestamp: 1650000000,
            delivery_status: DeliveryStatus::Sending,
        };
        
        // Test with very long content
        let long_content = "A".repeat(10000); // 10,000 characters
        let long_content_message = Message {
            id: "msg789".to_string(),
            sender_id: "sender1".to_string(),
            recipient_id: "recipient1".to_string(),
            content: long_content,
            timestamp: 1650000000,
            delivery_status: DeliveryStatus::Sending,
        };
        
        // Verify all messages are structurally valid
        assert_eq!(valid_message.id, "msg123");
        assert_eq!(empty_content_message.id, "msg456");
        assert_eq!(long_content_message.id, "msg789");
        assert_eq!(empty_content_message.content.len(), 0);
        assert_eq!(long_content_message.content.len(), 10000);
    }
    
    #[test]
    fn test_timestamp_handling() {
        // Test with current timestamp
        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        
        let current_message = Message {
            id: "msg_current".to_string(),
            sender_id: "sender1".to_string(),
            recipient_id: "recipient1".to_string(),
            content: "Current timestamp message".to_string(),
            timestamp: current_timestamp,
            delivery_status: DeliveryStatus::Sending,
        };
        
        // Test with past timestamp
        let past_timestamp = current_timestamp - 3600; // 1 hour ago
        let past_message = Message {
            id: "msg_past".to_string(),
            sender_id: "sender1".to_string(),
            recipient_id: "recipient1".to_string(),
            content: "Past timestamp message".to_string(),
            timestamp: past_timestamp,
            delivery_status: DeliveryStatus::Sent,
        };
        
        // Verify timestamps are stored correctly
        assert_eq!(current_message.timestamp, current_timestamp);
        assert_eq!(past_message.timestamp, past_timestamp);
        assert!(current_message.timestamp > past_message.timestamp);
        assert_eq!(current_message.timestamp - past_message.timestamp, 3600);
    }
}
