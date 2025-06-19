pub struct Contact {
    pub id: String,
    pub name: String,
    pub status: ContactStatus,
}

#[derive(Debug, Clone)]
pub enum ContactStatus {
    Online,
    Offline,
    Away,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub content: String,
    pub timestamp: u64,
    pub delivery_status: DeliveryStatus,
}

#[derive(Debug, Clone)]
pub struct PendingMessage {
    pub id: String,
    pub to: String,
    pub content: String,
    pub timestamp: u64,
    pub status: DeliveryStatus,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DeliveryStatus {
    Unknown = 0,   // Default/uncertain status
    Sending = 1,   // Message is being sent
    Sent = 2,      // Successfully sent to server
    Stored = 3,    // Stored on server (offline message)
    Delivered = 4, // Delivered to recipient's device 
    Read = 5,      // Read by recipient
    Failed = 6,    // Failed to send
}