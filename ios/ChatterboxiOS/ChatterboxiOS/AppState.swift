import Combine
import SwiftUI

@MainActor
class AppState: ObservableObject {
    let client = ChatterboxClient()

    // MARK: - Connection
    @Published var isConnected = false
    @Published var isConnecting = false
    @Published var connectionError: String?
    private(set) var ownJid = ""

    // MARK: - Roster
    /// Contacts keyed by bare JID.
    @Published var contacts: [String: FfiContact] = [:]

    // MARK: - Conversations
    /// Messages keyed by the *partner's* bare JID.
    @Published var conversations: [String: [FfiMessage]] = [:]
    /// Unread message counts keyed by partner JID.
    @Published var unread: [String: Int] = [:]

    // MARK: - Actions

    func connect(server: String, username: String, password: String) async {
        isConnecting = true
        connectionError = nil
        do {
            try await client.connect(server: server, username: username, password: password)
            ownJid = username.contains("@") ? username : "\(username)@\(server)"
            isConnected = true
            if let fetched = try? await client.getContacts() {
                for c in fetched { contacts[c.jid] = c }
            }
            startEventLoop()
        } catch {
            connectionError = error.localizedDescription
        }
        isConnecting = false
    }

    func sendMessage(to jid: String, body: String) async {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        // Optimistic local echo before the server round-trip
        let echo = FfiMessage(
            id: UUID().uuidString,
            fromJid: ownJid,
            toJid: jid,
            body: trimmed,
            timestamp: Int64(Date().timeIntervalSince1970),
            isEncrypted: true,
            status: "sent"
        )
        append(echo, partner: jid)
        try? await client.sendMessage(toJid: jid, body: trimmed)
    }

    func markRead(_ jid: String) {
        unread[jid] = 0
    }

    func disconnect() async {
        await client.disconnect()
        isConnected = false
    }

    // MARK: - Derived

    /// Conversations sorted newest-first, for the conversation list.
    var sortedConversations: [(jid: String, lastMessage: FfiMessage)] {
        conversations.compactMap { jid, msgs in
            msgs.last.map { (jid: jid, lastMessage: $0) }
        }
        .sorted { $0.lastMessage.timestamp > $1.lastMessage.timestamp }
    }

    // MARK: - Private

    private func startEventLoop() {
        Task {
            while let event = await client.nextEvent() {
                handle(event)
            }
            isConnected = false
        }
    }

    private func handle(_ event: FfiEvent) {
        switch event {
        case .message(let msg):
            let partner = partnerJid(for: msg)
            append(msg, partner: partner)
            unread[partner, default: 0] += 1
        case .contactUpdate(let contact):
            contacts[contact.jid] = contact
        case .disconnected:
            isConnected = false
        }
    }

    private func partnerJid(for msg: FfiMessage) -> String {
        let bare = msg.fromJid.components(separatedBy: "/").first ?? msg.fromJid
        return bare == ownJid
            ? (msg.toJid.components(separatedBy: "/").first ?? msg.toJid)
            : bare
    }

    private func append(_ msg: FfiMessage, partner: String) {
        conversations[partner, default: []].append(msg)
    }
}
