import SwiftUI

struct ConversationListView: View {
    @EnvironmentObject private var state: AppState
    @State private var newJid = ""
    @State private var showNewChat = false
    @State private var path = NavigationPath()

    var body: some View {
        NavigationStack(path: $path) {
            list
                .navigationDestination(for: String.self) { jid in
                    ChatView(jid: jid)
                }
        }
    }

    private var list: some View {
        List {
            ForEach(state.sortedConversations, id: \.jid) { item in
                NavigationLink(value: item.jid) {
                    ConversationRow(
                        jid: item.jid,
                        contact: state.contacts[item.jid],
                        lastMessage: item.lastMessage,
                        unread: state.unread[item.jid] ?? 0
                    )
                }
            }
        }
        .listStyle(.plain)
        .navigationTitle("Chatterbox")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showNewChat = true } label: {
                    Image(systemName: "square.and.pencil")
                }
            }
            ToolbarItem(placement: .bottomBar) {
                HStack(spacing: 5) {
                    Circle()
                        .fill(state.isConnected ? Color.green : Color.gray)
                        .frame(width: 8, height: 8)
                    Text(state.isConnected ? "Connected" : "Disconnected")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .alert("New Conversation", isPresented: $showNewChat) {
            TextField("user@example.com", text: $newJid)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.emailAddress)
            Button("Open") {
                let jid = newJid.trimmingCharacters(in: .whitespaces)
                newJid = ""
                guard !jid.isEmpty else { return }
                if state.conversations[jid] == nil {
                    state.conversations[jid] = []
                }
                path.append(jid)
            }
            Button("Cancel", role: .cancel) { newJid = "" }
        } message: {
            Text("Enter the JID of the person you want to chat with.")
        }
        .overlay {
            if state.sortedConversations.isEmpty {
                ContentUnavailableView(
                    "No Conversations",
                    systemImage: "bubble.left.and.bubble.right",
                    description: Text("Tap ✏ to start a new conversation.")
                )
            }
        }
    }
}

// MARK: - Row

private struct ConversationRow: View {
    let jid: String
    let contact: FfiContact?
    let lastMessage: FfiMessage
    let unread: Int

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            // Avatar with presence dot
            ZStack(alignment: .bottomTrailing) {
                Image(systemName: "person.circle.fill")
                    .resizable()
                    .frame(width: 46, height: 46)
                    .foregroundStyle(.secondary)
                Circle()
                    .fill(presenceColor)
                    .frame(width: 13, height: 13)
                    .overlay(Circle().stroke(Color(.systemBackground), lineWidth: 2))
            }

            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline) {
                    Text(displayName)
                        .font(.headline)
                        .lineLimit(1)
                    Spacer()
                    Text(formattedTime)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                HStack(alignment: .firstTextBaseline) {
                    Text(lastMessage.body)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    Spacer()
                    if unread > 0 {
                        Text("\(min(unread, 99))")
                            .font(.caption2.bold())
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(.blue, in: Capsule())
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }

    private var displayName: String {
        contact?.displayName.isEmpty == false
            ? contact!.displayName
            : (jid.components(separatedBy: "@").first ?? jid)
    }

    private var presenceColor: Color {
        switch contact?.status {
        case "online":  return .green
        case "away":    return .yellow
        default:        return .gray
        }
    }

    private var formattedTime: String {
        let date = Date(timeIntervalSince1970: Double(lastMessage.timestamp))
        return Calendar.current.isDateInToday(date)
            ? date.formatted(.dateTime.hour().minute())
            : date.formatted(.dateTime.month().day())
    }
}
