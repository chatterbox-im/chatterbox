import SwiftUI

struct ChatView: View {
    let jid: String
    @EnvironmentObject private var state: AppState
    @State private var draft = ""
    @FocusState private var composerFocused: Bool

    private var messages: [FfiMessage] {
        state.conversations[jid] ?? []
    }

    private var contactName: String {
        if let name = state.contacts[jid]?.displayName, !name.isEmpty { return name }
        return jid.components(separatedBy: "@").first ?? jid
    }

    var body: some View {
        VStack(spacing: 0) {
            messageList
            Divider()
            composer
        }
        .navigationTitle(contactName)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { state.markRead(jid) }
    }

    // MARK: - Message list

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 2) {
                    ForEach(messages, id: \.id) { msg in
                        MessageBubble(
                            msg: msg,
                            isOwn: msg.fromJid.hasPrefix(state.ownJid.components(separatedBy: "/").first ?? state.ownJid)
                        )
                        .id(msg.id)
                    }
                }
                .padding(.vertical, 10)
            }
            .onAppear {
                scrollToBottom(proxy: proxy, animated: false)
            }
            .onChange(of: messages.count) {
                scrollToBottom(proxy: proxy, animated: true)
            }
        }
    }

    private func scrollToBottom(proxy: ScrollViewProxy, animated: Bool) {
        guard let last = messages.last else { return }
        if animated {
            withAnimation(.easeOut(duration: 0.2)) { proxy.scrollTo(last.id, anchor: .bottom) }
        } else {
            proxy.scrollTo(last.id, anchor: .bottom)
        }
    }

    // MARK: - Composer

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField("Message", text: $draft, axis: .vertical)
                .lineLimit(1...5)
                .textFieldStyle(.plain)
                .focused($composerFocused)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(
                    Color(.secondarySystemBackground),
                    in: RoundedRectangle(cornerRadius: 20)
                )

            Button { send() } label: {
                Image(systemName: "arrow.up.circle.fill")
                    .resizable()
                    .frame(width: 34, height: 34)
                    .foregroundStyle(draft.trimmingCharacters(in: .whitespaces).isEmpty ? .gray : .blue)
            }
            .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private func send() {
        let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty else { return }
        draft = ""
        Task { await state.sendMessage(to: jid, body: body) }
    }
}

// MARK: - Bubble

private struct MessageBubble: View {
    let msg: FfiMessage
    let isOwn: Bool

    var body: some View {
        HStack(alignment: .bottom) {
            if isOwn { Spacer(minLength: 64) }
            VStack(alignment: isOwn ? .trailing : .leading, spacing: 3) {
                Text(msg.body)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(
                        isOwn ? Color.blue : Color(.secondarySystemBackground),
                        in: BubbleShape(isOwn: isOwn)
                    )
                    .foregroundStyle(isOwn ? .white : .primary)
                    .textSelection(.enabled)

                HStack(spacing: 3) {
                    if msg.isEncrypted {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 9))
                    }
                    Text(
                        Date(timeIntervalSince1970: Double(msg.timestamp)),
                        format: .dateTime.hour().minute()
                    )
                    .font(.system(size: 10))
                    if isOwn {
                        Image(systemName: statusIcon)
                            .font(.system(size: 10))
                    }
                }
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)
            }
            if !isOwn { Spacer(minLength: 64) }
        }
        .padding(.horizontal, 8)
    }

    private var statusIcon: String {
        switch msg.status {
        case "delivered": return "checkmark.circle"
        case "read":      return "checkmark.circle.fill"
        case "failed":    return "exclamationmark.circle"
        default:          return "clock"      // "sent" — awaiting delivery
        }
    }
}

// MARK: - Bubble shape

private struct BubbleShape: Shape {
    let isOwn: Bool
    private let radius: CGFloat = 18
    private let tailWidth: CGFloat = 6

    func path(in rect: CGRect) -> Path {
        var r = rect
        if isOwn {
            r.size.width -= tailWidth
        } else {
            r.origin.x += tailWidth
            r.size.width -= tailWidth
        }
        var path = Path()
        path.addRoundedRect(in: r, cornerSize: CGSize(width: radius, height: radius))
        return path
    }
}
