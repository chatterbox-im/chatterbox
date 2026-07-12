import Combine
import SwiftUI

@main
struct ChatterboxiOSApp: App {
    @StateObject private var model = ChatModel()
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
        }
    }
}

@MainActor
class ChatModel: ObservableObject {
    let client = ChatterboxClient()
    @Published var messages: [String] = []
    @Published var isConnected = false
    @Published var error: String?

    func connect(server: String, username: String, password: String) async {
        do {
            try await client.connect(server: server, username: username, password: password)
            isConnected = true
            Task {
                while let event = await client.nextEvent() {
                    switch event {
                    case .message(let msg):
                        messages.append("\(msg.fromJid): \(msg.body)")
                    case .disconnected:
                        isConnected = false
                    default: break
                    }
                }
            }
        } catch {
            self.error = error.localizedDescription
        }
    }
}
