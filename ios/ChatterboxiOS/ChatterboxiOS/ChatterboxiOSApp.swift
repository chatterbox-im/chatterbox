import SwiftUI

@main
struct ChatterboxiOSApp: App {
    @StateObject private var state = AppState()

    var body: some Scene {
        WindowGroup {
            Group {
                if state.isConnected {
                    ConversationListView()
                } else {
                    LoginView()
                }
            }
            .environmentObject(state)
            .animation(.easeInOut, value: state.isConnected)
        }
    }
}
