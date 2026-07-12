import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: ChatModel

    var body: some View {
        NavigationStack {
            List(model.messages, id: \.self) { msg in
                Text(msg).font(.body)
            }
            .navigationTitle("Chatterbox")
            .safeAreaInset(edge: .bottom) {
                HStack {
                    Image(systemName: model.isConnected ? "wifi" : "wifi.slash")
                        .foregroundStyle(model.isConnected ? .green : .secondary)
                    Text(model.isConnected ? "Connected" : "Disconnected")
                        .foregroundStyle(.secondary)
                    if let err = model.error {
                        Text(err).foregroundStyle(.red).lineLimit(1)
                    }
                }
                .padding()
                .background(.bar)
            }
        }
        .onAppear {
            Task {
                await model.connect(
                    server: "example.com",
                    username: "alice@example.com",
                    password: "secret"
                )
            }
        }
    }
}
