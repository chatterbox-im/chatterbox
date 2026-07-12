import SwiftUI

struct LoginView: View {
    @EnvironmentObject private var state: AppState

    @State private var server = ""
    @State private var username = ""
    @State private var password = ""
    @FocusState private var focus: Field?

    private enum Field { case server, username, password }

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("mysterymen.duckdns.org", text: $server)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .focused($focus, equals: .server)
                        .submitLabel(.next)
                        .onSubmit { focus = .username }
                }
                Section("Account") {
                    TextField("als", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.emailAddress)
                        .focused($focus, equals: .username)
                        .submitLabel(.next)
                        .onSubmit { focus = .password }
                    SecureField("Password", text: $password)
                        .focused($focus, equals: .password)
                        .submitLabel(.go)
                        .onSubmit { Task { await connect() } }
                }
                if let error = state.connectionError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .font(.footnote)
                    }
                }
            }
            .navigationTitle("Sign In")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    if state.isConnecting {
                        ProgressView()
                    } else {
                        Button("Connect") {
                            Task { await connect() }
                        }
                        .disabled(!isValid)
                    }
                }
            }
        }
        .onAppear { focus = .server }
    }

    private var isValid: Bool {
        !server.trimmingCharacters(in: .whitespaces).isEmpty &&
        !username.trimmingCharacters(in: .whitespaces).isEmpty &&
        !password.isEmpty
    }

    private func connect() async {
        await state.connect(
            server: server.trimmingCharacters(in: .whitespaces),
            username: username.trimmingCharacters(in: .whitespaces),
            password: password
        )
    }
}
