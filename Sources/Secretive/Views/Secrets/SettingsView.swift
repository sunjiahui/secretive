import SwiftUI
import SettingsKit
import AppKit

struct SettingsView: View {

    @Environment(\.settingsStore) var settingsStore
    @State private var policy = AuthenticationPolicy()
    @State private var selectedProgram: String?
    @State private var loaded = false
    @State private var errorText: String?

    var body: some View {
        Form {
            Section {
                Toggle(.settingsAllowGitReads, isOn: Binding(
                    get: { policy.allowGitReads },
                    set: { value in
                        var updated = policy
                        updated.allowGitReads = value
                        save(updated)
                    }
                ))
                Text(.settingsGitReadsDescription)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } header: {
                Text(.settingsAuthenticationExemptions)
            } footer: {
                Text(.settingsApplicationManagedDescription)
            }
            .disabled(!loaded)
            Section {
                List(policy.programs, selection: $selectedProgram) { program in
                    VStack(alignment: .leading) {
                        Text(verbatim: program.name)
                        Text(verbatim: program.executablePath)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                    }
                    .tag(program.id)
                }
                .frame(minHeight: 140)
                HStack {
                    Button(.settingsAddProgram, systemImage: "plus", action: addProgram)
                    Button(.settingsRemoveProgram, systemImage: "minus", action: removeProgram)
                        .disabled(selectedProgram == nil)
                }
                Text(.settingsTrustedProgramsDescription)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } header: {
                Text(.settingsTrustedPrograms)
            }
            .disabled(!loaded)
            if let errorText {
                Text(verbatim: errorText)
                    .errorStyle()
            }
            if !loaded {
                Button(.settingsReload, action: load)
            }
        }
        .disabled(!loaded && errorText == nil)
        .formStyle(.grouped)
        .padding()
        .frame(minWidth: 600, minHeight: 540)
        .onAppear(perform: load)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in load() }
    }

    private func load() {
        do {
            policy = try settingsStore.loadAuthenticationPolicy()
            loaded = true
            errorText = nil
        } catch {
            loaded = false
            errorText = error.localizedDescription
        }
    }

    private func save(_ updated: AuthenticationPolicy) {
        guard loaded else { return }
        do {
            try settingsStore.saveAuthenticationPolicy(updated)
            policy = updated
            errorText = nil
        } catch {
            errorText = error.localizedDescription
        }
    }

    private func addProgram() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let program = try ProgramIdentity.trustedProgram(at: url)
            var updated = policy
            updated.programs.removeAll { $0.id == program.id }
            updated.programs.append(program)
            save(updated)
        } catch {
            errorText = error.localizedDescription
        }
    }

    private func removeProgram() {
        guard let selectedProgram else { return }
        var updated = policy
        updated.programs.removeAll { $0.id == selectedProgram }
        save(updated)
        self.selectedProgram = nil
    }
}
