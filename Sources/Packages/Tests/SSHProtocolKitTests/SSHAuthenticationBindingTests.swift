import Foundation
import Testing
import SSHProtocolKit

@Suite struct SSHAuthenticationBindingTests {

    private let sessionID = Data(repeating: 42, count: 32)
    private var hostKey: Data { string("ssh-ed25519") + string(Data(repeating: 7, count: 32)) }
    private var key: Data { string("ecdsa-sha2-nistp256") + string("nistp256") + string(Data(repeating: 8, count: 65)) }

    @Test func directBindingPermitsOnlyItsAuthentication() {
        var binding = SSHAuthenticationBinding()
        #expect(!binding.permits(payload: payload(), keyBlob: key))
        let accepted = binding.record(hostKey: hostKey, sessionID: sessionID, forwarding: false)
        #expect(accepted)
        #expect(binding.permits(payload: payload(), keyBlob: key))
        #expect(binding.permits(payload: payload(hostbound: true), keyBlob: key))
        #expect(!binding.permits(payload: payload(session: Data([1])), keyBlob: key))
        #expect(!binding.permits(payload: payload(host: Data([1]), hostbound: true), keyBlob: key))
        #expect(!binding.permits(payload: payload(), keyBlob: Data([1])))
        #expect(!binding.permits(payload: payload() + Data([0]), keyBlob: key))
        #expect(!binding.permits(payload: Data(payload().dropLast()), keyBlob: key))
    }

    @Test func invalidForwardingAndRepeatedBindingsNeverExempt() {
        var invalid = SSHAuthenticationBinding()
        let emptyAccepted = invalid.record(hostKey: Data(), sessionID: Data(), forwarding: false)
        let retryAccepted = invalid.record(hostKey: hostKey, sessionID: sessionID, forwarding: false)
        #expect(!emptyAccepted)
        #expect(!retryAccepted)
        #expect(!invalid.permits(payload: payload(), keyBlob: key))
        var forwarded = SSHAuthenticationBinding()
        let forwardingAccepted = forwarded.record(hostKey: hostKey, sessionID: sessionID, forwarding: true)
        #expect(!forwardingAccepted)
        #expect(forwarded.hasBindingAttempt)
        let forwardingRetryAccepted = forwarded.record(hostKey: hostKey, sessionID: sessionID, forwarding: false)
        #expect(!forwardingRetryAccepted)
        var repeated = SSHAuthenticationBinding()
        let firstAccepted = repeated.record(hostKey: hostKey, sessionID: sessionID, forwarding: false)
        let duplicateAccepted = repeated.record(hostKey: hostKey, sessionID: sessionID, forwarding: false)
        #expect(firstAccepted)
        #expect(!duplicateAccepted)
        #expect(!repeated.permits(payload: payload(), keyBlob: key))
    }

    @Test func socketsDoNotShareBindings() {
        var first = SSHAuthenticationBinding()
        let second = SSHAuthenticationBinding()
        first.record(hostKey: hostKey, sessionID: sessionID, forwarding: false)
        #expect(first.permits(payload: payload(), keyBlob: key))
        #expect(!second.permits(payload: payload(), keyBlob: key))
        #expect(!second.hasBindingAttempt)
    }

    @Test func rejectsMalformedAndNonAuthenticationPayloads() {
        var binding = SSHAuthenticationBinding()
        binding.record(hostKey: hostKey, sessionID: sessionID, forwarding: false)
        #expect(!binding.permits(payload: payload(service: "other"), keyBlob: key))
        #expect(!binding.permits(payload: payload(method: "other"), keyBlob: key))
        #expect(!binding.permits(payload: payload(signed: 0), keyBlob: key))
        #expect(!binding.permits(payload: payload(signed: 2), keyBlob: key))
        #expect(!binding.permits(payload: payload(algorithm: "ssh-rsa"), keyBlob: key))
        #expect(!binding.permits(payload: Data([255, 255, 255, 255]), keyBlob: key))
        #expect(!binding.permits(payload: Data("SSHSIG".utf8), keyBlob: key))
        #expect(!binding.permits(payload: Data(repeating: 0, count: 1_048_577), keyBlob: key))
    }

    private func payload(session: Data? = nil, host: Data? = nil, hostbound: Bool = false,
                         service: String = "ssh-connection", method: String? = nil, signed: UInt8 = 1,
                         algorithm: String = "ecdsa-sha2-nistp256") -> Data {
        var data = string(session ?? sessionID)
        data += Data([50]) + string("git") + string(service)
        data += string(method ?? (hostbound ? "publickey-hostbound-v00@openssh.com" : "publickey"))
        data += Data([signed]) + string(algorithm) + string(key)
        if hostbound { data += string(host ?? hostKey) }
        return data
    }

    private func string(_ value: String) -> Data { string(Data(value.utf8)) }
    private func string(_ value: Data) -> Data {
        let count = UInt32(value.count)
        return Data([UInt8(truncatingIfNeeded: count >> 24), UInt8(truncatingIfNeeded: count >> 16),
                     UInt8(truncatingIfNeeded: count >> 8), UInt8(truncatingIfNeeded: count)]) + value
    }
}
