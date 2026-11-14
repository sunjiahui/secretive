import Foundation

/// Authorization evidence belongs to one agent socket, never to an Agent shared by sockets.
public struct SSHAuthenticationBinding: Sendable {

    private enum State: Sendable {
        case unbound
        case authentication(hostKey: Data, sessionID: Data)
        case disabled
    }

    private var state: State = .unbound

    public init() {}

    /// Call only after verifying the host signature. Empty/invalid parser sentinels permanently disable exemptions.
    @discardableResult public mutating func record(hostKey: Data, sessionID: Data, forwarding: Bool) -> Bool {
        guard case .unbound = state, !hostKey.isEmpty, !sessionID.isEmpty, !forwarding else {
            state = .disabled
            return false
        }
        state = .authentication(hostKey: hostKey, sessionID: sessionID)
        return true
    }

    public var hasBindingAttempt: Bool {
        if case .unbound = state { return false }
        return true
    }

    /// Reparse the signed bytes rather than trusting descriptive metadata returned by the input parser.
    public func permits(payload: Data, keyBlob: Data) -> Bool {
        guard case let .authentication(hostKey, sessionID) = state,
              payload.count <= 1_048_576 else { return false }
        do {
            var reader = Reader(bytes: Array(payload))
            guard try reader.string() == sessionID, try reader.byte() == 50 else { return false }
            _ = try reader.string() // username
            guard try reader.string() == Data("ssh-connection".utf8) else { return false }
            let method = try reader.string()
            guard method == Data("publickey".utf8) || method == Data("publickey-hostbound-v00@openssh.com".utf8),
                  try reader.byte() == 1 else { return false }
            let algorithm = try reader.string()
            let payloadKey = try reader.string()
            var keyReader = Reader(bytes: Array(keyBlob))
            guard payloadKey == keyBlob, algorithm == (try keyReader.string()) else { return false }
            if method == Data("publickey-hostbound-v00@openssh.com".utf8) {
                guard try reader.string() == hostKey else { return false }
            }
            // Standard publickey has no host-key field: its session ID is bound by the verified KEX signature.
            return reader.finished
        } catch {
            return false
        }
    }

    private struct Reader {
        let bytes: [UInt8]
        var index = 0
        var finished: Bool { index == bytes.count }

        mutating func byte() throws -> UInt8 {
            guard index < bytes.count else { throw ParseError() }
            defer { index += 1 }
            return bytes[index]
        }

        mutating func string() throws -> Data {
            guard bytes.count - index >= 4 else { throw ParseError() }
            let length = bytes[index..<(index + 4)].reduce(0) { ($0 << 8) | Int($1) }
            index += 4
            guard length <= bytes.count - index else { throw ParseError() }
            defer { index += length }
            return Data(bytes[index..<(index + length)])
        }
    }

    private struct ParseError: Error {}
}
