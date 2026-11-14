import Foundation
import Testing
import CryptoKit
@testable import SSHProtocolKit

@Suite struct SessionBindParserTests {
    @Test func verifiesEd25519AndPreservesCompleteHostKey() throws {
        let key = Curve25519.Signing.PrivateKey()
        let host = "ssh-ed25519".lengthAndData + key.publicKey.rawRepresentation.lengthAndData
        let sessionID = Data(repeating: 1, count: 32)
        let signature = "ssh-ed25519".lengthAndData + (try key.signature(for: sessionID)).lengthAndData
        let data = "session-bind@openssh.com".lengthAndData + host.lengthAndData
            + sessionID.lengthAndData + signature.lengthAndData + Data([0])
        let context = try parse(data)
        #expect(context.hostKeyBlob == host)
        #expect(context.sessionID == sessionID)
        #expect(!context.forwarding)
    }

    @Test func verifiesECDSAWireFormat() throws {
        let key = P256.Signing.PrivateKey()
        let host = "ecdsa-sha2-nistp256".lengthAndData + "nistp256".lengthAndData
            + key.publicKey.x963Representation.lengthAndData
        let sessionID = Data(repeating: 2, count: 32)
        let raw = try key.signature(for: sessionID).rawRepresentation
        let integers = mpint(Data(raw.prefix(32))) + mpint(Data(raw.suffix(32)))
        let signature = "ecdsa-sha2-nistp256".lengthAndData + integers.lengthAndData
        var data = "session-bind@openssh.com".lengthAndData + host.lengthAndData
        data += sessionID.lengthAndData + signature.lengthAndData + Data([0])
        #expect(try parse(data).hostKeyBlob == host)
    }

    @Test func invalidAndUnsupportedBindingsHaveNoAuthorizationEvidence() throws {
        let key = Curve25519.Signing.PrivateKey()
        let host = "ssh-ed25519".lengthAndData + key.publicKey.rawRepresentation.lengthAndData
        let sessionID = Data(repeating: 3, count: 32)
        let badSignature = "ssh-ed25519".lengthAndData + Data(repeating: 0, count: 64).lengthAndData
        let invalid = "session-bind@openssh.com".lengthAndData + host.lengthAndData
            + sessionID.lengthAndData + badSignature.lengthAndData + Data([0])
        #expect(try parse(invalid).hostKeyBlob.isEmpty)
        let unsupported = "session-bind@openssh.com".lengthAndData
            + ("unknown".lengthAndData + Data([1]).lengthAndData).lengthAndData
            + sessionID.lengthAndData + ("unknown".lengthAndData + Data([1]).lengthAndData).lengthAndData + Data([0])
        #expect(try parse(unsupported).hostKeyBlob.isEmpty)
    }

    private func parse(_ data: Data) throws -> SSHAgent.ProtocolExtension.OpenSSHExtension.SessionBindContext {
        let request = try SSHAgentInputParser().protocolExtension(from: data)
        guard case .openSSH(.sessionBind(let context)) = request else {
            throw ParseFailure()
        }
        return context
    }

    private func mpint(_ bytes: Data) -> Data {
        var value = Data(bytes.drop(while: { $0 == 0 }))
        if let first = value.first, first >= 0x80 { value.insert(0, at: 0) }
        return value.lengthAndData
    }

    private struct ParseFailure: Error {}
}
