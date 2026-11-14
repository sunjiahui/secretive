import Foundation
import OSLog
import SecretKit
import CertificateKit

import CryptoKit

public protocol SSHAgentInputParserProtocol {

    func parse(data: Data) async throws -> SSHAgent.Request

}

public struct SSHAgentInputParser: SSHAgentInputParserProtocol {

    private let logger = Logger(subsystem: "com.maxgoedjen.secretive.secretagent", category: "InputParser")

    public init() {
        assert(Bundle.main.bundleURL.pathExtension == "xpc" || ProcessInfo.processInfo.processName == "xctest", "Potentially unsafe parsing code should run in an XPC service")
    }

    public func parse(data: Data) throws(AgentParsingError) -> SSHAgent.Request {
        logger.debug("Parsing new data")
        guard data.count > 4 else {
            throw .invalidData
        }
        let specifiedLength = unsafe (data[0..<4].bytes.unsafeLoad(as: UInt32.self).bigEndian) + 4
        let rawRequestInt = data[4]
        let remainingDataRange = 5..<min(Int(specifiedLength), data.count)
        lazy var body: Data = { Data(data[remainingDataRange]) }()
        switch rawRequestInt {
        case SSHAgent.Request.requestIdentities.protocolID:
            return .requestIdentities
        case SSHAgent.Request.signRequest(.empty).protocolID:
            do {
                return .signRequest(try signatureRequestContext(from: body))
            } catch {
                throw .openSSHReader(error)
            }
        case SSHAgent.Request.addIdentity.protocolID:
            return .addIdentity
        case SSHAgent.Request.removeIdentity.protocolID:
            return .removeIdentity
        case SSHAgent.Request.removeAllIdentities.protocolID:
            return .removeAllIdentities
        case SSHAgent.Request.addIDConstrained.protocolID:
            return .addIDConstrained
        case SSHAgent.Request.addSmartcardKey.protocolID:
            return .addSmartcardKey
        case SSHAgent.Request.removeSmartcardKey.protocolID:
            return .removeSmartcardKey
        case SSHAgent.Request.lock.protocolID:
            return .lock
        case SSHAgent.Request.unlock.protocolID:
            return .unlock
        case SSHAgent.Request.addSmartcardKeyConstrained.protocolID:
            return .addSmartcardKeyConstrained
        case SSHAgent.Request.protocolExtension(.empty).protocolID:
            return .protocolExtension(try protocolExtension(from: body))
        default:
            return .unknown(rawRequestInt)
        }
    }

}

extension SSHAgentInputParser {

    private enum Constants {
        static let userAuthMagic: UInt8 = 50 // SSH2_MSG_USERAUTH_REQUEST
        static let sshSigMagic = Data("SSHSIG".utf8)
    }

    func signatureRequestContext(from data: Data) throws(OpenSSHReaderError) -> SSHAgent.Request.SignatureRequestContext {
        let reader = OpenSSHReader(data: data)
        let rawKeyBlob = try reader.readNextChunk()
        let keyBlob = certificatePublicKeyBlob(from: rawKeyBlob) ?? rawKeyBlob
        let rawPayload = try reader.readNextChunk()
        let payload: SSHAgent.Request.SignatureRequestContext.SignaturePayload
        do {
            if rawPayload.count > 6 && rawPayload[0..<6] == Constants.sshSigMagic {
                payload = .init(raw: rawPayload, decoded: .sshSig(try sshSigPayload(from: rawPayload[6...])))
            } else {
                payload = .init(raw: rawPayload, decoded: .sshConnection(try sshConnectionPayload(from: rawPayload)))
            }
        } catch {
            payload = .init(raw: rawPayload, decoded: nil)
        }
        return SSHAgent.Request.SignatureRequestContext(keyBlob: keyBlob, dataToSign: payload)
    }

    func sshSigPayload(from data: Data) throws(OpenSSHReaderError) -> SSHAgent.Request.SignatureRequestContext.SignaturePayload.DecodedPayload.SSHSigPayload {
        // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L79
        let payloadReader = OpenSSHReader(data: data)
        let namespace = try payloadReader.readNextChunkAsString()
        _ = try payloadReader.readNextChunk() // reserved
        let hashAlgorithm = try payloadReader.readNextChunkAsString()
        let hash = try payloadReader.readNextChunk()
        return .init(
            namespace: namespace,
            hashAlgorithm: hashAlgorithm,
            hash: hash
        )
    }

    func sshConnectionPayload(from data: Data) throws(OpenSSHReaderError) -> SSHAgent.Request.SignatureRequestContext.SignaturePayload.DecodedPayload.SSHConnectionPayload {
        let payloadReader = OpenSSHReader(data: data)
        _ = try payloadReader.readNextChunk()
        let magic = try payloadReader.readNextBytes(as: UInt8.self, convertEndianness: false)
        guard magic == Constants.userAuthMagic else { throw .incorrectFormat }
        let username = try payloadReader.readNextChunkAsString()
        _ = try payloadReader.readNextChunkAsString() // "ssh-connection"
        _ = try payloadReader.readNextChunkAsString() // "publickey-hostbound-v00@openssh.com"
        let hasSignature = try payloadReader.readNextByteAsBool()
        let algorithm = try payloadReader.readNextChunkAsString()
        let publicKeyReader = try payloadReader.readNextChunkAsSubReader()
        _ = try publicKeyReader.readNextChunk()
        _ = try publicKeyReader.readNextChunk()
        let publicKey = try publicKeyReader.readNextChunk()
        let hostKeyReader = try payloadReader.readNextChunkAsSubReader()
        _ = try hostKeyReader.readNextChunk()
        let hostKey = try hostKeyReader.readNextChunk()
        return .init(
            username: username,
            hasSignature: hasSignature,
            publicKeyAlgorithm: algorithm,
            publicKey: publicKey,
            hostKey: hostKey,
        )
    }

    func protocolExtension(from data: Data) throws(AgentParsingError) -> SSHAgent.ProtocolExtension {
        do {
            let reader = OpenSSHReader(data: data)
            let nameRaw = try reader.readNextChunkAsString()
            let nameSplit = nameRaw.split(separator: "@")
            guard nameSplit.count == 2 else {
                throw AgentParsingError.invalidData
            }
            let (name, domain) = (nameSplit[0], nameSplit[1])
            switch domain {
            case SSHAgent.ProtocolExtension.OpenSSHExtension.domain:
                switch name {
                case SSHAgent.ProtocolExtension.OpenSSHExtension.sessionBind(.empty).name:
                    do {
                        let completeHostKey = try reader.readNextChunk()
                        let hostkeyBlob = OpenSSHReader(data: completeHostKey)
                        let hostKeyType = try hostkeyBlob.readNextChunkAsString()
                        let hostKeyData: Data
                        if hostKeyType.hasPrefix("ecdsa-sha2-") {
                            let curve = try hostkeyBlob.readNextChunkAsString()
                            guard hostKeyType == "ecdsa-sha2-" + curve else { throw AgentParsingError.invalidData }
                            hostKeyData = try hostkeyBlob.readNextChunk()
                        } else {
                            hostKeyData = try hostkeyBlob.readNextChunk()
                        }
                        let sessionID = try reader.readNextChunk()
                        let signatureBlob = try reader.readNextChunkAsSubReader()
                        let signatureType = try signatureBlob.readNextChunkAsString()
                        guard signatureType == hostKeyType else { throw AgentParsingError.invalidData }
                        let signature = try signatureBlob.readNextChunk()
                        let forwardingByte = try reader.readNextBytes(as: UInt8.self)
                        guard forwardingByte <= 1, reader.done, hostkeyBlob.done, signatureBlob.done,
                              !sessionID.isEmpty else { throw AgentParsingError.invalidData }
                        let forwarding = forwardingByte == 1
                        switch hostKeyType {
                        case "ssh-ed25519":
                            let hostKey = try CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: hostKeyData)
                            guard hostKey.isValidSignature(signature, for: sessionID) else {
                                throw AgentParsingError.incorrectSignature
                            }
                        case "ecdsa-sha2-nistp256":
                            let hostKey = try CryptoKit.P256.Signing.PublicKey(x963Representation: hostKeyData)
                            guard hostKey.isValidSignature(try .init(rawRepresentation: ecdsaSignature(signature, size: 32)), for: sessionID) else {
                                throw AgentParsingError.incorrectSignature
                            }
                        case "ecdsa-sha2-nistp384":
                            let hostKey = try CryptoKit.P384.Signing.PublicKey(x963Representation: hostKeyData)
                            guard hostKey.isValidSignature(try .init(rawRepresentation: ecdsaSignature(signature, size: 48)), for: sessionID) else {
                                throw AgentParsingError.incorrectSignature
                            }
                        case "ssh-mldsa-65":
                            if #available(macOS 26.0, *) {
                                let hostKey = try CryptoKit.MLDSA65.PublicKey(rawRepresentation: hostKeyData)
                                guard hostKey.isValidSignature(signature, for: sessionID) else {
                                    throw AgentParsingError.incorrectSignature
                                }
                            } else {
                                throw AgentParsingError.unhandledRequest
                            }
                        case "ssh-mldsa-87":
                            if #available(macOS 26.0, *) {
                                let hostKey = try CryptoKit.MLDSA65.PublicKey(rawRepresentation: hostKeyData)
                                guard hostKey.isValidSignature(signature, for: sessionID) else {
                                    throw AgentParsingError.incorrectSignature
                                }
                            } else {
                                throw AgentParsingError.unhandledRequest
                            }
                        case "ssh-rsa":
                            throw AgentParsingError.unhandledRequest
                        default:
                            throw AgentParsingError.unhandledRequest
                        }
                        let context = SSHAgent.ProtocolExtension.OpenSSHExtension.SessionBindContext(
                            hostKey: hostKeyData,
                            sessionID: sessionID,
                            signature: signature,
                            forwarding: forwarding,
                            hostKeyBlob: completeHostKey
                        )
                        return .openSSH(.sessionBind(context))
                    } catch {
                        return .openSSH(.sessionBind(.empty))
                    }
                default:
                    return .openSSH(.unknown(String(name)))
                }
            default:
                return .unknown(nameRaw)
            }

        } catch let error as OpenSSHReaderError {
            throw .openSSHReader(error)
        } catch let error as AgentParsingError {
            throw error
        } catch {
            throw .unknownRequest
        }
    }

    func certificatePublicKeyBlob(from hash: Data) -> Data? {
        let reader = OpenSSHReader(data: hash)
        do {
            let certType = try reader.readNextChunkAsString()
            guard let certType = OpenSSHCertificate.CertificateType(rawValue: certType) else { return nil }
            _ = try reader.readNextChunk() // nonce
            let curveIdentifier = try reader.readNextChunk()
            let publicKey = try reader.readNextChunk()
            let openSSHIdentifier = certType.keyIdentifier
            return openSSHIdentifier.lengthAndData +
            curveIdentifier.lengthAndData +
                publicKey.lengthAndData
            
        } catch {
            return nil
        }
    }

    private func ecdsaSignature(_ signature: Data, size: Int) throws(OpenSSHReaderError) -> Data {
        let reader = OpenSSHReader(data: signature)
        var result = Data()
        for _ in 0..<2 {
            var integer = try reader.readNextChunk()
            guard let first = integer.first, first < 0x80 else { throw .incorrectFormat }
            if first == 0 { integer.removeFirst() }
            guard !integer.isEmpty, integer.count <= size else { throw .incorrectFormat }
            result.append(Data(repeating: 0, count: size - integer.count))
            result.append(integer)
        }
        guard reader.done else { throw .incorrectFormat }
        return result
    }

}


extension SSHAgentInputParser {

    public enum AgentParsingError: Error, Codable {
        case unknownRequest
        case unhandledRequest
        case invalidData
        case incorrectSignature
        case openSSHReader(OpenSSHReaderError)
    }

}
