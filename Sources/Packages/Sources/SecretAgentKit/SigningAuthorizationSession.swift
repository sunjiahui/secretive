import Foundation
import Darwin
import Security
import SettingsKit
import SSHProtocolKit

/// Fresh, bounded authorization evidence for one socket. Descriptive UI provenance is not an authorization token.
@MainActor public final class SigningAuthorizationSession {

    private let fileHandle: FileHandle
    private let initialPeer: ProcessIdentity?
    private var binding = SSHAuthenticationBinding()

    init(fileHandle: FileHandle) {
        self.fileHandle = fileHandle
        self.initialPeer = ProcessIdentity(pid: fileHandle.pidOfConnectedProcess)
    }

    func record(_ context: SSHAgent.ProtocolExtension.OpenSSHExtension.SessionBindContext) -> Bool {
        binding.record(hostKey: context.hostKeyBlob, sessionID: context.sessionID, forwarding: context.forwarding)
    }

    func isExempt(payload: Data, keyBlob: Data, policy: AuthenticationPolicy) -> Bool {
        guard policy.allowGitReads || !policy.programs.isEmpty else { return false }
        guard let initialPeer, fileHandle.pidOfConnectedProcess == initialPeer.pid,
              let peer = ProcessIdentity(pid: initialPeer.pid), peer.uid == geteuid(), peer.sameProcess(as: initialPeer),
              let chain = processChain(from: peer) else { return false }

        // A forwarded request still has a local ssh -> Terminal ancestry. It needs connection evidence too.
        let peerName = URL(fileURLWithPath: peer.path).lastPathComponent
        let sshNames: Set<String> = ["ssh", "sshd", "sshd-session"]
        if sshNames.contains(peerName) || binding.hasBindingAttempt {
            guard peer.path == "/usr/bin/ssh", peer.satisfies("anchor apple"),
                  binding.permits(payload: payload, keyBlob: keyBlob) else { return false }
        } else if chain.contains(where: { sshNames.contains(URL(fileURLWithPath: $0.path).lastPathComponent) }) {
            return false
        }

        for program in policy.programs {
            if chain.contains(where: { $0.path == program.executablePath && $0.satisfies(program.requirement) }) {
                return chain.allSatisfy { $0.isCurrent }
            }
        }
        guard policy.allowGitReads, peer.path == "/usr/bin/ssh",
              binding.permits(payload: payload, keyBlob: keyBlob) else { return false }
        // The nearest Git invocation wins. A nested push must not inherit an outer fetch's exemption.
        guard let git = chain.first(where: { URL(fileURLWithPath: $0.path).lastPathComponent == "git" }),
              ["/usr/bin/git", "/Library/Developer/CommandLineTools/usr/bin/git",
               "/Library/Developer/CommandLineTools/usr/libexec/git-core/git",
               "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
               "/Applications/Xcode.app/Contents/Developer/usr/libexec/git-core/git"].contains(git.path),
              git.satisfies("anchor apple"), let arguments = git.arguments,
              GitReadCommand.matches(arguments) else { return false }
        return chain.allSatisfy { $0.isCurrent }
    }

    private func processChain(from peer: ProcessIdentity) -> [ProcessIdentity]? {
        var chain = [peer]
        var seen: Set<Int32> = [peer.pid]
        for _ in 0..<31 {
            guard let last = chain.last else { return nil }
            if last.parentPID <= 1 { return chain }
            guard seen.insert(last.parentPID).inserted,
                  let parent = ProcessIdentity(pid: last.parentPID),
                  last.isCurrent else { return nil }
            chain.append(parent)
        }
        return nil
    }
}

private struct ProcessIdentity {
    let pid: Int32
    let parentPID: Int32
    let uid: UInt32
    let path: String
    let startSeconds: UInt64
    let startMicroseconds: UInt64

    init?(pid: Int32) {
        guard pid > 0 else { return nil }
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.size
        guard unsafe proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size)) == size else { return nil }
        var buffer = [UInt8](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE))
        let length = unsafe proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0, let end = buffer.firstIndex(of: 0),
              let path = String(bytes: buffer[..<end], encoding: .utf8), path.hasPrefix("/") else { return nil }
        self.pid = pid
        self.parentPID = Int32(info.pbi_ppid)
        self.uid = info.pbi_uid
        self.path = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
        self.startSeconds = info.pbi_start_tvsec
        self.startMicroseconds = info.pbi_start_tvusec
    }

    func sameProcess(as other: Self) -> Bool {
        pid == other.pid && uid == other.uid && path == other.path
            && startSeconds == other.startSeconds && startMicroseconds == other.startMicroseconds
    }

    var isCurrent: Bool {
        guard let current = Self(pid: pid) else { return false }
        return sameProcess(as: current) && parentPID == current.parentPID
    }

    func satisfies(_ text: String) -> Bool {
        guard isCurrent else { return false }
        var requirement: SecRequirement?
        guard unsafe SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        guard unsafe SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code, SecCodeCheckValidity(code, [], requirement) == errSecSuccess else { return false }
        return isCurrent
    }

    var arguments: [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = ProcessArguments.maximumBytes
        var buffer = [UInt8](repeating: 0, count: size)
        guard unsafe sysctl(&mib, UInt32(mib.count), &buffer, &size, nil, 0) == 0,
              size > 0, size <= buffer.count else { return nil }
        return ProcessArguments.decode(Array(buffer.prefix(size)))
    }
}
