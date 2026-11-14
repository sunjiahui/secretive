import Foundation
import AppKit
import Security
import SecretKit

/// An object responsible for generating ``SecretKit.SigningRequestProvenance`` objects.
struct SigningRequestTracer {
}

extension SigningRequestTracer {

    /// Generates a ``SecretKit.SigningRequestProvenance`` from a ``FileHandle``.
    /// - Parameter fileHandle: The reader involved in processing the request.
    /// - Returns: A ``SecretKit.SigningRequestProvenance`` describing the origin of the request.
    func provenance(from fileHandle: FileHandle) -> SigningRequestProvenance {
        let firstInfo = process(from: fileHandle.pidOfConnectedProcess)
        var provenance = SigningRequestProvenance(root: firstInfo)
        var seen: Set<Int32> = [firstInfo.pid]
        while provenance.chain.count < 32,
              NSRunningApplication(processIdentifier: provenance.origin.pid) == nil,
              let parentPID = provenance.origin.parentPID, parentPID > 0, seen.insert(parentPID).inserted {
            provenance.chain.append(process(from: parentPID))
        }
        return provenance
    }

    /// Generates a `kinfo_proc` representation of the provided process ID.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: a `kinfo_proc` struct describing the process ID.
    func pidAndNameInfo(from pid: Int32) -> kinfo_proc? {
        guard pid > 0 else { return nil }
        var info = unsafe kinfo_proc()
        var len = unsafe MemoryLayout<kinfo_proc>.size
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard unsafe sysctl(&name, UInt32(name.count), &info, &len, nil, 0) == 0,
              len == (unsafe MemoryLayout<kinfo_proc>.size) else { return nil }
        return unsafe info
    }

    /// Generates a ``SecretKit.SigningRequestProvenance.Process`` from a provided process ID.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: A ``SecretKit.SigningRequestProvenance.Process`` describing the process.
    func process(from pid: Int32) -> SigningRequestProvenance.Process {
        guard let pidAndNameInfo = self.pidAndNameInfo(from: pid) else {
            return .init(pid: pid, processName: "Unknown", appName: nil, iconURL: nil, path: "", validSignature: false, parentPID: nil)
        }
        let ppid = unsafe pidAndNameInfo.kp_eproc.e_ppid != 0 ? pidAndNameInfo.kp_eproc.e_ppid : nil
        // libproc's maximum is 4 * MAXPATHLEN; the compound C macro may not be imported into Swift.
        var pathBuffer = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = unsafe proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        let path = length > 0 ? String(decoding: pathBuffer.prefix(while: { $0 != 0 }), as: UTF8.self) : ""
        let procName = URL(fileURLWithPath: path).lastPathComponent
        var secCode: SecCode?
        let flags: SecCSFlags = [.considerExpiration, .enforceRevocationChecks]
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        let status = unsafe SecCodeCopyGuestWithAttributes(nil, attributes, [], &secCode)
        let valid = status == errSecSuccess && secCode.map { SecCodeCheckValidity($0, flags, nil) == errSecSuccess } == true
        return SigningRequestProvenance.Process(pid: pid, processName: procName, appName: appName(for: pid), iconURL: iconURL(for: pid), path: path, validSignature: valid, parentPID: ppid)
    }

    /// Looks up the URL for the icon of a process ID, if it has one.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: A URL to the icon, if the process has one.
    func iconURL(for pid: Int32) -> URL? {
        do {
            if let app = NSRunningApplication(processIdentifier: pid), let icon = app.icon?.tiffRepresentation {
                let temporaryURL = URL(fileURLWithPath: (NSTemporaryDirectory() as NSString).appendingPathComponent("\(app.bundleIdentifier ?? UUID().uuidString).png"))
                if FileManager.default.fileExists(atPath: temporaryURL.path) {
                    return temporaryURL
                }
                let bitmap = NSBitmapImageRep(data: icon)
                try bitmap?.representation(using: .png, properties: [:])?.write(to: temporaryURL)
                return temporaryURL
            }
        } catch {
        }
        return nil
    }

    /// Looks up the application name of a process ID, if it has one.
    /// - Parameter pid: The process ID to look up.
    /// - Returns: The process's display name, if the process has one.
    func appName(for pid: Int32) -> String? {
        NSRunningApplication(processIdentifier: pid)?.localizedName
    }

}
