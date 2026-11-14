import Foundation
import Testing
@testable import XPCWrappers

@Suite struct EmbeddedXPCServiceTests {

    @Test(arguments: ["SecretiveUpdater", "SecretAgentInputParser", "SecretiveCertificateParser", "SecretAgentHostsfileReader"])
    func customBuildUsesEmbeddedIdentifier(_ product: String) throws {
        try withApplication { application in
            let identifier = "com.example.Local.\(product)"
            try writeService(product, identifier: identifier, in: application)
            #expect(EmbeddedXPCService.identifier(for: "com.maxgoedjen.Secretive.\(product)", in: application) == identifier)
        }
    }

    @Test func upstreamIdentifierIsPreserved() throws {
        try withApplication { application in
            let identifier = "com.maxgoedjen.Secretive.SecretAgentInputParser"
            try writeService("SecretAgentInputParser", identifier: identifier, in: application)
            #expect(EmbeddedXPCService.identifier(for: identifier, in: application) == identifier)
        }
    }

    @Test func missingServiceRetainsRequestedName() throws {
        try withApplication { application in
            let name = "com.example.Missing"
            #expect(EmbeddedXPCService.identifier(for: name, in: application) == name)
        }
    }

    @Test func missingIdentifierRetainsRequestedName() throws {
        try withApplication { application in
            try writeService("Service", identifier: nil, in: application)
            #expect(EmbeddedXPCService.identifier(for: "com.example.Service", in: application) == "com.example.Service")
        }
    }

    @Test func pathComponentsCannotEscapeServiceDirectory() throws {
        try withApplication { application in
            #expect(EmbeddedXPCService.identifier(for: "com.example./Outside", in: application) == "com.example./Outside")
            #expect(EmbeddedXPCService.identifier(for: "", in: application).isEmpty)
        }
    }

    private func withApplication(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory.appendingPathComponent("应用 Local.app", isDirectory: true))
    }

    private func writeService(_ product: String, identifier: String?, in application: URL) throws {
        let contents = application.appendingPathComponent("Contents/XPCServices/\(product).xpc/Contents", isDirectory: true)
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        var info = ["CFBundleName": product, "CFBundlePackageType": "XPC!"]
        info["CFBundleIdentifier"] = identifier
        let data = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try data.write(to: contents.appendingPathComponent("Info.plist"))
    }
}
