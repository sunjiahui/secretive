import Foundation
import Testing
@testable import SecretAgentKit

@Suite struct SigningRequestTracerTests {
    @Test func currentProcessPathCanBeRead() {
        let pid = ProcessInfo.processInfo.processIdentifier
        let process = SigningRequestTracer().process(from: pid)
        #expect(process.pid == pid)
        #expect(!process.path.isEmpty)
        #expect(process.path.hasPrefix("/"))
    }

    @Test func failedProcessLookupsAreUntrusted() {
        let tracer = SigningRequestTracer()
        for pid: Int32 in [0, -1, Int32.max] {
            let process = tracer.process(from: pid)
            #expect(!process.validSignature)
            #expect(process.parentPID == nil)
            #expect(process.path.isEmpty)
        }
    }

    @Test func nonSocketHasNoTrustedPeer() throws {
        let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: "/dev/null"))
        defer { try? file.close() }
        #expect(file.pidOfConnectedProcess == 0)
        let source = SigningRequestTracer().provenance(from: file)
        #expect(source.chain.count == 1)
        #expect(!source.intact)
    }
}
