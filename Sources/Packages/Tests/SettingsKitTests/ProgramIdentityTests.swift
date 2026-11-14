#if os(macOS)
import Foundation
import Testing
import SettingsKit

@Suite struct ProgramIdentityTests {
    @Test func capturesSystemProgramIdentity() throws {
        let program = try ProgramIdentity.trustedProgram(at: URL(fileURLWithPath: "/usr/bin/ssh"))
        #expect(program.executablePath == "/usr/bin/ssh")
        #expect(!program.requirement.isEmpty)
    }

    @Test func refusesMissingAndUnsignedPrograms() throws {
        #expect(throws: (any Error).self) {
            try ProgramIdentity.trustedProgram(at: URL(fileURLWithPath: "/does-not-exist/secretive-test"))
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let script = directory.appendingPathComponent("unsigned")
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: script)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        #expect(throws: (any Error).self) { try ProgramIdentity.trustedProgram(at: script) }
    }
}
#endif
