import Foundation
import Security

/// Captures a code-signing requirement when a user selects a program.
public enum ProgramIdentity {

    public static func trustedProgram(at url: URL) throws -> AuthenticationPolicy.TrustedProgram {
        let executable = (url.pathExtension == "app" ? Bundle(url: url)?.executableURL : url)?
            .resolvingSymlinksInPath().standardizedFileURL
        guard let executable, FileManager.default.isExecutableFile(atPath: executable.path) else {
            throw IdentityError.invalidProgram
        }
        var code: SecStaticCode?
        try check(unsafe SecStaticCodeCreateWithPath(executable as CFURL, [], &code))
        guard let code else { throw IdentityError.invalidProgram }
        try check(SecStaticCodeCheckValidity(code, [], nil))
        var requirement: SecRequirement?
        try check(unsafe SecCodeCopyDesignatedRequirement(code, [], &requirement))
        guard let requirement else { throw IdentityError.invalidProgram }
        var text: CFString?
        try check(unsafe SecRequirementCopyString(requirement, [], &text))
        guard let text, !(text as String).isEmpty else { throw IdentityError.invalidProgram }
        return .init(name: url.deletingPathExtension().lastPathComponent,
                     executablePath: executable.path, requirement: text as String)
    }

    private static func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else { throw IdentityError.codeSignature(status) }
    }

    private enum IdentityError: LocalizedError {
        case invalidProgram
        case codeSignature(OSStatus)

        var errorDescription: String? {
            switch self {
            case .invalidProgram:
                "Select an application or executable with a verifiable code signature."
            case .codeSignature(let status):
                "The program's code signature could not be verified (\(status))."
            }
        }
    }
}
