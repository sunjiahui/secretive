import Foundation

/// Exemptions apply only to keys explicitly created with application-managed authentication.
public struct AuthenticationPolicy: Codable, Equatable, Sendable {

    public var allowGitReads = false
    public var programs: [TrustedProgram] = []

    public init() {}

    public struct TrustedProgram: Codable, Equatable, Sendable, Identifiable {
        public var id: String { executablePath }
        public let name: String
        public let executablePath: String
        public let requirement: String

        public init(name: String, executablePath: String, requirement: String) {
            self.name = name
            self.executablePath = executablePath
            self.requirement = requirement
        }
    }
}

/// Parses argv, never a shell command string. Unknown options and aliases require authentication.
public enum GitReadCommand {

    public static func matches(_ arguments: [String]) -> Bool {
        guard !arguments.isEmpty else { return false }
        var index = 1
        let flags: Set<String> = [
            "--no-pager", "--paginate", "--no-replace-objects", "--literal-pathspecs",
            "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks",
        ]
        let options: Set<String> = ["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"]
        while index < arguments.count {
            let argument = arguments[index]
            if argument == "fetch" || argument == "pull" { return true }
            if flags.contains(argument) {
                index += 1
            } else if options.contains(argument) {
                guard index + 1 < arguments.count, !arguments[index + 1].isEmpty else { return false }
                index += 2
            } else if ["--git-dir=", "--work-tree=", "--namespace=", "--config-env="].contains(where: {
                argument.hasPrefix($0) && argument.count > $0.count
            }) || ((argument.hasPrefix("-C") || argument.hasPrefix("-c")) && argument.count > 2) {
                index += 1
            } else {
                return false
            }
        }
        return false
    }
}

/// Bounded decoding of macOS KERN_PROCARGS2. Environment variables are never decoded or retained.
public enum ProcessArguments {

    public static let maximumBytes = 262_144

    public static func decode(_ data: [UInt8]) -> [String]? {
        guard data.count >= 5, data.count <= maximumBytes else { return nil }
        // All supported macOS architectures use little endian Int32 argc.
        let count = data.prefix(4).enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << ($1.offset * 8) }
        guard count > 0, count <= 4096 else { return nil }
        var index = 4
        guard let executableEnd = data[index...].firstIndex(of: 0), executableEnd > index else { return nil }
        index = executableEnd
        while index < data.count && data[index] == 0 { index += 1 }
        var arguments: [String] = []
        for _ in 0..<count {
            guard index < data.count, let end = data[index...].firstIndex(of: 0),
                  let argument = String(bytes: data[index..<end], encoding: .utf8) else { return nil }
            arguments.append(argument)
            index = end + 1
        }
        return arguments
    }
}
