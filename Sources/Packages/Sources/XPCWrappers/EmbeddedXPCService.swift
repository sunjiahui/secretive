import Foundation

enum EmbeddedXPCService {

    /// Read the bundled helper's identity so custom builds can use their own bundle identifiers.
    static func identifier(for requestedName: String, in applicationURL: URL) -> String {
        guard let product = requestedName.split(separator: ".").last,
              product.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }) else {
            return requestedName
        }
        let serviceURL = applicationURL
            .appendingPathComponent("Contents/XPCServices", isDirectory: true)
            .appendingPathComponent(String(product) + ".xpc", isDirectory: true)
        guard let identifier = Bundle(url: serviceURL)?.bundleIdentifier, !identifier.isEmpty else {
            return requestedName
        }
        return identifier
    }
}
