import Foundation
import Security

extension SettingsStore {

    /// Read on every application-managed signature so removing an exemption takes effect immediately.
    public func loadAuthenticationPolicy() throws -> AuthenticationPolicy {
        var query = policyQuery
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = unsafe SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return AuthenticationPolicy() }
        guard status == errSecSuccess, let data = result as? Data else {
            throw PolicyStoreError(status: status)
        }
        return try JSONDecoder().decode(AuthenticationPolicy.self, from: data)
    }

    /// Atomic replacement of the complete policy, with visible errors rather than a silent save failure.
    public func saveAuthenticationPolicy(_ policy: AuthenticationPolicy) throws {
        let data = try JSONEncoder().encode(policy)
        let status = SecItemUpdate(policyQuery as CFDictionary, [kSecValueData: data] as CFDictionary)
        if status == errSecItemNotFound {
            var attributes = policyQuery
            attributes[kSecValueData] = data
            attributes[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let inserted = SecItemAdd(attributes as CFDictionary, nil)
            guard inserted == errSecSuccess else { throw PolicyStoreError(status: inserted) }
        } else if status != errSecSuccess {
            throw PolicyStoreError(status: status)
        }
    }

    private var policyQuery: [CFString: Any] {
        [kSecClass: kSecClassGenericPassword,
         kSecAttrService: Constants.keyTag,
         kSecAttrAccount: "AuthenticationPolicy.v1",
         kSecUseDataProtectionKeychain: true]
    }

    private struct PolicyStoreError: LocalizedError {
        let status: OSStatus
        var errorDescription: String? { "Unable to access authentication settings (\(status))." }
    }
}
