import Foundation
import Security

public class KeychainManager {

    public static func listCertificados() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            return []
        }
        var aliases: [String] = []
        for item in items {
            if let certData = item[kSecValueData as String] as? Data,
               let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                if let label = item[kSecAttrLabel as String] as? String {
                    if nonRepudiation(cert) {
                        aliases.append(label)
                    }
                }
            }
        }
        return aliases
    }

    private static func nonRepudiation(_ cert: SecCertificate) -> Bool {
        let keyUsageOID = "2.5.29.15" as CFString
        guard let values = SecCertificateCopyValues(cert, [keyUsageOID] as CFArray, nil) as? [CFDictionary] else {
            return false
        }
        for value in values {
            if let oid = value["key" as CFString] as? String, oid == (keyUsageOID as String) {
                if let number = value["value" as CFString] as? Int {
                    return (number & 0x40) != 0
                }
            }
        }
        return false
    }

    public static func getPrivateKey(alias: String) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: alias,
            kSecReturnRef as String: true,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let key = result as? SecKey else {
            throw NSError(domain: "ACJFirma", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se encontró clave privada para alias: \(alias)"])
        }
        return key
    }

    public static func getCertificate(alias: String) throws -> SecCertificate {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: alias,
            kSecReturnRef as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let cert = result as? SecCertificate else {
            throw NSError(domain: "ACJFirma", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se encontró certificado para alias: \(alias)"])
        }
        return cert
    }

    public static func getCertificateChain(alias: String) throws -> [SecCertificate] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: alias,
            kSecReturnRef as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let identity = result as? SecIdentity else {
            return [try getCertificate(alias: alias)]
        }
        var cert: SecCertificate?
        SecIdentityCopyCertificate(identity, &cert)
        var chain = [SecCertificate]()
        if let c = cert {
            chain.append(c)
        }
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        SecTrustCreateWithCertificates(chain as CFArray, policy, &trust)
        if let t = trust {
            let count = SecTrustGetCertificateCount(t)
            for i in 0..<count {
                if let c = SecTrustGetCertificateAtIndex(t, i) {
                    if !chain.contains(where: { CFEqual($0, c) }) {
                        chain.append(c)
                    }
                }
            }
        }
        return chain
    }

    public static func importarP12(p12Data: Data, password: String) throws {
        let options: [String: Any] = [
            kSecImportExportPassphrase as String: password,
        ]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess, let imported = items as? [[String: Any]], let first = imported.first else {
            throw NSError(domain: "ACJFirma", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error importando PKCS#12"])
        }
        if let identity = first[kSecImportItemIdentity as String] as? SecIdentity {
            var cert: SecCertificate?
            SecIdentityCopyCertificate(identity, &cert)
            if let c = cert, let label = SecCertificateCopySubjectSummary(c) as String? {
                let addQuery: [String: Any] = [
                    kSecClass as String: kSecClassIdentity,
                    kSecAttrLabel as String: label,
                    kSecValueRef as String: identity,
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                ]
                SecItemAdd(addQuery as CFDictionary, nil)
            }
        }
    }

    public static func existeAlias(alias: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: alias,
            kSecReturnRef as String: false,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
}
