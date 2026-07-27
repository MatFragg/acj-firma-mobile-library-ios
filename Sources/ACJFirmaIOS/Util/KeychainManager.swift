import Foundation
import Security
import OpenSSL

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
        let certData = SecCertificateCopyData(cert) as Data
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }
        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }
        guard let x509 = d2i_X509_bio(bio, nil) else { return false }
        defer { X509_free(x509) }
        let usage = X509_get_key_usage(x509)
        return (usage & 0x40) != 0
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
        guard status == errSecSuccess, let result = result,
              CFGetTypeID(result) == SecKeyGetTypeID() else {
            throw NSError(domain: "ACJFirma", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se encontró clave privada para alias: \(alias)"])
        }
        return result as! SecKey
    }

    public static func getCertificate(alias: String) throws -> SecCertificate {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: alias,
            kSecReturnRef as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let result = result,
              CFGetTypeID(result) == SecCertificateGetTypeID() else {
            throw NSError(domain: "ACJFirma", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se encontró certificado para alias: \(alias)"])
        }
        return result as! SecCertificate
    }

    public static func getCertificateChain(alias: String) throws -> [SecCertificate] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: alias,
            kSecReturnRef as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let result = result,
              CFGetTypeID(result) == SecIdentityGetTypeID() else {
            return [try getCertificate(alias: alias)]
        }
        let identity = result as! SecIdentity
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
            if let certs = SecTrustCopyCertificateChain(t) as? [SecCertificate] {
                for c in certs {
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
        if let rawIdentity = first[kSecImportItemIdentity as String],
           CFGetTypeID(rawIdentity as AnyObject) == SecIdentityGetTypeID() {
            let identity = rawIdentity as! SecIdentity
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
