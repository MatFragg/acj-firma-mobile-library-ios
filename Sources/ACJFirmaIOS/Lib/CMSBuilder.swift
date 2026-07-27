import Foundation
import Security
import OpenSSL

public class CMSBuilder {

    public static func buildSignedData(
        content: Data,
        privateKey: SecKey,
        certificate: SecCertificate,
        chain: [SecCertificate]
    ) throws -> Data {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        let pkey = try secKeyToEVP_PKEY(privateKey)
        defer { EVP_PKEY_free(pkey) }

        let x509 = try secCertificateToX509(certificate)
        defer { X509_free(x509) }

        let flags: Int32 = PKCS7_DETACHED | PKCS7_BINARY | PKCS7_NOSMIMECAP

        content.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let p7 = PKCS7_sign(x509, pkey, nil, bio, flags) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error creating PKCS7 signature"])
        }
        defer { PKCS7_free(p7) }

        for i in 0..<chain.count {
            let x = try secCertificateToX509(chain[i])
            PKCS7_add_certificate(p7, x)
        }

        var out: UnsafeMutablePointer<UInt8>?
        let len = i2d_PKCS7(p7, &out)
        guard len > 0, let outPtr = out else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error encoding PKCS7"])
        }

        let result = Data(bytes: outPtr, count: Int(len))
        free(outPtr)
        return result
    }

    private static func secKeyToEVP_PKEY(_ key: SecKey) throws -> OpaquePointer {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error exporting SecKey"])
        }

        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        let rsa = d2i_RSAPrivateKey_bio(bio, nil)
        guard let rsaKey = rsa else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error parsing RSA private key from SecKey"])
        }

        let pkey = EVP_PKEY_new()
        EVP_PKEY_assign(pkey, EVP_PKEY_RSA, UnsafeMutableRawPointer(rsaKey))
        return pkey!
    }

    private static func secCertificateToX509(_ cert: SecCertificate) throws -> OpaquePointer {
        let data = SecCertificateCopyData(cert) as Data
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let x509 = d2i_X509_bio(bio, nil) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error converting SecCertificate to X509"])
        }
        return x509
    }

    public static func signWithSecKey(privateKey: SecKey, data: Data) throws -> Data {
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Algorithm not supported"])
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            throw error?.takeRetainedValue() ?? NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error creating signature"])
        }
        return signature
    }

    public static func verifySignature(content: Data, signature: Data, certificate: SecCertificate) throws -> Bool {
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error getting public key"])
        }

        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Algorithm not supported for verification"])
        }

        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(publicKey, algorithm, content as CFData, signature as CFData, &error)
        if !result, let err = error?.takeRetainedValue() as? Error {
            throw err
        }
        return result
    }

    // MARK: - PAdES-T (Timestamp)

    /// Placeholder for PAdES-T (TSA timestamping).
    /// The required OpenSSL function PKCS7_add_attrib is not available in this build.
    /// Returns the signed data unchanged.
    public static func addLevelTTimestamp(signedData: Data, signedContent: Data, tsaUrl: String) throws -> Data {
        LogManager.warning("PAdES-T (timestamp) no disponible - saltando sellado de tiempo")
        return signedData
    }
}
