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

        var chainStack: UnsafeMutablePointer<stack_st_X509>?
        for i in 0..<chain.count {
            let x = try secCertificateToX509(chain[i])
            if chainStack == nil {
                chainStack = sk_X509_new_null()
            }
            sk_X509_push(chainStack, x)
        }

        if let sk = chainStack {
            PKCS7_set_certs(p7, sk)
        }

        var out: UnsafeMutablePointer<UInt8>?
        let len = i2d_PKCS7(p7, &out)
        guard len > 0, let outPtr = out else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error encoding PKCS7"])
        }

        let result = Data(bytes: outPtr, count: Int(len))
        OPENSSL_free(out)
        return result
    }

    private static func secKeyToEVP_PKEY(_ key: SecKey) throws -> UnsafeMutablePointer<EVP_PKEY> {
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
        EVP_PKEY_assign_RSA(pkey, rsaKey)
        return pkey!
    }

    private static func secCertificateToX509(_ cert: SecCertificate) throws -> UnsafeMutablePointer<X509> {
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

    /// Adds an RFC 3161 TimeStampToken as an unsigned attribute to the CMS/PKCS7 signer info.
    /// Upgrades the signature from Baseline-B to Baseline-T.
    public static func addLevelTTimestamp(signedData: Data, signedContent: Data, tsaUrl: String) throws -> Data {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        signedData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let p7 = d2i_PKCS7_bio(bio, nil) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error parseando PKCS7 para timestamp"])
        }
        defer { PKCS7_free(p7) }

        guard let signerInfoStack = PKCS7_get_signer_info(p7) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se encontraron firmantes en PKCS7"])
        }

        guard sk_PKCS7_SIGNER_INFO_num(signerInfoStack) > 0,
              let signerInfo = sk_PKCS7_SIGNER_INFO_value(signerInfoStack, 0) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No hay firmantes en PKCS7"])
        }

        let contentHash = SignHelpers.sha256(data: signedContent)
        let tsaToken = try TSAClient.requestTimestamp(contentHash: contentHash, tsaUrl: tsaUrl)

        let tsaOID = "1.2.840.113549.1.9.16.2.14"
        let tsaNid = OBJ_txt2nid(tsaOID)

        // Build DER-encoded PKCS7 from the TSA token bytes
        let tsaBio = BIO_new(BIO_s_mem())
        defer { BIO_free(tsaBio) }

        tsaToken.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                BIO_write(tsaBio, base, Int32(ptr.count))
            }
        }

        guard let tsP7 = d2i_PKCS7_bio(tsaBio, nil) else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error parseando TimeStampToken"])
        }
        defer { PKCS7_free(tsP7) }

        var tsOut: UnsafeMutablePointer<UInt8>?
        let tsLen = i2d_PKCS7(tsP7, &tsOut)
        guard tsLen > 0, let tsPtr = tsOut else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error re-codificando TimeStampToken"])
        }

        let tsDer = Data(bytes: tsPtr, count: Int(tsLen))
        OPENSSL_free(tsOut)

        // Add the timestamp token as unsigned attribute via PKCS7_add_attrib
        let addResult = tsDer.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
            guard let base = ptr.baseAddress else { return 0 }
            return PKCS7_add_attrib(signerInfo, tsaNid, V_ASN1_OCTET_STRING,
                UnsafeMutableRawPointer(mutating: base), Int32(tsDer.count))
        }

        guard addResult != 0 else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error agregando timestamp unsigned attribute"])
        }

        var out: UnsafeMutablePointer<UInt8>?
        let len = i2d_PKCS7(p7, &out)
        guard len > 0, let outPtr = out else {
            throw NSError(domain: "CMSBuilder", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error re-codificando PKCS7 con timestamp"])
        }

        let result = Data(bytes: outPtr, count: Int(len))
        OPENSSL_free(out)
        return result
    }
}
