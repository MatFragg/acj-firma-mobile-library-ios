import Foundation
import Security
import OpenSSL

public class CRLClient {

    private static var cacheDir: URL?

    private static func getCacheDir() throws -> URL {
        if let dir = cacheDir { return dir }
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let dir = paths[0].appendingPathComponent("acj_firma", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        cacheDir = dir
        return dir
    }

    public static func check(urls: [String], cert: SecCertificate, issuer: SecCertificate, tsl: TslService, chain: [SecCertificate]) throws {
        for url in urls {
            try check(url: url, cert: cert, issuer: issuer, tsl: tsl, chain: chain)
        }
    }

    public static func check(url: String, cert: SecCertificate, issuer: SecCertificate, tsl: TslService, chain: [SecCertificate]) throws {
        let crlData = try downloadCrl(url: url)
        let crl = try parseCrl(crlData)
        let signer = try buscarFirmanteCrl(crl: crl, issuer: issuer, tsl: tsl, chain: chain)
        try validarAutorizacionFirmaCrl(signer)
        try validarVigenciaCrl(crl)
        try comprobarRevocacion(crl: crl, cert: cert)
    }

    private static func downloadCrl(url: String) throws -> Data {
        let cacheKey = crlCacheKey(url)
        let cacheFile = try getCacheDir().appendingPathComponent("crl_\(cacheKey).der")

        if FileManager.default.fileExists(atPath: cacheFile.path) {
            let crlData = try Data(contentsOf: cacheFile)
            if let bio = BIO_new(BIO_s_mem()) {
                defer { BIO_free(bio) }
                crlData.withUnsafeBytes { ptr in
                    if let base = ptr.baseAddress {
                        BIO_write(bio, base, Int32(ptr.count))
                    }
                }
                if let crl = d2i_X509_CRL_bio(bio, nil) {
                    defer { X509_CRL_free(crl) }
                    let nextUpdate = X509_CRL_get0_nextUpdate(crl)
                    if nextUpdate != nil {
                        let now = Date()
                        if let next = dateFromASN1_TIME(nextUpdate), now < next {
                            LogManager.info("Usando CRL en caché: \(cacheFile.lastPathComponent)")
                            return crlData
                        }
                    }
                }
                try? FileManager.default.removeItem(at: cacheFile)
            }
        }

        LogManager.info("Descargando CRL: \(url)")
        guard let requestURL = URL(string: url) else {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "URL CRL inválida"])
        }

        var request = URLRequest(url: requestURL)
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 60

        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseError: Error?

        URLSession.shared.dataTask(with: request) { data, _, error in
            responseData = data
            responseError = error
            semaphore.signal()
        }.resume()

        semaphore.wait()

        if let error = responseError {
            throw error
        }
        guard let data = responseData else {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No CRL data"])
        }

        try data.write(to: cacheFile, options: .atomic)
        LogManager.info("CRL cacheada: \(cacheFile.lastPathComponent) (\(data.count) bytes)")
        return data
    }

    private static func parseCrl(_ data: Data) throws -> OpaquePointer {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        data.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let crl = d2i_X509_CRL_bio(bio, nil) else {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error parseando CRL"])
        }
        return crl
    }

    private static func buscarFirmanteCrl(crl: OpaquePointer, issuer: SecCertificate, tsl: TslService, chain: [SecCertificate]) throws -> SecCertificate {
        let issuerData = SecCertificateCopyData(issuer) as Data
        let issuerBio = BIO_new(BIO_s_mem())
        defer { BIO_free(issuerBio) }

        issuerData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(issuerBio, base, Int32(ptr.count))
            }
        }
        guard let issuerX509 = d2i_X509_bio(issuerBio, nil) else {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error converting issuer"])
        }
        defer { X509_free(issuerX509) }

        if verificarFirmaCrl(crl: crl, issuer: issuerX509) {
            return issuer
        }

        for tslCert in tsl.getCertificados() {
            let tslData = SecCertificateCopyData(tslCert) as Data
            let tslBio = BIO_new(BIO_s_mem())
            defer { BIO_free(tslBio) }

            tslData.withUnsafeBytes { ptr in
                if let base = ptr.baseAddress {
                    BIO_write(tslBio, base, Int32(ptr.count))
                }
            }
            if let tslX509 = d2i_X509_bio(tslBio, nil) {
                if verificarFirmaCrl(crl: crl, issuer: tslX509) {
                    return tslCert
                }
                X509_free(tslX509)
            }
        }

        for chainCert in chain {
            let chainData = SecCertificateCopyData(chainCert) as Data
            let chainBio = BIO_new(BIO_s_mem())
            defer { BIO_free(chainBio) }

            chainData.withUnsafeBytes { ptr in
                if let base = ptr.baseAddress {
                    BIO_write(chainBio, base, Int32(ptr.count))
                }
            }
            if let chainX509 = d2i_X509_bio(chainBio, nil) {
                if verificarFirmaCrl(crl: crl, issuer: chainX509) {
                    return chainCert
                }
                X509_free(chainX509)
            }
        }

        throw NSError(domain: "CRLClient", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "El estado de revocación no pudo ser verificado"])
    }

    private static func verificarFirmaCrl(crl: OpaquePointer, issuer: OpaquePointer) -> Bool {
        let store = X509_STORE_new()
        defer { X509_STORE_free(store) }

        let ctx = X509_STORE_CTX_new()
        defer { X509_STORE_CTX_free(ctx) }

        X509_STORE_add_cert(store, issuer)
        X509_STORE_CTX_init(ctx, store, issuer, nil)

        let result = X509_CRL_verify(crl, X509_get_pubkey(issuer))
        return result == 1
    }

    private static func validarAutorizacionFirmaCrl(_ signer: SecCertificate) throws {
        let keyUsageOID = "2.5.29.15" as CFString
        guard let values = SecCertificateCopyValues(signer, [keyUsageOID] as CFArray, nil) as? [CFDictionary] else {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "El CRL es inválido: no tiene cRLSign"])
        }
        for value in values {
            if let oid = value["key" as CFString] as? String, oid == (keyUsageOID as String) {
                if let number = value["value" as CFString] as? Int {
                    if (number & 0x02) == 0 {
                        throw NSError(domain: "CRLClient", code: -1,
                            userInfo: [NSLocalizedDescriptionKey: "El CRL es inválido"])
                    }
                }
            }
        }
    }

    private static func validarVigenciaCrl(_ crl: OpaquePointer) throws {
        guard let nextUpdate = X509_CRL_get0_nextUpdate(crl) else { return }
        let now = Date()
        if let next = dateFromASN1_TIME(nextUpdate), now > next {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "El CRL ha expirado."])
        }
    }

    private static func comprobarRevocacion(crl: OpaquePointer, cert: SecCertificate) throws {
        let certData = SecCertificateCopyData(cert) as Data
        let certBio = BIO_new(BIO_s_mem())
        defer { BIO_free(certBio) }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(certBio, base, Int32(ptr.count))
            }
        }
        guard let x509 = d2i_X509_bio(certBio, nil) else {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error converting cert for revocation check"])
        }
        defer { X509_free(x509) }

        var revoked: OpaquePointer?
        let result = X509_CRL_get0_by_cert(crl, &revoked, x509)
        if result == 1 {
            var cn: CFString?
            SecCertificateCopyCommonName(cert, &cn)
            let name = (cn as String?) ?? "desconocido"
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "El certificado \(name) está revocado."])
        }
    }

    private static func crlCacheKey(_ url: String) -> String {
        guard let data = url.data(using: .utf8) else { return url }
        let hash = SignHelpers.sha1(data: data)
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    public static func getCrlUrls(_ cert: SecCertificate) throws -> [String] {
        let certData = SecCertificateCopyData(cert) as Data
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let x509 = d2i_X509_bio(bio, nil) else {
            throw NSError(domain: "CRLClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error converting cert"])
        }
        defer { X509_free(x509) }

        var result: [String] = []
        guard let rawExt = X509_get_ext_d2i(x509, Int(NID_crl_distribution_points), nil, nil) else { return result }
        let ext = OpaquePointer(rawExt)
        defer { CRL_DIST_POINTS_free(ext) }

        let count = Int(sk_DIST_POINT_num(ext))
        for i in 0..<count {
            guard let dp = sk_DIST_POINT_value(ext, i) else { continue }
            let dpn = dp.pointee.distpoint
            if dpn == nil || dpn!.pointee.type != 0 { continue }
            let names = dpn!.pointee.name.fullname
            let nameCount = Int(sk_GENERAL_NAME_num(names))
            for j in 0..<nameCount {
                guard let gn = sk_GENERAL_NAME_value(names, j) else { continue }
                if gn.pointee.type == GEN_URI {
                    var dataPtr: UnsafeMutablePointer<UInt8>?
                    let len = ASN1_STRING_to_UTF8(&dataPtr, gn.pointee.d.ia5)
                    if len > 0, let ptr = dataPtr {
                        let url = String(cString: ptr)
                        OPENSSL_free(ptr)
                        result.append(url)
                    }
                }
            }
        }
        return result
    }

    private static func dateFromASN1_TIME(_ time: OpaquePointer?) -> Date? {
        guard let t = time else { return nil }
        var dataPtr: UnsafeMutablePointer<UInt8>?
        let len = ASN1_STRING_to_UTF8(&dataPtr, t)
        guard len > 0, let ptr = dataPtr else { return nil }
        let str = String(cString: ptr)
        OPENSSL_free(ptr)

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        if str.hasSuffix("Z") {
            formatter.dateFormat = "yyyyMMddHHmmss'Z'"
            formatter.timeZone = TimeZone(abbreviation: "UTC")
        } else {
            formatter.dateFormat = "yyyyMMddHHmmssZ"
        }
        return formatter.date(from: str)
    }
}
