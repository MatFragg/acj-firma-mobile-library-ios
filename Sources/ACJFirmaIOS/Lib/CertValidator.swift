import Foundation
import Security
import OpenSSL

public class CertValidator {

    private static let keyUsageOID = "2.5.29.15" as CFString

    public static func validarCadenaCompleta(chain: [SecCertificate], tsl: TslService) throws {
        try validarUsos(chain.first)
        try validarExpiracionCadena(chain)
        try validarConfianzaYRevocacion(chain, tsl: tsl)
    }

    public static func validarUsos(_ cert: SecCertificate?) throws {
        guard let c = cert else {
            throw NSError(domain: "CertValidator", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Certificado no disponible"])
        }
        guard let values = SecCertificateCopyValues(c, [keyUsageOID] as CFArray, nil) as? [CFDictionary] else {
            throw NSError(domain: "CertValidator", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se pudo leer KeyUsage"])
        }
        for value in values {
            if let oid = value["key" as CFString] as? String, oid == (keyUsageOID as String) {
                if let number = value["value" as CFString] as? Int {
                    let digitalSignature = (number & 0x80) != 0
                    let nonRepudiation = (number & 0x40) != 0
                    let keyEncipherment = (number & 0x20) != 0
                    if !digitalSignature, !nonRepudiation {
                        throw NSError(domain: "CertValidator", code: -1,
                            userInfo: [NSLocalizedDescriptionKey: "El certificado no tiene KeyUsage digitalSignature ni nonRepudiation"])
                    }
                    if keyEncipherment {
                        throw NSError(domain: "CertValidator", code: -1,
                            userInfo: [NSLocalizedDescriptionKey: "El certificado tiene KeyUsage keyEncipherment"])
                    }
                }
            }
        }
    }

    public static func validarExpiracionCadena(_ chain: [SecCertificate]) throws {
        for cert in chain {
            guard let notAfter = getNotAfter(cert) else { continue }
            if Date() > notAfter {
                var cn: CFString?
                SecCertificateCopyCommonName(cert, &cn)
                let name = (cn as String?) ?? "desconocido"
                throw NSError(domain: "CertValidator", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "El certificado \(name) ha expirado"])
            }
        }
    }

    private static func getNotAfter(_ cert: SecCertificate) -> Date? {
        let certData = SecCertificateCopyData(cert) as Data
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let x509 = d2i_X509_bio(bio, nil) else { return nil }
        defer { X509_free(x509) }

        guard let notAfter = X509_get0_notAfter(x509) else { return nil }
        return dateFromASN1_TIME(notAfter)
    }

    private static func dateFromASN1_TIME(_ time: UnsafePointer<ASN1_TIME>?) -> Date? {
        guard let t = time else { return nil }
        var dataPtr: UnsafeMutablePointer<UInt8>?
        let len = ASN1_STRING_to_UTF8(&dataPtr, t)
        guard len > 0, let ptr = dataPtr else { return nil }
        let str = String(cString: ptr)
        OPENSSL_free(ptr)

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        if str.hasSuffix("Z") {
            formatter.dateFormat = "yyMMddHHmmss'Z'"
            formatter.timeZone = TimeZone(abbreviation: "UTC")
            if let date = formatter.date(from: str) { return date }
            formatter.dateFormat = "yyyyMMddHHmmss'Z'"
            if let date = formatter.date(from: str) { return date }
        }
        formatter.dateFormat = "yyMMddHHmmssZ"
        if let date = formatter.date(from: str) { return date }
        formatter.dateFormat = "yyyyMMddHHmmssZ"
        return formatter.date(from: str)
    }

    public static func validarConfianzaYRevocacion(_ chain: [SecCertificate], tsl: TslService) throws {
        guard !chain.isEmpty else {
            throw NSError(domain: "CertValidator", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Cadena de certificados vacía"])
        }

        for i in 0..<chain.count {
            let cert = chain[i]
            let emisor = try resolverEmisor(cert: cert, indice: i, chain: chain, tsl: tsl)

            if esCertificadoDeConfianzaDirecta(cert, tsl: tsl) {
                LogManager.info("Certificado ancla en TSL")
                return
            }

            if esCertificadoDeConfianzaDirecta(emisor, tsl: tsl) {
                LogManager.info("Emisor ancla en TSL")
                try verificarRevocacion(cert: cert, emisor: emisor, tsl: tsl, chain: chain)
                return
            }

            try verificarRevocacion(cert: cert, emisor: emisor, tsl: tsl, chain: chain)
        }

        throw NSError(domain: "CertValidator", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "El certificado no pertenece a la red de confianza de la TSL."])
    }

    private static func resolverEmisor(cert: SecCertificate, indice: Int, chain: [SecCertificate], tsl: TslService) throws -> SecCertificate {
        if indice + 1 < chain.count {
            return chain[indice + 1]
        }
        if let ancla = buscarAnclaEnTsl(cert, tsl: tsl) {
            return ancla
        }
        if let intermediate = fetchIntermediateViaAia(cert) {
            LogManager.info("Intermedio descargado via AIA")
            if buscarAnclaEnTsl(intermediate, tsl: tsl) != nil {
                LogManager.info("Intermedio lleva a ancla en TSL")
                return intermediate
            }
            for tslCert in tsl.getCertificados() {
                if CFEqual(intermediate, tslCert) {
                    return intermediate
                }
            }
        }
        throw NSError(domain: "CertValidator", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "No se pudo resolver el emisor del certificado"])
    }

    private static func verificarRevocacion(cert: SecCertificate, emisor: SecCertificate, tsl: TslService, chain: [SecCertificate]) throws {
        do {
            try OCSPClient.check(cert: cert, issuer: emisor)
            return
        } catch {
            if esErrorDeNegocio(error.localizedDescription) {
                throw error
            }
            LogManager.warning("Falla OCSP, intentando CRL: \(error.localizedDescription)")
        }

        guard let crlUrls = try? CRLClient.getCrlUrls(cert), !crlUrls.isEmpty else { return }

        var ultimoError: String?
        for url in crlUrls {
            do {
                try CRLClient.check(url: url, cert: cert, issuer: emisor, tsl: tsl, chain: chain)
                return
            } catch {
                if esErrorDeNegocio(error.localizedDescription) {
                    throw error
                }
                ultimoError = error.localizedDescription
                LogManager.warning("Falla CRL \(url): \(ultimoError!)")
            }
        }
        if let error = ultimoError {
            throw NSError(domain: "CertValidator", code: -1,
                userInfo: [NSLocalizedDescriptionKey: error])
        }
    }

    private static func esCertificadoDeConfianzaDirecta(_ cert: SecCertificate, tsl: TslService) -> Bool {
        guard tsl.isValida() else { return false }
        for tslCert in tsl.getCertificados() {
            if CFEqual(cert, tslCert) {
                return true
            }
        }
        return false
    }

    private static func buscarAnclaEnTsl(_ cert: SecCertificate, tsl: TslService) -> SecCertificate? {
        guard tsl.isValida() else { return nil }

        let certIssuer = getIssuerDN(cert)
        for tslCert in tsl.getCertificados() {
            if getSubjectDN(tslCert) == certIssuer {
                if verificarFirma(cert: cert, issuer: tslCert) {
                    return tslCert
                }
            }
        }
        return nil
    }

    private static func getSubjectDN(_ cert: SecCertificate) -> String {
        let certData = SecCertificateCopyData(cert) as Data
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let x509 = d2i_X509_bio(bio, nil) else { return "" }
        defer { X509_free(x509) }

        let subject = X509_get_subject_name(x509)
        var out: UnsafeMutablePointer<Int8>?
        let len = X509_NAME_oneline(subject, &out, 0)
        guard len > 0, let ptr = out else { return "" }
        let result = String(cString: ptr)
        OPENSSL_free(ptr)
        return result
    }

    private static func getIssuerDN(_ cert: SecCertificate) -> String {
        let certData = SecCertificateCopyData(cert) as Data
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let x509 = d2i_X509_bio(bio, nil) else { return "" }
        defer { X509_free(x509) }

        let issuer = X509_get_issuer_name(x509)
        var out: UnsafeMutablePointer<Int8>?
        let len = X509_NAME_oneline(issuer, &out, 0)
        guard len > 0, let ptr = out else { return "" }
        let result = String(cString: ptr)
        OPENSSL_free(ptr)
        return result
    }

    private static func verificarFirma(cert: SecCertificate, issuer: SecCertificate) -> Bool {
        let certData = SecCertificateCopyData(cert) as Data
        let issuerData = SecCertificateCopyData(issuer) as Data

        let certBio = BIO_new(BIO_s_mem())
        let issuerBio = BIO_new(BIO_s_mem())
        defer {
            BIO_free(certBio)
            BIO_free(issuerBio)
        }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress { BIO_write(certBio, base, Int32(ptr.count)) }
        }
        issuerData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress { BIO_write(issuerBio, base, Int32(ptr.count)) }
        }

        guard let x509 = d2i_X509_bio(certBio, nil),
              let issuerX509 = d2i_X509_bio(issuerBio, nil) else { return false }
        defer {
            X509_free(x509)
            X509_free(issuerX509)
        }

        let pubKey = X509_get_pubkey(issuerX509)
        defer { EVP_PKEY_free(pubKey) }
        guard let pk = pubKey else { return false }

        return X509_verify(x509, pk) == 1
    }

    private static func fetchIntermediateViaAia(_ cert: SecCertificate) -> SecCertificate? {
        guard let url = getCaIssuersUrl(cert) else { return nil }
        LogManager.info("Descargando CA desde AIA: \(url)")
        guard let requestURL = URL(string: url) else { return nil }

        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        URLSession.shared.dataTask(with: requestURL) { data, _, _ in
            responseData = data
            semaphore.signal()
        }.resume()
        semaphore.wait()

        guard let data = responseData,
              let intermediate = SecCertificateCreateWithData(nil, data as CFData) else { return nil }
        return intermediate
    }

    private static func getCaIssuersUrl(_ cert: SecCertificate) -> String? {
        let certData = SecCertificateCopyData(cert) as Data
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress { BIO_write(bio, base, Int32(ptr.count)) }
        }

        guard let x509 = d2i_X509_bio(bio, nil) else { return nil }
        defer { X509_free(x509) }

        guard let rawAIA = X509_get_ext_d2i(x509, Int(NID_info_access), nil, nil) else { return nil }
        let aia = OpaquePointer(rawAIA)
        defer { AUTHORITY_INFO_ACCESS_free(aia) }

        let count = Int(sk_ACCESS_DESCRIPTION_num(aia))
        for i in 0..<count {
            guard let ad = sk_ACCESS_DESCRIPTION_value(aia, i) else { continue }
            if OBJ_obj2nid(ad.pointee.method) == NID_ad_CA_ISSUERS {
                let gn = ad.pointee.location
                if gn.pointee.type == GEN_URI {
                    var dataPtr: UnsafeMutablePointer<UInt8>?
                    let len = ASN1_STRING_to_UTF8(&dataPtr, gn.pointee.d.ia5)
                    if len > 0, let ptr = dataPtr {
                        let url = String(cString: ptr)
                        OPENSSL_free(ptr)
                        return url
                    }
                }
            }
        }
        return nil
    }

    private static func esErrorDeNegocio(_ mensaje: String) -> Bool {
        let lower = mensaje.lowercased()
        let keywords = ["revocado", "expirado", "vencido", "inválido", "no tiene keyusage", "crlsign", "no se pudo verificar"]
        return keywords.contains(where: { lower.contains($0) })
    }
}
