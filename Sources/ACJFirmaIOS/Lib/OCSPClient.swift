import Foundation
import Security
import OpenSSL

public class OCSPClient {

    public static func check(cert: SecCertificate, issuer: SecCertificate) throws {
        let ocspUrl = try getOcspUrl(cert)
        guard let url = ocspUrl else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No OCSP URL in AIA extension"])
        }

        let requestData = try buildOcspRequest(cert: cert, issuer: issuer)
        let responseData = try httpPost(url: url, data: requestData)
        try parseOcspResponse(responseData, issuer: issuer, cert: cert)
    }

    private static func buildOcspRequest(cert: SecCertificate, issuer: SecCertificate) throws -> Data {
        let certData = SecCertificateCopyData(cert) as Data
        let issuerData = SecCertificateCopyData(issuer) as Data

        let certBio = BIO_new(BIO_s_mem())
        let issuerBio = BIO_new(BIO_s_mem())
        defer {
            BIO_free(certBio)
            BIO_free(issuerBio)
        }

        certData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(certBio, base, Int32(ptr.count))
            }
        }
        issuerData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(issuerBio, base, Int32(ptr.count))
            }
        }

        guard let certX509 = d2i_X509_bio(certBio, nil),
              let issuerX509 = d2i_X509_bio(issuerBio, nil) else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error converting certificates"])
        }
        defer {
            X509_free(certX509)
            X509_free(issuerX509)
        }

        let req = OCSP_REQUEST_new()
        defer { OCSP_REQUEST_free(req) }

        let cid = OCSP_cert_to_id(nil, certX509, issuerX509)
        defer { OCSP_CERTID_free(cid) }

        OCSP_request_add0_id(req, cid)

        var out: UnsafeMutablePointer<UInt8>?
        let len = i2d_OCSP_REQUEST(req, &out)
        guard len > 0, let outPtr = out else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error encoding OCSP request"])
        }
        let result = Data(bytes: outPtr, count: Int(len))
        OPENSSL_free(out)
        return result
    }

    private static func httpPost(url: String, data: Data) throws -> Data {
        guard let requestURL = URL(string: url) else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Invalid OCSP URL"])
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/ocsp-request", forHTTPHeaderField: "Content-Type")
        request.setValue("application/ocsp-response", forHTTPHeaderField: "Accept")
        request.httpBody = data
        request.timeoutInterval = 30

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
        guard let result = responseData else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No OCSP response data"])
        }
        return result
    }

    private static func parseOcspResponse(_ data: Data, issuer: SecCertificate, cert: SecCertificate) throws {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        data.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let resp = d2i_OCSP_RESPONSE_bio(bio, nil) else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error parsing OCSP response"])
        }
        defer { OCSP_RESPONSE_free(resp) }

        let status = OCSP_response_status(resp)
        guard status == OCSP_RESPONSE_STATUS_SUCCESSFUL else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "OCSP Status error: \(status)"])
        }

        guard let basicResp = OCSP_response_get1_basic(resp) else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error getting basic OCSP response"])
        }
        defer { OCSP_BASICRESP_free(basicResp) }

        var count: Int32 = 0
        let singleResps = OCSP_resp_count(basicResp)
        guard singleResps > 0 else {
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "OCSP sin respuestas"])
        }

        let singleResp = OCSP_resp_get0(basicResp, 0)
        var reason: Int32 = -1
        let revocationTime: OpaquePointer?
        let thisUpdate: OpaquePointer?
        let nextUpdate: OpaquePointer?

        let certStatus = OCSP_single_get0_status(singleResp, &reason, &revocationTime, &thisUpdate, &nextUpdate)

        switch certStatus {
        case V_OCSP_CERTSTATUS_GOOD:
            LogManager.info("OCSP GOOD")
            return
        case V_OCSP_CERTSTATUS_REVOKED:
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "El certificado está revocado (OCSP)."])
        default:
            throw NSError(domain: "OCSPClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Estado OCSP desconocido."])
        }
    }

    private static func getOcspUrl(_ cert: SecCertificate) throws -> String? {
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

        guard let rawAIA = X509_get_ext_d2i(x509, Int(NID_info_access), nil, nil) else { return nil }
        let aia = OpaquePointer(rawAIA)
        defer { AUTHORITY_INFO_ACCESS_free(aia) }

        let count = sk_ACCESS_DESCRIPTION_num(aia)
        for i in 0..<count {
            guard let ad = sk_ACCESS_DESCRIPTION_value(aia, i) else { continue }
            let method = OBJ_nid2obj(Int(NID_ad_OCSP))
            if OBJ_cmp(ad.pointee.method, method) == 0 {
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
}
