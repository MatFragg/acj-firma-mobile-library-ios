import Foundation
import OpenSSL

public class TSAClient {

    public static func requestTimestamp(contentHash: Data, tsaUrl: String) throws -> Data {
        guard let url = URL(string: tsaUrl) else {
            throw NSError(domain: "TSAClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "URL de TSA inválida: \(tsaUrl)"])
        }

        let requestDER = try buildTimeStampReq(contentHash: contentHash)

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/timestamp-query", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/timestamp-reply", forHTTPHeaderField: "Accept")
        urlRequest.httpBody = requestDER
        urlRequest.timeoutInterval = 30

        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseError: Error?

        URLSession.shared.dataTask(with: urlRequest) { data, _, error in
            responseData = data
            responseError = error
            semaphore.signal()
        }.resume()

        semaphore.wait()

        if let error = responseError {
            throw error
        }
        guard let data = responseData else {
            throw NSError(domain: "TSAClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se recibió respuesta de la TSA"])
        }

        return try parseTimeStampResp(data)
    }

    private static func buildTimeStampReq(contentHash: Data) throws -> Data {
        let req = TS_REQ_new()
        defer { TS_REQ_free(req) }

        let version = ASN1_INTEGER_new()
        defer { ASN1_INTEGER_free(version) }
        ASN1_INTEGER_set(version, 1)
        TS_REQ_set_version(req, version)

        let msgImprint = TS_MSG_IMPRINT_new()
        defer { TS_MSG_IMPRINT_free(msgImprint) }

        let algo = X509_ALGOR_new()
        defer { X509_ALGOR_free(algo) }
        let nid = OBJ_txt2nid("SHA256")
        X509_ALGOR_set0(algo, OBJ_nid2obj(nid), V_ASN1_NULL, nil)
        TS_MSG_IMPRINT_set_algo(msgImprint, algo)

        contentHash.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                TS_MSG_IMPRINT_set_msg(msgImprint, base, Int32(contentHash.count))
            }
        }

        TS_REQ_set_msg_imprint(req, msgImprint)
        TS_REQ_set_cert_req(req, 1)

        var out: UnsafeMutablePointer<UInt8>?
        let len = i2d_TS_REQ(req, &out)
        guard len > 0, let outPtr = out else {
            throw NSError(domain: "TSAClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error codificando TimeStampReq"])
        }
        let result = Data(bytes: outPtr, count: Int(len))
        free(out)
        return result
    }

    private static func parseTimeStampResp(_ data: Data) throws -> Data {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        data.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let resp = d2i_TS_RESP_bio(bio, nil) else {
            throw NSError(domain: "TSAClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error parseando TimeStampResp"])
        }
        defer { TS_RESP_free(resp) }

        let status = TS_RESP_get_status(resp)
        guard status == 0 else {
            let statusNames = ["granted", "grantedWithMods", "rejection", "waiting", "revocationWarning", "revocationNotification"]
            let statusName = status >= 0 && status < statusNames.count ? statusNames[Int(status)] : "unknown(\(status))"
            throw NSError(domain: "TSAClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "TSA rechazó la solicitud: \(statusName)"])
        }

        guard let token = TS_RESP_get_token(resp) else {
            throw NSError(domain: "TSAClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se encontró TimeStampToken en la respuesta"])
        }

        var out: UnsafeMutablePointer<UInt8>?
        let len = i2d_PKCS7(token, &out)
        guard len > 0, let outPtr = out else {
            throw NSError(domain: "TSAClient", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error codificando TimeStampToken"])
        }
        let result = Data(bytes: outPtr, count: Int(len))
        free(out)
        return result
    }
}
