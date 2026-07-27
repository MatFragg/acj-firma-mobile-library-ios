import Foundation
import Security
import OpenSSL

public class SignHelpers {

    public static func getCertificadoInfo(_ cert: SecCertificate, campo: String) -> String {
        var commonName: CFString?
        let status = SecCertificateCopyCommonName(cert, &commonName)
        guard status == errSecSuccess, let cn = commonName as String? else {
            return Constants.cadenaVacia
        }
        let campoBuscar = campo.replacingOccurrences(of: "=", with: "").uppercased()
        if campoBuscar == "CN" {
            return cn
        }
        let subject = SecCertificateCopySubjectSummary(cert) as String? ?? ""
        return extraerCampoDN(subject, campo: campoBuscar)
    }

    public static func extraerCampoDN(_ dn: String, campo: String) -> String {
        let pattern = "\(campo)="
        let parts = dn.components(separatedBy: ",")
        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix(pattern) {
                return String(trimmed.dropFirst(pattern.count))
            }
        }
        return Constants.cadenaVacia
    }

    public static func nonRepudiation(_ cert: SecCertificate) -> Bool {
        guard let keyUsage = copyKeyUsage(cert) else { return false }
        return keyUsage.count > 1 && keyUsage[1]
    }

    private static func copyKeyUsage(_ cert: SecCertificate) -> [Bool]? {
        let keyUsageOID = "2.5.29.15" as CFString
        guard let values = SecCertificateCopyValues(cert, [keyUsageOID] as CFArray, nil) as? [CFDictionary] else {
            return nil
        }
        for value in values {
            if let oid = value["key" as CFString] as? String, oid == (keyUsageOID as String) {
                if let number = value["value" as CFString] as? Int {
                    return [
                        (number & 0x80) != 0,
                        (number & 0x40) != 0,
                        (number & 0x20) != 0,
                        (number & 0x10) != 0,
                        (number & 0x08) != 0,
                        (number & 0x04) != 0,
                        (number & 0x02) != 0,
                        (number & 0x01) != 0,
                    ]
                }
            }
        }
        return nil
    }

    public static func formatDateFull(_ fecha: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = Constants.formatoFecha
        formatter.locale = Locale.current
        return formatter.string(from: fecha)
    }

    public static func getDateTmp() -> Date {
        Date(timeIntervalSinceNow: -5)
    }

    public static func cropText(_ text: String, longitud: Int) -> String {
        guard !text.isEmpty, longitud > 0 else { return text }
        var resultado = ""
        var index = text.startIndex
        while index < text.endIndex {
            let remaining = text[index...]
            if remaining.count <= longitud {
                resultado += remaining
                break
            }
            let end = text.index(index, offsetBy: longitud, limitedBy: text.endIndex) ?? text.endIndex
            let range = index..<end
            let chunk = text[range]
            if let lastSpace = chunk.lastIndex(of: " "), lastSpace > index {
                resultado += text[index..<lastSpace] + "\n"
                index = text.index(after: lastSpace)
            } else {
                resultado += chunk + "\n"
                index = end
            }
        }
        return resultado
    }

    public static func retornarCadenaList(_ errores: [String]) -> String {
        errores.map { "• \($0)" }.joined(separator: "\n")
    }

    public static func getRUCFromCertificado(_ cert: SecCertificate) -> String {
        let dn = SecCertificateCopySubjectSummary(cert) as String? ?? ""
        if dn.contains("RUC:") {
            if let range = dn.range(of: "RUC:") {
                let afterRUC = dn[range.upperBound...].trimmingCharacters(in: .whitespaces)
                let parts = afterRUC.components(separatedBy: CharacterSet.whitespaces)
                let ruc = parts.first ?? ""
                let numericRuc = ruc.components(separatedBy: CharacterSet.decimalDigits.inverted).joined()
                return numericRuc
            }
        }
        let cn = getCertificadoInfo(cert, campo: "CN=")
        if cn.contains("RUC:") {
            if let range = cn.range(of: "RUC:") {
                let afterRUC = cn[range.upperBound...].trimmingCharacters(in: .whitespaces)
                let parts = afterRUC.components(separatedBy: CharacterSet.whitespaces)
                return parts.first ?? ""
            }
        }
        return Constants.cadenaVacia
    }

    public static func sha256(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buf in
            if let base = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                SHA256(base, data.count, &hash)
            }
        }
        return Data(hash)
    }

    public static func sha1(data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(SHA_DIGEST_LENGTH))
        data.withUnsafeBytes { buf in
            if let base = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                SHA1(base, data.count, &hash)
            }
        }
        return Data(hash)
    }
}
