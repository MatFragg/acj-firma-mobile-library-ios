import Foundation
import Security
import PDFKit
import OpenSSL

public class ResultadoFirma {
    public let valida: Bool
    public let nombreFirmante: String
    public let motivo: String?
    public let location: String?
    public let fechaFirma: Date?
    public let mensajeError: String
    public let selloEmitidoPor: String?
    public let selloMarcaDeHora: Date?
    public let selloValidoHasta: Date?

    public init(valida: Bool, nombreFirmante: String, motivo: String?, location: String?,
                fechaFirma: Date?, mensajeError: String,
                selloEmitidoPor: String? = nil, selloMarcaDeHora: Date? = nil,
                selloValidoHasta: Date? = nil) {
        self.valida = valida
        self.nombreFirmante = nombreFirmante
        self.motivo = motivo
        self.location = location
        self.fechaFirma = fechaFirma
        self.mensajeError = mensajeError
        self.selloEmitidoPor = selloEmitidoPor
        self.selloMarcaDeHora = selloMarcaDeHora
        self.selloValidoHasta = selloValidoHasta
    }
}

public class ResultadoValidacion {
    public let documentoValido: Bool
    public let firmas: [ResultadoFirma]
    public let mensajeError: String

    public init(documentoValido: Bool, firmas: [ResultadoFirma], mensajeError: String) {
        self.documentoValido = documentoValido
        self.firmas = firmas
        self.mensajeError = mensajeError
    }
}

public class ValidacionController {

    public static func validarDocumento(pdfData: Data, tsl: TslService) -> ResultadoValidacion {
        guard PDFDocument(data: pdfData) != nil else {
            return ResultadoValidacion(documentoValido: false, firmas: [],
                mensajeError: "No se pudo cargar el PDF")
        }

        var resultados: [ResultadoFirma] = []

        let signatures = extractSignatures(from: pdfData)
        if signatures.isEmpty {
            return ResultadoValidacion(documentoValido: false, firmas: [],
                mensajeError: "El documento no contiene firmas.")
        }

        for (name, reason, location, date) in signatures {
            do {
                let byteRange = try extraerByteRange(pdfData: pdfData)
                let cmsData = try extraerCMS(pdfData: pdfData, byteRange: byteRange)

                let resultado = try validarFirma(
                    pdfData: pdfData,
                    cmsData: cmsData,
                    byteRange: byteRange,
                    nombreFirmante: name,
                    motivo: reason,
                    location: location,
                    fechaFirma: date,
                    tsl: tsl
                )
                resultados.append(resultado)
            } catch {
                resultados.append(ResultadoFirma(
                    valida: false,
                    nombreFirmante: name ?? "Desconocido",
                    motivo: reason,
                    location: location,
                    fechaFirma: date,
                    mensajeError: "Error técnico: \(error.localizedDescription)"
                ))
            }
        }

        let todoValido = resultados.allSatisfy { $0.valida }
        return ResultadoValidacion(documentoValido: todoValido, firmas: resultados, mensajeError: "")
    }

    private static func extractSignatures(from pdfData: Data) -> [(String?, String?, String?, Date?)] {
        guard let pdfString = String(data: pdfData, encoding: .ascii) else { return [] }
        var signatures: [(String?, String?, String?, Date?)] = []

        let sigPattern = "/Type\\s*/Sig[^>]*>>"
        let namePattern = "/Name\\s*\\(([^)]*)\\)"
        let reasonPattern = "/Reason\\s*\\(([^)]*)\\)"
        let locationPattern = "/Location\\s*\\(([^)]*)\\)"

        guard let sigRegex = try? NSRegularExpression(pattern: sigPattern, options: [.dotMatchesLineSeparators]),
              let nameRegex = try? NSRegularExpression(pattern: namePattern),
              let reasonRegex = try? NSRegularExpression(pattern: reasonPattern),
              let locationRegex = try? NSRegularExpression(pattern: locationPattern) else {
            return signatures
        }

        let nsString = pdfString as NSString
        let sigMatches = sigRegex.matches(in: pdfString, range: NSRange(location: 0, length: nsString.length))

        for sigMatch in sigMatches {
            let sigBlock = nsString.substring(with: sigMatch.range)
            let nsBlock = sigBlock as NSString

            let name: String? = {
                if let m = nameRegex.firstMatch(in: sigBlock, range: NSRange(location: 0, length: nsBlock.length)) {
                    return nsBlock.substring(with: m.range(at: 1))
                }
                return nil
            }()
            let reason: String? = {
                if let m = reasonRegex.firstMatch(in: sigBlock, range: NSRange(location: 0, length: nsBlock.length)) {
                    return nsBlock.substring(with: m.range(at: 1))
                }
                return nil
            }()
            let location: String? = {
                if let m = locationRegex.firstMatch(in: sigBlock, range: NSRange(location: 0, length: nsBlock.length)) {
                    return nsBlock.substring(with: m.range(at: 1))
                }
                return nil
            }()

            signatures.append((name, reason, location, nil))
        }
        return signatures
    }

    private static func extraerByteRange(pdfData: Data) throws -> [Int] {
        try PDFSigner.calcularByteRange(pdfData: pdfData)
    }

    private static func extraerCMS(pdfData: Data, byteRange: [Int]) throws -> Data {
        guard byteRange.count >= 4 else {
            throw NSError(domain: "ValidacionController", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "ByteRange inválido"])
        }

        let cmsStart = byteRange[1]
        let cmsEnd = byteRange[2]
        let cmsRegion = pdfData[cmsStart..<cmsEnd]

        guard let cmsStr = String(data: cmsRegion, encoding: .ascii) else {
            throw NSError(domain: "ValidacionController", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error leyendo región CMS del PDF"])
        }

        guard let openBracket = cmsStr.firstIndex(of: "<"),
              let closeBracket = cmsStr.lastIndex(of: ">"),
              openBracket < closeBracket else {
            throw NSError(domain: "ValidacionController", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Formato CMS inválido en PDF"])
        }

        let hexStr = cmsStr[cmsStr.index(after: openBracket)..<closeBracket]
        let cleanHex = hexStr.components(separatedBy: .whitespacesAndNewlines).joined()

        guard cleanHex.count % 2 == 0 else {
            throw NSError(domain: "ValidacionController", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Hex CMS inválido (longitud impar)"])
        }

        var cmsData = Data()
        var index = cleanHex.startIndex
        while index < cleanHex.endIndex {
            let next = cleanHex.index(index, offsetBy: 2)
            if let byte = UInt8(cleanHex[index..<next], radix: 16) {
                cmsData.append(byte)
            } else {
                throw NSError(domain: "ValidacionController", code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Hex CMS inválido"])
            }
            index = next
        }
        return cmsData
    }

    private static func validarFirma(
        pdfData: Data,
        cmsData: Data,
        byteRange: [Int],
        nombreFirmante: String?,
        motivo: String?,
        location: String?,
        fechaFirma: Date?,
        tsl: TslService
    ) throws -> ResultadoFirma {
        guard byteRange.count >= 4 else {
            return ResultadoFirma(valida: false, nombreFirmante: nombreFirmante ?? "Desconocido",
                motivo: motivo, location: location, fechaFirma: fechaFirma,
                mensajeError: "ByteRange inválido")
        }

        let br0 = byteRange[0]
        let br1 = byteRange[1]
        let br2 = byteRange[2]
        let br3 = byteRange[3]

        var signedBytes = Data()
        signedBytes.append(pdfData[br0..<br0 + br1])
        signedBytes.append(pdfData[br2..<br2 + br3])

        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        cmsData.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                BIO_write(bio, base, Int32(ptr.count))
            }
        }

        guard let p7 = d2i_PKCS7_bio(bio, nil) else {
            return ResultadoFirma(valida: false, nombreFirmante: nombreFirmante ?? "Desconocido",
                motivo: motivo, location: location, fechaFirma: fechaFirma,
                mensajeError: "No se pudo parsear CMS")
        }
        defer { PKCS7_free(p7) }

        guard let certStack = PKCS7_get0_signers(p7, nil, 0) else {
            return ResultadoFirma(valida: false, nombreFirmante: nombreFirmante ?? "Desconocido",
                motivo: motivo, location: location, fechaFirma: fechaFirma,
                mensajeError: "No se encontraron certificados en CMS")
        }

        let certCount = OPENSSL_sk_num(certStack)
        var certChain: [SecCertificate] = []
        for i in 0..<certCount {
            guard let raw = OPENSSL_sk_value(certStack, Int32(i)) else { continue }
            let x509 = OpaquePointer(raw)
            var out: UnsafeMutablePointer<UInt8>?
            let len = i2d_X509(x509, &out)
            if len > 0, let outPtr = out {
                let certData = Data(bytes: outPtr, count: Int(len))
                free(outPtr)
                if let secCert = SecCertificateCreateWithData(nil, certData as CFData) {
                    certChain.append(secCert)
                }
            }
        }

        guard !certChain.isEmpty else {
            return ResultadoFirma(valida: false, nombreFirmante: nombreFirmante ?? "Desconocido",
                motivo: motivo, location: location, fechaFirma: fechaFirma,
                mensajeError: "No se pudieron extraer certificados")
        }

        let leafCert = certChain[0]
        var cn: CFString?
        SecCertificateCopyCommonName(leafCert, &cn)
        let nombre = (cn as String?) ?? nombreFirmante ?? "Desconocido"

        // Verificación criptográfica: pasar los bytes firmados a PKCS7_verify
        let contentBio = BIO_new(BIO_s_mem())
        defer { BIO_free(contentBio) }

        signedBytes.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                BIO_write(contentBio, base, Int32(ptr.count))
            }
        }

        let verifier = PKCS7_verify(p7, nil, nil, contentBio, nil, PKCS7_NOVERIFY)
        let validaCripto = verifier == 1

        if !validaCripto {
            return ResultadoFirma(valida: false, nombreFirmante: nombre,
                motivo: motivo, location: location, fechaFirma: fechaFirma,
                mensajeError: "La firma digital (criptográfica) no es válida.")
        }

        do {
            try CertValidator.validarCadenaCompleta(chain: certChain, tsl: tsl)
        } catch {
            return ResultadoFirma(valida: false, nombreFirmante: nombre,
                motivo: motivo, location: location, fechaFirma: fechaFirma,
                mensajeError: error.localizedDescription)
        }

        return ResultadoFirma(valida: true, nombreFirmante: nombre,
            motivo: motivo, location: location, fechaFirma: fechaFirma,
            mensajeError: "")
    }

}
