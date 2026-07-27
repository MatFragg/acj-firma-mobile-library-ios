import Foundation
import Security
import UIKit

public class FirmaController {
    private var certChain: [SecCertificate] = []
    private var ocspIsAvailable = true

    public init() {}

    public func firmarDocumento(_ parametros: Parameters) async throws {
        certChain = []

        let pdfURL = URL(fileURLWithPath: parametros.rutaPdfOriginal)
        guard FileManager.default.fileExists(atPath: pdfURL.path) else {
            throw NSError(domain: "FirmaController", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "PDF no encontrado en: \(pdfURL.path)"])
        }

        let pdfData = try Data(contentsOf: pdfURL)

        let (privateKey, cert) = try await cargarCredenciales(parametros)

        let cnLog = SignHelpers.getCertificadoInfo(cert, campo: "CN=")
        LogManager.info("Certificado seleccionado para firmar: \(cnLog)")

        if parametros.verificarTsl {
            let tsl = try await TslService.getInstance()
            if certChain.isEmpty {
                certChain = [cert]
            }
            let resultado = try? CertValidator.validarCadenaCompleta(chain: certChain, tsl: tsl)
            if resultado != nil {
                LogManager.info("Validación TSL completada")
            }
        }

        var imageData: Data?
        if parametros.visibleFirma {
            let imageBytes = try generarImagenFirmaBytes(cert: cert, params: parametros)
            imageData = imageBytes
        }

        let (preparedData, byteRange, contentToSign) = try PDFSigner.prepareForSigning(
            pdfData: pdfData,
            params: parametros
        )

        let cmsData = try CMSBuilder.buildSignedData(
            content: contentToSign,
            privateKey: privateKey,
            certificate: cert,
            chain: certChain
        )

        var finalCmsData = cmsData
        if parametros.level == .t, let tsaUrl = parametros.tsaUrl, !tsaUrl.isEmpty {
            finalCmsData = try CMSBuilder.addLevelTTimestamp(
                signedData: cmsData,
                signedContent: contentToSign,
                tsaUrl: tsaUrl
            )
        }

        let signedPDF = try PDFSigner.embedSignature(
            preparedData: preparedData,
            signatureData: finalCmsData,
            byteRange: byteRange,
            params: parametros,
            imageData: imageData
        )

        let nombreSalida = construirNombreSalida(pdfURL.lastPathComponent, sufijo: parametros.sufijo)
        let destinoURL = URL(fileURLWithPath: parametros.rutaDestino).appendingPathComponent(nombreSalida)

        try signedPDF.write(to: destinoURL, options: .atomic)
        LogManager.info("FIRMA COMPLETADA: \(destinoURL.path)")
    }

    private func cargarCredenciales(_ params: Parameters) async throws -> (SecKey, SecCertificate) {
        if let rutaCert = params.rutaCertificado,
           (rutaCert.lowercased().hasSuffix(".p12") || rutaCert.lowercased().hasSuffix(".pfx")) {
            let p12URL = URL(fileURLWithPath: rutaCert)
            let p12Data = try Data(contentsOf: p12URL)
            let password = params.passwordCertificado ?? ""

            try KeychainManager.importarP12(p12Data: p12Data, password: password)

            if let alias = params.aliasCertificado {
                let pk = try KeychainManager.getPrivateKey(alias: alias)
                let cert = try KeychainManager.getCertificate(alias: alias)
                let chain = try KeychainManager.getCertificateChain(alias: alias)
                certChain = chain
                return (pk, cert)
            }

            throw NSError(domain: "FirmaController", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se pudo cargar la clave/certificado del archivo: \(rutaCert)"])
        } else if let alias = params.aliasCertificado {
            let pk = try KeychainManager.getPrivateKey(alias: alias)
            let cert = try KeychainManager.getCertificate(alias: alias)
            let chain = try KeychainManager.getCertificateChain(alias: alias)
            certChain = chain
            return (pk, cert)
        }

        throw NSError(domain: "FirmaController", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "No se pudo cargar la clave privada o el certificado."])
    }

    private func generarImagenFirmaBytes(cert: SecCertificate, params: Parameters) throws -> Data {
        let nombre = SignHelpers.getCertificadoInfo(cert, campo: "CN=")
        let ruc = SignHelpers.getRUCFromCertificado(cert)

        let fecha = SignHelpers.formatDateFull(Date())
        let titulo = "Firmado digitalmente por"

        var logo: UIImage?
        if let ruta = params.rutaImagen, !ruta.isEmpty {
            if let imgData = try? Data(contentsOf: URL(fileURLWithPath: ruta)) {
                logo = UIImage(data: imgData)
            }
        }

        let cargoStr = SignHelpers.getCertificadoInfo(cert, campo: "T=")
        let empresaStr = SignHelpers.getCertificadoInfo(cert, campo: "O=")

        let cargoOpt = params.incluirCargo && !cargoStr.isEmpty ? cargoStr : nil
        let empresaOpt = params.incluirEmpresa && !empresaStr.isEmpty ? empresaStr : nil

        var originalHeight = params.height
        let alturaCalculada = ImageWriter.calcularAlturaRequerida(
            nombre: nombre,
            ruc: !ruc.isEmpty ? ruc : nil,
            empresa: empresaOpt,
            cargo: cargoOpt,
            fontSize: params.fontSize
        )

        if originalHeight > 0, originalHeight != alturaCalculada {
            params.y = params.y + (originalHeight - alturaCalculada)
        }
        params.height = alturaCalculada
        params.width = 210

        let image = ImageWriter.generarImagenFirmaHD(
            logo: logo,
            titulo: titulo,
            nombre: nombre,
            ruc: !ruc.isEmpty ? ruc : nil,
            empresa: empresaOpt,
            cargo: cargoOpt,
            fecha: fecha,
            width: params.width,
            height: params.height,
            fontSize: params.fontSize
        )

        guard let pngData = image.pngData() else {
            throw NSError(domain: "FirmaController", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error generando PNG de firma"])
        }
        return pngData
    }

    private func construirNombreSalida(_ nombreOriginal: String, sufijo: String?) -> String {
        let suf = sufijo?.isEmpty ?? true ? "_FIRMADO" : sufijo!
        if let idx = nombreOriginal.lastIndex(of: ".") {
            return String(nombreOriginal[..<idx]) + suf + String(nombreOriginal[idx...])
        }
        return nombreOriginal + suf
    }
}
