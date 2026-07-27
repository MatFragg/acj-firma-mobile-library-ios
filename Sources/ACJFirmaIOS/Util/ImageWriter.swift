import Foundation
import UIKit

public class ImageWriter {

    public static func generarImagenFirmaHD(
        logo: UIImage?,
        titulo: String,
        nombre: String,
        ruc: String?,
        empresa: String?,
        cargo: String?,
        fecha: String,
        width: Int,
        height: Int,
        fontSize: Int
    ) -> UIImage {
        let scale: CGFloat = 4.0
        let scaledWidth = CGFloat(width) * scale
        let scaledHeight = CGFloat(height) * scale

        let renderer = UIGraphicsImageRenderer(size: CGSize(width: scaledWidth, height: scaledHeight))
        let image = renderer.image { (ctx: UIGraphicsImageRendererContext) -> Void in
            let c = ctx.cgContext
            c.scaleBy(x: scale, y: scale)
            c.setFillColor(UIColor.white.cgColor)
            c.fill(CGRect(x: 0, y: 0, width: CGFloat(width), height: CGFloat(height)))

            let logoAreaWidth = CGFloat(width) * 0.30
            let paddingX: CGFloat = 4
            let xTexto = logoAreaWidth + paddingX
            let lineH = CGFloat(fontSize) + 2

            var nombreFinal = nombre
            if let rucStr = ruc, !rucStr.isEmpty, !nombreFinal.contains("RUC:\(rucStr)") {
                if !nombreFinal.contains(rucStr) {
                    nombreFinal += " RUC:\(rucStr)"
                } else {
                    nombreFinal = nombreFinal.replacingOccurrences(of: rucStr, with: "RUC:\(rucStr)")
                }
            }

            let envolvente = SignHelpers.cropText(nombreFinal, longitud: 30)
            let lineasNombre = envolvente.components(separatedBy: "\n")

            var lineasCargo: [String] = []
            if let c = cargo, !c.isEmpty {
                lineasCargo = SignHelpers.cropText(c, longitud: 30).components(separatedBy: "\n")
            }
            var lineasEmpresa: [String] = []
            if let e = empresa, !e.isEmpty {
                lineasEmpresa = SignHelpers.cropText(e, longitud: 30).components(separatedBy: "\n")
            }

            let lineCount = 1 + lineasNombre.count + lineasCargo.count + lineasEmpresa.count + 1 + 1
            let totalContentHeight = lineH * CGFloat(lineCount)
            let yStart = (CGFloat(height) - totalContentHeight) / 2 + CGFloat(fontSize) - 1

            let paragraphStyle = NSMutableParagraphStyle()
            paragraphStyle.lineBreakMode = .byWordWrapping
            let textAttrs: [NSAttributedString.Key: Any] = [
                .font: UIFont.systemFont(ofSize: CGFloat(fontSize)),
                .foregroundColor: UIColor.black,
                .paragraphStyle: paragraphStyle,
            ]

            if let logoImg = logo {
                let logoAvailableWidth = logoAreaWidth - (paddingX * 2)
                let aspectRatio = logoImg.size.height / logoImg.size.width
                var logoDrawWidth = logoAvailableWidth
                var logoDrawHeight = logoDrawWidth * aspectRatio
                if logoDrawHeight > CGFloat(height) - 10 {
                    logoDrawHeight = CGFloat(height) - 10
                    logoDrawWidth = logoDrawHeight / aspectRatio
                }
                let logoX = paddingX + (logoAvailableWidth - logoDrawWidth) / 2
                let logoY = (CGFloat(height) - logoDrawHeight) / 2
                logoImg.draw(in: CGRect(x: logoX, y: logoY, width: logoDrawWidth, height: logoDrawHeight))
            }

            var y = yStart
            let displayTitulo = titulo.isEmpty ? "Firmado digitalmente por" : titulo
            (displayTitulo as NSString).draw(at: CGPoint(x: xTexto, y: y), withAttributes: textAttrs)
            y += lineH

            for linea in lineasNombre {
                (linea as NSString).draw(at: CGPoint(x: xTexto, y: y), withAttributes: textAttrs)
                y += lineH
            }
            for linea in lineasEmpresa {
                (linea as NSString).draw(at: CGPoint(x: xTexto, y: y), withAttributes: textAttrs)
                y += lineH
            }
            for linea in lineasCargo {
                (linea as NSString).draw(at: CGPoint(x: xTexto, y: y), withAttributes: textAttrs)
                y += lineH
            }

            let fechaDisplay = fecha.hasPrefix("Fecha") ? fecha : "Fecha: \(fecha)"
            (fechaDisplay as NSString).draw(at: CGPoint(x: xTexto, y: y), withAttributes: textAttrs)
            y += lineH
            ("Firmado con ACJ Signature" as NSString).draw(at: CGPoint(x: xTexto, y: y), withAttributes: textAttrs)
        }
        return image
    }

    public static func generarImagenFirmaSimple(
        titulo: String,
        nombre: String,
        fecha: String,
        width: Int,
        height: Int,
        fontSize: Int
    ) -> UIImage {
        generarImagenFirmaHD(
            logo: nil,
            titulo: titulo,
            nombre: nombre,
            ruc: nil,
            empresa: nil,
            cargo: nil,
            fecha: fecha,
            width: width,
            height: height,
            fontSize: fontSize
        )
    }

    public static func generarImagenFirmaConLogo(
        logo: UIImage?,
        titulo: String,
        nombre: String,
        fecha: String,
        width: Int,
        height: Int,
        fontSize: Int
    ) -> UIImage {
        generarImagenFirmaHD(
            logo: logo,
            titulo: titulo,
            nombre: nombre,
            ruc: nil,
            empresa: nil,
            cargo: nil,
            fecha: fecha,
            width: width,
            height: height,
            fontSize: fontSize
        )
    }

    public static func calcularAlturaRequerida(
        nombre: String,
        ruc: String?,
        empresa: String?,
        cargo: String?,
        fontSize: Int
    ) -> Int {
        var nombreFinal = nombre
        if let rucStr = ruc, !rucStr.isEmpty, !nombreFinal.contains("RUC:\(rucStr)") {
            if !nombreFinal.contains(rucStr) {
                nombreFinal += " RUC:\(rucStr)"
            } else {
                nombreFinal = nombreFinal.replacingOccurrences(of: rucStr, with: "RUC:\(rucStr)")
            }
        }

        let textoEnvolvente = SignHelpers.cropText(nombreFinal, longitud: 30)
        let lineasNombre = textoEnvolvente.components(separatedBy: "\n")

        var extraLines = 0
        if let e = empresa, !e.isEmpty {
            extraLines += SignHelpers.cropText(e, longitud: 30).components(separatedBy: "\n").count
        }
        if let c = cargo, !c.isEmpty {
            extraLines += SignHelpers.cropText(c, longitud: 30).components(separatedBy: "\n").count
        }

        let lineH = CGFloat(fontSize) + 2
        return Int(lineH * CGFloat(1 + lineasNombre.count + extraLines + 1 + 1)) + 5
    }
}
