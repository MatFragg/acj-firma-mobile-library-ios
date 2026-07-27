import Foundation
import PDFKit

public class PDFSigner {

    private static let placeholderHexLen = 40000

    /// Prepares the PDF for PAdES signing by inserting a signature dictionary with placeholders.
    /// Returns prepared data, the ByteRange, and the exact byte content to be signed via CMS.
    public static func prepareForSigning(pdfData: Data, params: Parameters) throws -> (preparedData: Data, byteRange: [Int], contentToSign: Data) {
        guard let eofRange = pdfData.range(of: Data("%%EOF".utf8), options: .backwards) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "PDF inválido: no se encontró %%EOF"])
        }

        let objNum = nextObjectNumber(in: pdfData)
        let reason = pdfEscape(params.motivo)
        let location = pdfEscape(params.location)
        let dateStr = pdfDateFormat()
        let brPad = "0000000000 0000000000 0000000000 0000000000"
        let placeholderHex = String(repeating: "0", count: placeholderHexLen)

        let sigDictStr = """
        \(objNum) 0 obj
        << /Type /Sig
           /Filter /Adobe.PPKLite
           /SubFilter /adbe.pkcs7.detached
           /ByteRange [\(brPad)]
           /Contents <\(placeholderHex)>
           /Reason (\(reason))
           /Location (\(location))
           /M (D:\(dateStr))
        >>
        endobj

        """

        guard let sigData = sigDictStr.data(using: .ascii) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error codificando diccionario de firma"])
        }

        var mutableData = pdfData
        mutableData.insert(contentsOf: sigData, at: eofRange.lowerBound)

        guard let placeholderRange = mutableData.range(of: Data(placeholderHex.utf8)) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error localizando placeholder en PDF"])
        }

        let contentsStart = placeholderRange.lowerBound - 1
        let contentsEnd = placeholderRange.upperBound

        guard let brRange = mutableData.range(of: Data(brPad.utf8)) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error localizando ByteRange placeholder"])
        }

        let br1 = contentsStart
        let br2 = contentsEnd + 1
        let br0 = 0
        let br3 = mutableData.count - br2
        let byteRange = [br0, br1, br2, br3]

        let realBRStr = String(format: "%010d %010d %010d %010d", br0, br1, br2, br3)
        guard let realBRData = realBRStr.data(using: .ascii) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error codificando ByteRange"])
        }
        mutableData.replaceSubrange(brRange, with: realBRData)

        var contentToSign = Data()
        contentToSign.append(mutableData[br0..<br1])
        contentToSign.append(mutableData[br2..<mutableData.count])

        return (mutableData, byteRange, contentToSign)
    }

    /// Embeds the CMS signature data into the prepared PDF, replacing the hex placeholder.
    /// CMS hex length must not exceed the placeholder length.
    public static func embedSignature(preparedData: Data, signatureData: Data, byteRange: [Int], params: Parameters, imageData: Data?) throws -> Data {
        let cmsHex = signatureData.map { String(format: "%02x", $0) }.joined()

        guard cmsHex.count <= placeholderHexLen else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "CMS demasiado grande para el placeholder (\(cmsHex.count) > \(placeholderHexLen))"])
        }

        let paddedHex = cmsHex + String(repeating: "0", count: placeholderHexLen - cmsHex.count)

        let gapStart = byteRange[1]
        let gapEnd = byteRange[2]
        let gapData = preparedData[gapStart..<gapEnd]
        let gapStr = String(data: gapData, encoding: .ascii) ?? ""

        guard let hexRange = gapStr.range(of: String(repeating: "0", count: placeholderHexLen)) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "No se encontró placeholder hex en el gap del ByteRange"])
        }

        let nativeStart = gapStr.distance(from: gapStr.startIndex, to: hexRange.lowerBound)
        let replaceStart = gapStart + nativeStart

        guard let paddedData = paddedHex.data(using: .ascii) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error codificando CMS hex"])
        }

        var result = preparedData
        result.replaceSubrange(replaceStart..<replaceStart + paddedData.count, with: paddedData)

        if let imgData = imageData, params.visibleFirma {
            result = try addVisibleAnnotation(pdfData: result, imageData: imgData, params: params)
        }

        return result
    }

    // MARK: - PDF Utilities

    private static func nextObjectNumber(in data: Data) -> Int {
        guard let str = String(data: data, encoding: .ascii) else { return 1 }
        let pattern = "(\\d+)\\s+0\\s+obj"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return 1 }
        let matches = regex.matches(in: str, range: NSRange(location: 0, length: str.utf16.count))
        var maxObj = 0
        for match in matches {
            let range = match.range(at: 1)
            let numStr = (str as NSString).substring(with: range)
            if let num = Int(numStr), num > maxObj {
                maxObj = num
            }
        }
        return maxObj + 1
    }

    private static func pdfEscape(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "(", with: "\\(")
            .replacingOccurrences(of: ")", with: "\\)")
    }

    private static func pdfDateFormat() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMddHHmmssZZZZZ"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        let str = formatter.string(from: Date())
        let clean = str.replacingOccurrences(of: ":", with: "'").replacingOccurrences(of: "+", with: "+")
        return clean
    }

    // MARK: - Visible Annotation

    public static func calcularByteRange(pdfData: Data) throws -> [Int] {
        guard let pdfString = String(data: pdfData, encoding: .ascii) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error leyendo PDF"])
        }

        let patterns = [
            "/ByteRange\\s*\\[\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\\]",
            "/ByteRange[\\[\\s](\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)"
        ]

        for pattern in patterns {
            do {
                let regex = try NSRegularExpression(pattern: pattern, options: [])
                if let match = regex.firstMatch(in: pdfString, options: [], range: NSRange(location: 0, length: pdfString.utf16.count)) {
                    let groups = (1...4).map { i -> Int in
                        let range = match.range(at: i)
                        let str = (pdfString as NSString).substring(with: range)
                        return Int(str) ?? 0
                    }
                    return groups
                }
            } catch {}
        }

        return [0, 0, 0, 0]
    }

    public static func addVisibleAnnotation(
        pdfData: Data,
        imageData: Data,
        params: Parameters
    ) throws -> Data {
        guard let document = PDFDocument(data: pdfData),
              let page = document.page(at: params.pagina - 1) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error cargando PDF para anotación"])
        }

        guard let image = UIImage(data: imageData) else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error creando imagen de sello"])
        }

        let imageBounds = CGRect(
            x: CGFloat(params.x),
            y: page.bounds(for: .mediaBox).height - CGFloat(params.y) - CGFloat(params.height),
            width: CGFloat(params.width),
            height: CGFloat(params.height)
        )

        let props: [PDFAnnotationKey: Any] = [.image: image]
        let annotation = PDFAnnotation(bounds: imageBounds, forType: .stamp, withProperties: props)
        annotation.shouldDisplay = true
        page.addAnnotation(annotation)

        guard let outputData = document.dataRepresentation() else {
            throw NSError(domain: "PDFSigner", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Error guardando PDF con anotación"])
        }
        return outputData
    }
}
