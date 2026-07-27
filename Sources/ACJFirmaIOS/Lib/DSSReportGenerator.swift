import Foundation

public enum DSSReportType {
    case simple
    case detailed
    case web
}

public class DSSReportGenerator {

    private static let indent = "  "

    /// Generates a simple HTML report from a DSS XML report string.
    public static func generateSimpleReport(_ xmlReport: String) -> String {
        let extracted = extractSimpleFields(xmlReport)
        return buildSimpleHTML(extracted)
    }

    /// Generates a detailed HTML report from a DSS XML report string.
    public static func generateDetailedReport(_ xmlReport: String) -> String {
        let signatures = extractSignatures(xmlReport)
        return buildDetailedHTML(signatures)
    }

    /// Generates a web-friendly HTML report.
    public static func generateWebReport(_ xmlReport: String) -> String {
        let signatures = extractSignatures(xmlReport)
        return buildWebHTML(signatures)
    }

    // MARK: - Extraction

    private struct SimpleFields {
        var documentName = ""
        var indication = ""
        var signedBy = ""
        var signingTime = ""
        var errors: [String] = []
    }

    private struct SignatureInfo {
        var id = ""
        var signedBy = ""
        var signingTime = ""
        var indication = ""
        var level = ""
        var errors: [String] = []
    }

    private static func extractSimpleFields(_ xml: String) -> SimpleFields {
        var fields = SimpleFields()
        fields.documentName = extractTag(xml, "DocumentName")
        fields.indication = extractTag(xml, "Indication")
        fields.signedBy = extractTag(xml, "SignedBy")
        fields.signingTime = extractTag(xml, "SigningTime")
        let errorsXML = extractTagBlock(xml, "Errors")
        if !errorsXML.isEmpty {
            let message = extractTag(errorsXML, "Error")
            if !message.isEmpty {
                fields.errors = [message]
            }
        }
        return fields
    }

    private static func extractSignatures(_ xml: String) -> [SignatureInfo] {
        var signatures: [SignatureInfo] = []
        let sigBlocks = extractAllTagBlocks(xml, "Signature")
        for block in sigBlocks {
            var sig = SignatureInfo()
            sig.id = extractTag(block, "Id")
            sig.signedBy = extractTag(block, "SignedBy")
            sig.signingTime = extractTag(block, "SigningTime")
            sig.indication = extractTag(block, "Indication")
            sig.level = extractTag(block, "SignatureLevel")
            let errorsBlock = extractTagBlock(block, "Errors")
            if !errorsBlock.isEmpty {
                sig.errors = extractAllTags(errorsBlock, "Error")
            } else {
                let mainErrors = extractTagBlock(xml, "Errors")
                if !mainErrors.isEmpty {
                    sig.errors = extractAllTags(mainErrors, "Error")
                }
            }
            signatures.append(sig)
        }
        return signatures
    }

    // MARK: - HTML Builders

    private static func buildSimpleHTML(_ fields: SimpleFields) -> String {
        let indicationColor = fields.indication.contains("PASSED") ? "green" : "red"
        return """
        <!DOCTYPE html>
        <html><head><meta charset="UTF-8"><title>Reporte de Validación</title>
        <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .passed { color: green; font-weight: bold; }
        .failed { color: red; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        </style></head><body>
        <h1>Reporte de Validación de Firmas</h1>
        <table>
        <tr><th>Documento</th><td>\(escapeHTML(fields.documentName))</td></tr>
        <tr><th>Firmante</th><td>\(escapeHTML(fields.signedBy))</td></tr>
        <tr><th>Fecha de Firma</th><td>\(escapeHTML(fields.signingTime))</td></tr>
        <tr><th>Resultado</th><td class="\(indicationColor)">\(escapeHTML(fields.indication))</td></tr>
        </table>
        \(fields.errors.isEmpty ? "" : "<p style='color:red'>Errores: \(fields.errors.map(escapeHTML).joined(separator: "<br>"))</p>")
        </body></html>
        """
    }

    private static func buildDetailedHTML(_ signatures: [SignatureInfo]) -> String {
        var rows = ""
        for sig in signatures {
            let indicationColor = sig.indication.contains("PASSED") ? "passed" : "failed"
            let errorsHTML = sig.errors.isEmpty ? "—" : sig.errors.map { "<span style='color:red'>\(escapeHTML($0))</span>" }.joined(separator: "<br>")
            rows += """
            <tr>
                <td>\(escapeHTML(sig.id))</td>
                <td>\(escapeHTML(sig.signedBy))</td>
                <td>\(escapeHTML(sig.signingTime))</td>
                <td class="\(indicationColor)">\(escapeHTML(sig.indication))</td>
                <td>\(escapeHTML(sig.level))</td>
                <td>\(errorsHTML)</td>
            </tr>
            """
        }
        return """
        <!DOCTYPE html>
        <html><head><meta charset="UTF-8"><title>Reporte Detallado</title>
        <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .passed { color: green; font-weight: bold; }
        .failed { color: red; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        </style></head><body>
        <h1>Reporte Detallado de Validación</h1>
        <table>
        <tr><th>ID</th><th>Firmante</th><th>Fecha</th><th>Resultado</th><th>Nivel</th><th>Errores</th></tr>
        \(rows)
        </table>
        </body></html>
        """
    }

    private static func buildWebHTML(_ signatures: [SignatureInfo]) -> String {
        let content = buildDetailedHTML(signatures)
        return content.replacingOccurrences(of: "<html>", with: "<html><meta name='viewport' content='width=device-width, initial-scale=1'>")
    }

    // MARK: - XML Helpers

    private static func extractTag(_ xml: String, _ tag: String) -> String {
        let pattern = "<\(tag)[^>]*>(.*?)</\(tag)>"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else { return "" }
        let nsRange = NSRange(xml.startIndex..<xml.endIndex, in: xml)
        guard let match = regex.firstMatch(in: xml, range: nsRange) else { return "" }
        guard let range = Range(match.range(at: 1), in: xml) else { return "" }
        return String(xml[range]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func extractTagBlock(_ xml: String, _ tag: String) -> String {
        let pattern = "<\(tag)[^>]*>(.*?)</\(tag)>"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else { return "" }
        let nsRange = NSRange(xml.startIndex..<xml.endIndex, in: xml)
        guard let match = regex.firstMatch(in: xml, range: nsRange) else { return "" }
        guard let range = Range(match.range(at: 0), in: xml) else { return "" }
        return String(xml[range])
    }

    private static func extractAllTagBlocks(_ xml: String, _ tag: String) -> [String] {
        let pattern = "<\(tag)[^>]*>(.*?)</\(tag)>"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else { return [] }
        let nsRange = NSRange(xml.startIndex..<xml.endIndex, in: xml)
        let matches = regex.matches(in: xml, range: nsRange)
        return matches.compactMap { match -> String? in
            guard let range = Range(match.range(at: 0), in: xml) else { return nil }
            return String(xml[range])
        }
    }

    private static func extractAllTags(_ xml: String, _ tag: String) -> [String] {
        let pattern = "<\(tag)[^>]*>(.*?)</\(tag)>"
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators]) else { return [] }
        let nsRange = NSRange(xml.startIndex..<xml.endIndex, in: xml)
        let matches = regex.matches(in: xml, range: nsRange)
        return matches.compactMap { match -> String? in
            guard let range = Range(match.range(at: 1), in: xml) else { return nil }
            return String(xml[range]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private static func escapeHTML(_ str: String) -> String {
        str.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
