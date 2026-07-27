import Foundation
import Security

public class TslRepository {

    private static let cacheDirName = "acj_siganture_cache_tsl"
    private static let cacheFileName = "tsl-PE.xml"

    public static func load(
        countryCode: String,
        url: String,
        expiration: TimeInterval,
        dcFilter: String?,
        verifyTsl: Bool
    ) async throws -> (certs: [SecCertificate], issueDate: Date?, nextUpdate: Date?) {
        let bytes = try await obtenerBytes(url: url, expiration: expiration)
        return try parsear(bytes, countryCode: countryCode, dcFilter: dcFilter)
    }

    private static func obtenerBytes(url: String, expiration: TimeInterval) async throws -> Data {
        let cacheDir = try cacheDirectory()
        let cacheFile = cacheDir.appendingPathComponent(cacheFileName)

        let debeDescargar = expiration <= 0
            || !FileManager.default.fileExists(atPath: cacheFile.path)
            || (Date().timeIntervalSince(try FileManager.default.attributesOfItem(atPath: cacheFile.path)[.modificationDate] as? Date ?? .distantPast) > expiration)

        if !debeDescargar {
            LogManager.info("Usando TSL en caché: \(cacheFile.path)")
            return try Data(contentsOf: cacheFile)
        }

        LogManager.info("Descargando TSL desde: \(url)")
        guard let downloadURL = URL(string: url) else {
            throw NSError(domain: "TslRepository", code: -1, userInfo: [NSLocalizedDescriptionKey: "URL inválida: \(url)"])
        }

        let (data, response) = try await URLSession.shared.data(from: downloadURL)
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw NSError(domain: "TslRepository", code: -1, userInfo: [NSLocalizedDescriptionKey: "Error HTTP descargando TSL"])
        }

        try data.write(to: cacheFile, options: .atomic)
        LogManager.info("TSL cacheada en: \(cacheFile.path)")
        return data
    }

    private static func parsear(_ data: Data, countryCode: String, dcFilter: String?) throws -> (certs: [SecCertificate], issueDate: Date?, nextUpdate: Date?) {
        let parser = TslXMLParser()
        try parser.parse(data: data, countryCode: countryCode)
        LogManager.info("TSL parseada. Certificados cargados: \(parser.certificates.count)")
        return (parser.certificates, parser.issueDate, parser.nextUpdate)
    }

    private static func cacheDirectory() throws -> URL {
        let paths = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
        let cacheDir = paths[0].appendingPathComponent(cacheDirName, isDirectory: true)
        if !FileManager.default.fileExists(atPath: cacheDir.path) {
            try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
        }
        return cacheDir
    }

    public static func limpiarCache() {
        guard let cacheDir = try? cacheDirectory() else { return }
        let files = (try? FileManager.default.contentsOfDirectory(at: cacheDir, includingPropertiesForKeys: nil)) ?? []
        for file in files where file.lastPathComponent.lowercased().contains("tsl") {
            try? FileManager.default.removeItem(at: file)
            LogManager.info("TSL borrada: \(file.lastPathComponent)")
        }
    }
}

private class TslXMLParser: NSObject, XMLParserDelegate {
    var certificates: [SecCertificate] = []
    var issueDate: Date?
    var nextUpdate: Date?
    private var currentElement = ""
    private var currentText = ""
    private var inX509Certificate = false
    private var countryCode = ""

    func parse(data: Data, countryCode: String) throws {
        self.countryCode = countryCode
        let parser = Foundation.XMLParser(data: data)
        parser.delegate = self
        if !parser.parse() {
            if let error = parser.parserError {
                throw error
            }
        }
    }

    func parser(_ parser: Foundation.XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        currentElement = elementName
        currentText = ""
        if elementName.hasSuffix("X509Certificate") {
            inX509Certificate = true
        }
    }

    func parser(_ parser: Foundation.XMLParser, foundCharacters string: String) {
        currentText += string
    }

    func parser(_ parser: Foundation.XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        let trimmed = currentText.trimmingCharacters(in: .whitespacesAndNewlines)

        if elementName.hasSuffix("IssueDate") || elementName.hasSuffix("IssueDateTime") {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: trimmed) {
                issueDate = date
            } else {
                formatter.formatOptions = [.withInternetDateTime]
                if let date = formatter.date(from: trimmed) {
                    issueDate = date
                }
            }
        } else if elementName.hasSuffix("NextUpdate") {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: trimmed) {
                nextUpdate = date
            } else {
                formatter.formatOptions = [.withInternetDateTime]
                if let date = formatter.date(from: trimmed) {
                    nextUpdate = date
                }
            }
        } else if elementName.hasSuffix("X509Certificate") {
            inX509Certificate = false
            if !trimmed.isEmpty {
                let cleanBase64 = trimmed.components(separatedBy: .whitespacesAndNewlines).joined()
                if let certData = Data(base64Encoded: cleanBase64),
                   let cert = SecCertificateCreateWithData(nil, certData as CFData) {
                    certificates.append(cert)
                }
            }
        }

        currentText = ""
    }
}
