import Foundation
import Security

public enum TslContext {
    case production
    case test(url: String)
}

public class TslService {
    private static var instance: TslService?
    private static let lock = NSLock()

    private var certificates: [SecCertificate] = []
    private var errorMessage: String?
    private var issueDate: Date?
    private var nextUpdate: Date?
    private var isValid: Bool = false

    public static func getInstance(context: TslContext = .production) async throws -> TslService {
        lock.lock()
        defer { lock.unlock() }

        if let existing = instance, existing.isValid {
            return existing
        }

        let service = TslService()
        try await service.cargarTsl(context: context)
        instance = service
        return service
    }

    public static func resetInstance() {
        lock.lock()
        defer { lock.unlock() }
        instance = nil
    }

    private func cargarTsl(context: TslContext) async throws {
        let tslUrl: String
        let altUrl: String

        switch context {
        case .production:
            tslUrl = "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml"
            altUrl = "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml"
        case .test(let url):
            tslUrl = url
            altUrl = url
        }

        let expiration: TimeInterval = 24 * 60 * 60
        let dcFilter = ".*(RENIEC|ECEP|ECERNEP|EC-PSVA).*"

        do {
            LogManager.info("Validando TSL...")
            let (certs, issue, next) = try await TslRepository.load(
                countryCode: "PE",
                url: tslUrl,
                expiration: expiration,
                dcFilter: dcFilter,
                verifyTsl: true
            )

            self.certificates = certs
            self.issueDate = issue
            self.nextUpdate = next

            try TslValidator.verificarVigencia(issueDate: issue, nextUpdate: next)
            self.isValid = true
            LogManager.info("La TSL está correcta")
        } catch {
            LogManager.warning("Fallo TSL primaria, intentando alternativa...")
            do {
                let (certs, issue, next) = try await TslRepository.load(
                    countryCode: "PE",
                    url: altUrl,
                    expiration: expiration,
                    dcFilter: dcFilter,
                    verifyTsl: true
                )
                self.certificates = certs
                self.issueDate = issue
                self.nextUpdate = next
                try TslValidator.verificarVigencia(issueDate: issue, nextUpdate: next)
                self.isValid = true
                LogManager.info("La TSL está correcta (alternativa)")
            } catch {
                self.errorMessage = "Error cargando TSL: \(error.localizedDescription)"
                self.isValid = false
                throw error
            }
        }
    }

    public func getCertificados() -> [SecCertificate] {
        certificates
    }

    public func isValida() -> Bool {
        isValid && !certificates.isEmpty
    }

    public func getError() -> String? {
        errorMessage
    }
}
