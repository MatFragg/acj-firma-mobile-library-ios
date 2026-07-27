import Foundation

public class TslValidator {

    public static func verificarVigencia(issueDate: Date?, nextUpdate: Date?) throws {
        guard let issue = issueDate, let next = nextUpdate else {
            LogManager.warning("No se pudieron verificar las fechas de vigencia de la TSL")
            return
        }

        let ahora = Date()
        if ahora < issue {
            throw NSError(domain: "TslValidator", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "La TSL aún no es vigente. Fecha de emisión: \(issue)"])
        }
        if ahora > next {
            throw NSError(domain: "TslValidator", code: -1,
                userInfo: [NSLocalizedDescriptionKey: "La TSL ha vencido. Fecha de vencimiento: \(next)"])
        }
        LogManager.info("TSL dentro de fecha válida")
    }
}
