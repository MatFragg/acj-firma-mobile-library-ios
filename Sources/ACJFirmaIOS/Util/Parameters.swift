import Foundation

public enum FirmaLevel: String {
    case b = "B"
    case t = "T"
}

public enum SignType: String {
    case texto = "T"
    case logoTexto = "LT"
}

public enum Appearance: String {
    case simple = "S"
    case imagen = "I"
}

public enum Extras: String {
    case empresa = "E"
    case cargo = "C"
    case empresaCargo = "CE"
}

public class Parameters {
    public var rutaCertificado: String?
    public var rutaPdfOriginal: String = ""
    public var rutaDestino: String = ""
    public var sufijo: String?

    public var motivo: String = ""
    public var location: String = ""
    public var aliasCertificado: String?
    public var level: FirmaLevel = .b

    public var visibleFirma: Bool = false
    public var signType: SignType = .texto
    public var extras: Extras?
    public var rutaImagen: String?
    public var tituloFirma: String?
    public var appearance: Appearance = .simple
    public var pagina: Int = 1
    public var fontSize: Int = 8
    public var width: Int = 210
    public var height: Int = 60
    public var x: Int = 50
    public var y: Int = 50
    public var incluirCargo: Bool = true
    public var incluirEmpresa: Bool = true

    public var verificarTsl: Bool = true
    public var tslUrl: String = "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml"

    public var verificarTsa: Bool = false
    public var tsaUrl: String?

    public var passwordCertificado: String?

    public init() {}
}
