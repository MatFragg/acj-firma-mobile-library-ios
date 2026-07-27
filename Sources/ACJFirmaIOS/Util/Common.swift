import Foundation

public class Common {
    public static let shared = Common()
    private var properties: [String: String] = [:]

    private init() {
        guard let url = Bundle.module.url(forResource: "common", withExtension: "plist"),
              let data = try? Data(contentsOf: url),
              let dict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: String] else {
            return
        }
        properties = dict
    }

    public func get(_ key: String) -> String? {
        properties[key]
    }

    public var tslUrl: String {
        self.get("app.url.tsl") ?? "https://iofe.indecopi.gob.pe/TSL/tsl-pe.xml"
    }

    public var tslAlternativeUrl: String {
        self.get("app.url.tsl.alterno") ?? tslUrl
    }

    public var tsaUrl: String? {
        self.get("app.url.tsa")
    }

    public var tsaAlternativeUrl: String? {
        self.get("app.url.tsa.alterno")
    }

    public var tsaUser: String? {
        self.get("app.tsa.user")
    }

    public var tsaPassword: String? {
        self.get("app.tsa.password")
    }
}
