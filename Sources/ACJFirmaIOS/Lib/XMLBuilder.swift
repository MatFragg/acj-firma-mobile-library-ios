import Foundation

public class XMLBuilder {

    public static func parseXML(data: Data) throws -> Any {
        let options: XMLParser.Options = [.nodeLoadExternalEntitiesNever, .documentIncludeContentModel]
        let document = try XMLDocument(data: data, options: options)
        return document
    }

    public static func buildDocument(data: Data) throws -> XMLDocument {
        let options: XMLParser.Options = [.nodeLoadExternalEntitiesNever, .documentIncludeContentModel]
        return try XMLDocument(data: data, options: options)
    }

    public static func safeParse(data: Data) throws -> XMLElement? {
        let doc = try buildDocument(data: data)
        return doc.rootElement()
    }

    public static func extractText(from element: XMLElement?, xpath: String) -> String {
        guard let nodes = try? element?.nodes(forXPath: xpath) else { return "" }
        return nodes.compactMap { $0.stringValue }.first ?? ""
    }

    public static func extractAllTexts(from element: XMLElement?, xpath: String) -> [String] {
        guard let nodes = try? element?.nodes(forXPath: xpath) else { return [] }
        return nodes.compactMap { $0.stringValue }
    }
}
