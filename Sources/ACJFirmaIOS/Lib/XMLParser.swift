import Foundation

public class XMLParserUtil {

    /// Safely parses XML data using Foundation's SAX parser.
    /// Returns the root element name or empty string on failure.
    public static func parseXML(data: Data) -> String? {
        let parser = Foundation.XMLParser(data: data)
        let delegate = RootNameDelegate()
        parser.delegate = delegate
        if parser.parse() {
            return delegate.rootName
        }
        return nil
    }
}

private class RootNameDelegate: NSObject, Foundation.XMLParserDelegate {
    var rootName: String?
    private var parsedRoot = false

    func parser(_ parser: Foundation.XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        if !parsedRoot {
            rootName = elementName
            parsedRoot = true
        }
    }
}
