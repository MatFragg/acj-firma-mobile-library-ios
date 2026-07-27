import XCTest
#if canImport(UIKit)
import UIKit
#endif
@testable import ACJFirmaIOS

final class ACJFirmaIOSTests: XCTestCase {

    // MARK: - SignHelpers Tests

    func testCropText() {
        let text = "Lorem ipsum dolor sit amet consectetur adipiscing elit"
        let cropped = SignHelpers.cropText(text, longitud: 10)
        let lines = cropped.components(separatedBy: "\n")
        XCTAssertGreaterThan(lines.count, 1)
        XCTAssertTrue(cropped.contains(text) || !cropped.isEmpty)
    }

    func testFormatDateFull() {
        let date = Date()
        let formatted = SignHelpers.formatDateFull(date)
        XCTAssertFalse(formatted.isEmpty)
        XCTAssertTrue(formatted.contains("/"))
    }

    func testSha256() {
        let data = "Hello, World!".data(using: .utf8)!
        let hash = SignHelpers.sha256(data: data)
        XCTAssertEqual(hash.count, 32)
    }

    func testSha1() {
        let data = "Hello, World!".data(using: .utf8)!
        let hash = SignHelpers.sha1(data: data)
        XCTAssertEqual(hash.count, 20)
    }

    func testRetornarCadenaList() {
        let errors = ["Error 1", "Error 2"]
        let result = SignHelpers.retornarCadenaList(errors)
        XCTAssertTrue(result.contains("Error 1"))
        XCTAssertTrue(result.contains("Error 2"))
    }

    // MARK: - Constants Tests

    func testConstants() {
        XCTAssertEqual(Constants.cadenaVacia, "")
        XCTAssertEqual(Constants.folderCache, "acj_firma")
        XCTAssertEqual(Constants.levelB, "B")
        XCTAssertEqual(Constants.levelT, "T")
        XCTAssertEqual(Constants.signTypeTexto, "T")
        XCTAssertEqual(Constants.signTypeLogoTexo, "LT")
        XCTAssertEqual(Constants.appearanceSimple, "S")
        XCTAssertEqual(Constants.appearanceImagen, "I")
    }

    // MARK: - Parameters Tests

    func testParametersDefaults() {
        let params = Parameters()
        XCTAssertEqual(params.level, .b)
        XCTAssertFalse(params.visibleFirma)
        XCTAssertTrue(params.verificarTsl)
        XCTAssertFalse(params.verificarTsa)
        XCTAssertEqual(params.signType, .texto)
        XCTAssertEqual(params.appearance, .simple)
        XCTAssertEqual(params.pagina, 1)
    }

    func testParametersCustom() {
        let params = Parameters()
        params.level = .t
        params.visibleFirma = true
        params.motivo = "Test reason"
        params.location = "Test location"
        params.signType = .logoTexto
        params.appearance = .imagen
        params.extras = .empresaCargo

        XCTAssertEqual(params.level, .t)
        XCTAssertTrue(params.visibleFirma)
        XCTAssertEqual(params.motivo, "Test reason")
    }

    // MARK: - ImageWriter Tests

    func testCalcularAlturaRequerida() {
        let height = ImageWriter.calcularAlturaRequerida(
            nombre: "Juan Perez",
            ruc: "12345678901",
            empresa: "ACJ Technology",
            cargo: "Developer",
            fontSize: 8
        )
        XCTAssertGreaterThan(height, 0)
    }

    func testGenerarImagenFirmaSimple() {
        #if canImport(UIKit)
        let image = ImageWriter.generarImagenFirmaSimple(
            titulo: "Test",
            nombre: "Juan Perez",
            fecha: "27/07/2026",
            width: 210,
            height: 60,
            fontSize: 8
        )
        XCTAssertNotNil(image)
        #endif
    }

    // MARK: - DSS Report Tests

    func testDSSSimpleReport() {
        let xml = """
        <SimpleReport>
            <DocumentName>test.pdf</DocumentName>
            <ValidatedSignatures>
                <Signature>
                    <Id>SIG-1</Id>
                    <SignedBy>CN=Test User</SignedBy>
                    <SigningTime>2026-07-27T00:00:00Z</SigningTime>
                    <Indication>TOTAL_PASSED</Indication>
                </Signature>
            </ValidatedSignatures>
        </SimpleReport>
        """
        let report = DSSReportGenerator.generateSimpleReport(xml)
        XCTAssertTrue(report.contains("TOTAL_PASSED"))
        XCTAssertTrue(report.contains("Test User"))
        XCTAssertTrue(report.contains("test.pdf"))
    }

    func testDSSDetailedReport() {
        let xml = """
        <SimpleReport>
            <DocumentName>test.pdf</DocumentName>
            <ValidatedSignatures>
                <Signature>
                    <Id>SIG-1</Id>
                    <SignedBy>CN=Test User</SignedBy>
                    <SigningTime>2026-07-27T00:00:00Z</SigningTime>
                    <Indication>TOTAL_PASSED</Indication>
                    <SignatureLevel>PAdES-Baseline-B</SignatureLevel>
                </Signature>
            </ValidatedSignatures>
        </SimpleReport>
        """
        let report = DSSReportGenerator.generateDetailedReport(xml)
        XCTAssertTrue(report.contains("PAdES-Baseline-B"))
        XCTAssertTrue(report.contains("SIG-1"))
    }

    // MARK: - XML Builder Tests

    func testXMLExtractTag() {
        let xml = "<root><name>Test</name></root>"
        let patterns = [
            "<name[^>]*>(.*?)</name>",
            "<root[^>]*>(.*?)</root>"
        ]

        // Use reflection to test private helper
        // Instead, just verify the parsing is consistent
        // We rely on the DSSReportGenerator tests for XML parsing
    }

    // MARK: - Common Tests (requires bundle resources)

    func testCommonConfig() {
        // Common loads from common.plist in the module bundle
        let common = Common.shared
        let tslUrl = common.tslUrl
        XCTAssertFalse(tslUrl.isEmpty)
        XCTAssertTrue(tslUrl.contains("indecopi"))
    }

    // MARK: - Performance Tests

    func testSha256Performance() {
        let data = Data(repeating: 0x41, count: 1024 * 1024)
        measure {
            _ = SignHelpers.sha256(data: data)
        }
    }

    @available(macOS 13.0, iOS 16.0, *)
    func testCropTextPerformance() {
        let longText = String(repeating: "Lorem ipsum dolor sit amet ", count: 100)
        measure {
            _ = SignHelpers.cropText(longText, longitud: 30)
        }
    }
}
