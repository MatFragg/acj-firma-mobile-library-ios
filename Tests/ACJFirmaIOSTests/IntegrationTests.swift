import XCTest
@testable import ACJFirmaIOS

final class IntegrationTests: XCTestCase {

    // The test certificate password. Change to match test_cert.p12.
    let testCertPassword: String? = nil // e.g., "test"

    func testKeychainList() throws {
        let aliases = try KeychainManager.listCertificados()
        // Just verify the call doesn't crash
        XCTAssertNotNil(aliases)
    }

    func testNonRepudiationCheck() throws {
        // Test that non-repudiation check works on a known cert
        // This is a functional test - requires a cert in the keychain
        let aliases = try KeychainManager.listCertificados()
        if !aliases.isEmpty {
            let cert = try KeychainManager.getCertificate(alias: aliases[0])
            let nr = SignHelpers.nonRepudiation(cert)
            // nonRepudiation should be true for valid certs
            XCTAssertTrue(nr)
        }
    }

    func testExisteAlias() {
        let exists = KeychainManager.existeAlias(alias: "non_existent_alias_xyz")
        XCTAssertFalse(exists)
    }

    func testCertificateChainForNonExistent() {
        XCTAssertThrowsError(try KeychainManager.getCertificateChain(alias: "non_existent"))
    }
}
