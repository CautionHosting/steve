import Foundation

enum SmokeFailure: Error, CustomStringConvertible {
    case assertion(String)
    case usage

    var description: String {
        switch self {
        case .assertion(let message): message
        case .usage: "usage: steve-sdk-swift-smoke pinned-x25519|tofu-xwing"
        }
    }
}

func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SmokeFailure.assertion(message)
    }
}

func report(_ message: String) {
    print("  PASS \(message)")
}

func bytes(_ value: String) -> Data {
    Data(value.utf8)
}

func expectedProfile() -> PcrProfile {
    PcrProfile(pcrs: [
        Pcr(index: 0, value: Data(repeating: 0x10, count: 48)),
        Pcr(index: 1, value: Data(repeating: 0x11, count: 48)),
        Pcr(index: 2, value: Data(repeating: 0x12, count: 48)),
        Pcr(index: 3, value: Data(repeating: 0x13, count: 48)),
    ])
}

func config(_ suite: KeyExchangeSuite?) -> SteveClientConfig {
    SteveClientConfig(
        baseUrl: "http://127.0.0.1:49500",
        applicationContext: bytes("steve-sdk-uniffi-smoke-v1"),
        keyExchange: suite,
        sessionRotationIntervalMs: 60_000,
        sessionEstablishmentTimeoutMs: 5_000,
        requestTimeoutMs: 5_000
    )
}

func request(
    method: String,
    path: String,
    headers: [HttpHeader] = [],
    body: Data? = nil
) -> HttpRequest {
    HttpRequest(method: method, path: path, headers: headers, body: body)
}

func requireAttestation(
    _ attestation: AttestationInfo,
    trust: PcrTrustStatus,
    previousSession: Data? = nil
) throws {
    try require(attestation.moduleId == "steve-local-eval", "unexpected module ID")
    try require(attestation.sessionId.count == 16, "session ID must be 16 bytes")
    try require(attestation.pcrs == expectedProfile(), "attestation must expose the signed PCR map")
    try require(attestation.pcrTrust == trust, "unexpected PCR trust status")
    if let previousSession {
        try require(attestation.sessionId != previousSession, "rotation reused the session ID")
    }
}

final class MemoryTrustStore: PcrTrustStore, @unchecked Sendable {
    private let lock = NSLock()
    private var records: [Data: PcrProfile] = [:]
    private var observedKeys: [Data] = []
    private var observedProfiles: [PcrProfile] = []

    func loadOrInsert(key: Data, observed: PcrProfile) throws -> PcrTrustRecord {
        lock.lock()
        defer { lock.unlock() }
        observedKeys.append(key)
        observedProfiles.append(observed)
        if let existing = records[key] {
            return .existing(profile: existing)
        }
        records[key] = observed
        return .inserted
    }

    func snapshot() -> (keys: [Data], profiles: [PcrProfile]) {
        lock.lock()
        defer { lock.unlock() }
        return (observedKeys, observedProfiles)
    }
}

final class FailingTrustStore: PcrTrustStore, @unchecked Sendable {
    func loadOrInsert(key: Data, observed: PcrProfile) throws -> PcrTrustRecord {
        throw PcrTrustStoreCallbackError.Failed(message: "swift trust failure sentinel")
    }
}

func runPinnedX25519() async throws {
    let client = try createPinnedForSyntheticTesting(
        config: config(nil),
        profiles: [expectedProfile()]
    )
    let first = try await client.verifyAttestation()
    try requireAttestation(first, trust: .pinned)
    report("X25519 session established and pinned attestation verified")

    let body = Data([0x00, 0xff, 0x53, 0x54, 0x45, 0x56, 0x45])
    let response = try await client.send(request: request(
        method: "POST",
        path: "/echo?client=swift-pinned&repeat-headers=1",
        headers: [
            HttpHeader(name: "content-type", value: bytes("application/ignored")),
            HttpHeader(name: "Content-Type", value: bytes("application/octet-stream")),
        ],
        body: body
    ))
    try require(response.status == 200, "protected echo returned a non-200 status")
    try require(response.body == body, "protected echo changed the binary body")
    let exchange = response.exchange
    try require(exchange.protocolName == "STEVE-E2P-V2", "exchange protocol metadata differed")
    try require(exchange.protection == "AES-256-GCM", "exchange protection metadata differed")
    try require(exchange.sessionId == first.sessionId, "exchange reported the wrong session")
    try require(exchange.sequence == 1, "first application exchange did not use sequence 1")
    try require(exchange.keyExchange == .x25519, "exchange reported the wrong session KEM")
    try require(exchange.pcrTrust == .pinned, "exchange reported the wrong PCR trust result")
    try require(exchange.outerStatus == 200, "exchange reported the wrong outer HTTP status")
    try require(
        exchange.requestCiphertextBytes == exchange.requestPlaintextBytes + 16,
        "request AES-GCM ciphertext size differed"
    )
    try require(
        exchange.requestEnvelopeBytes > exchange.requestCiphertextBytes,
        "request envelope did not include authenticated metadata"
    )
    try require(
        exchange.responseCiphertextBytes == exchange.responsePlaintextBytes + 16,
        "response AES-GCM ciphertext size differed"
    )
    try require(
        exchange.responseEnvelopeBytes > exchange.responseCiphertextBytes,
        "response envelope did not include authenticated metadata"
    )
    try require(
        response.headers.contains {
            $0.name.lowercased() == "content-type" && $0.value == bytes("application/octet-stream")
        },
        "duplicate request headers did not retain the last value"
    )
    try require(
        response.headers.filter { $0.name.lowercased() == "set-cookie" }.count == 2,
        "repeated response headers were not preserved"
    )
    report("protected binary echo preserved header and body semantics")

    async let slow = client.send(request: request(method: "GET", path: "/delay?ms=80"))
    async let fast = client.send(request: request(method: "GET", path: "/delay?ms=10"))
    let (slowResponse, fastResponse) = try await (slow, fast)
    try require(slowResponse.body == bytes("delayed:80"), "slow concurrent response differed")
    try require(fastResponse.body == bytes("delayed:10"), "fast concurrent response differed")
    report("concurrent protected requests completed on one client")

    let rotated = try await client.rotateSession()
    try requireAttestation(rotated, trust: .pinned, previousSession: first.sessionId)
    report("session rotation produced a new pinned session")
    print("PASS Swift UniFFI smoke: X25519 pinned")
}

func runTofuXwing() async throws {
    let wrongSuite = try createPinnedForSyntheticTesting(
        config: config(.x25519),
        profiles: [expectedProfile()]
    )
    do {
        _ = try await wrongSuite.verifyAttestation()
        throw SmokeFailure.assertion("wrong-suite session unexpectedly succeeded")
    } catch is SmokeFailure {
        throw SmokeFailure.assertion("wrong-suite session unexpectedly succeeded")
    } catch SteveError.ProtocolStatus(let message) {
        try require(
            message.contains("session creation failed with 400 Bad Request")
                && message.contains("\"error\":\"protocol_error\""),
            "wrong-suite session returned an unexpected protocol error"
        )
    }
    report("wrong-suite X25519 session was rejected without fallback")

    let failing = try createTofuForSyntheticTesting(
        config: config(.xwingDraft10),
        trustStore: FailingTrustStore()
    )
    do {
        _ = try await failing.verifyAttestation()
        throw SmokeFailure.assertion("failing TOFU callback unexpectedly succeeded")
    } catch SteveError.PcrTrustStore(let message) {
        try require(message.contains("swift trust failure sentinel"), "callback error message was lost")
    }
    report("Swift TOFU callback failure failed closed with its message")

    let _ = try createTofuForSyntheticTesting(
        config: config(.xwingDraft10),
        trustStore: MemoryTrustStore()
    )

    let store = MemoryTrustStore()
    let client = try createTofuForSyntheticTesting(
        config: config(.xwingDraft10),
        trustStore: store,
        additionalPcrIndices: Data([3])
    )
    let first = try await client.verifyAttestation()
    try requireAttestation(first, trust: .tofuEnrolled)
    report("XWING-DRAFT10 session established and Swift TOFU enrolled")
    let rotated = try await client.rotateSession()
    try requireAttestation(rotated, trust: .tofuMatched, previousSession: first.sessionId)

    let snapshot = store.snapshot()
    try require(snapshot.keys.count == 2, "TOFU callback was not called once per session")
    try require(snapshot.keys.allSatisfy { $0.count == 32 }, "TOFU key must be 32 bytes")
    try require(snapshot.keys[0] == snapshot.keys[1], "TOFU key changed across rotation")
    try require(
        snapshot.profiles.allSatisfy { $0.pcrs.map(\.index) == [0, 1, 2, 3] },
        "TOFU callback must receive PCR0/1/2 and the selected PCR3"
    )
    report("rotation matched PCR0/1/2/3 using a stable 32-byte trust key")

    let body = Data([0x00, 0x01, 0xfe, 0xff])
    let response = try await client.send(request: request(
        method: "POST",
        path: "/echo?client=swift-tofu-xwing",
        headers: [HttpHeader(name: "content-type", value: bytes("application/octet-stream"))],
        body: body
    ))
    try require(response.status == 200, "X-Wing protected echo returned a non-200 status")
    try require(response.body == body, "X-Wing protected echo changed the binary body")
    try require(response.exchange.sessionId == rotated.sessionId, "exchange reported the wrong rotated session")
    try require(response.exchange.keyExchange == .xwingDraft10, "exchange reported the wrong session KEM")
    try require(response.exchange.pcrTrust == .tofuMatched, "exchange reported the wrong TOFU result")
    report("X-Wing protected binary echo preserved the response")
    print("PASS Swift UniFFI smoke: XWING-DRAFT10 TOFU")
}

@main
struct Smoke {
    static func main() async throws {
        guard CommandLine.arguments.count == 2 else {
            throw SmokeFailure.usage
        }
        switch CommandLine.arguments[1] {
        case "pinned-x25519": try await runPinnedX25519()
        case "tofu-xwing": try await runTofuXwing()
        default: throw SmokeFailure.usage
        }
    }
}
