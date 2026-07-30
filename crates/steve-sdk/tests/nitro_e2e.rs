use std::{
    env,
    time::{Duration, Instant},
};

use serde::Deserialize;
use steve_sdk::{Client, Error, ExpectedPcrs, KeyExchangeSuite};

const FIXTURE_CONTRACT: &str = "steve-test-fixture/v1";
const MAX_ECHO_BYTES: usize = 1024 * 1024;
const MAX_DELAY_MS: u64 = 10_000;

#[derive(Debug, Deserialize, PartialEq)]
struct FixtureCapabilities {
    contract: String,
    capabilities: Vec<String>,
    max_echo_bytes: usize,
    max_delay_ms: u64,
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn decode_pcr(name: &str) -> Vec<u8> {
    let encoded = required_env(name);
    assert_eq!(
        encoded.len(),
        96,
        "{name} must contain exactly 96 hexadecimal characters"
    );
    let decoded = (0..encoded.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&encoded[offset..offset + 2], 16)
                .unwrap_or_else(|_| panic!("{name} must contain only hexadecimal characters"))
        })
        .collect::<Vec<_>>();
    assert!(
        decoded.iter().any(|byte| *byte != 0),
        "{name} must be nonzero; deploy without Caution debug mode"
    );
    decoded
}

fn expected_pcrs() -> ExpectedPcrs {
    ExpectedPcrs::from([
        (0, decode_pcr("STEVE_EXPECTED_PCR0")),
        (1, decode_pcr("STEVE_EXPECTED_PCR1")),
        (2, decode_pcr("STEVE_EXPECTED_PCR2")),
    ])
}

fn mutated_pcrs(expected: &ExpectedPcrs) -> ExpectedPcrs {
    let mut pcr0 = expected.get(&0).expect("PCR0 exists").clone();
    pcr0[0] ^= 1;
    ExpectedPcrs::from([
        (0, pcr0),
        (1, expected.get(&1).expect("PCR1 exists").clone()),
        (2, expected.get(&2).expect("PCR2 exists").clone()),
    ])
}

fn assert_expected_pcrs(actual: &ExpectedPcrs, expected: &ExpectedPcrs) {
    for index in [0, 1, 2] {
        assert_eq!(
            actual.get(&index),
            expected.get(&index),
            "PCR{index} did not match the independently verified value"
        );
    }
}

fn selected_suite() -> KeyExchangeSuite {
    match required_env("STEVE_KEY_EXCHANGE").as_str() {
        "X25519" => KeyExchangeSuite::X25519,
        "XWING-DRAFT10" => KeyExchangeSuite::XWingDraft10,
        _ => panic!("STEVE_KEY_EXCHANGE must be exactly X25519 or XWING-DRAFT10"),
    }
}

fn opposite_suite(suite: KeyExchangeSuite) -> KeyExchangeSuite {
    match suite {
        KeyExchangeSuite::X25519 => KeyExchangeSuite::XWingDraft10,
        KeyExchangeSuite::XWingDraft10 => KeyExchangeSuite::X25519,
    }
}

#[tokio::test]
#[ignore = "requires an explicit remote Nitro origin, suite, and independently verified PCRs"]
async fn remote_nitro_e2e() {
    let origin = required_env("STEVE_REMOTE_ORIGIN");
    let suite = selected_suite();
    let expected_pcrs = expected_pcrs();

    let pcr_mismatch = Client::builder(&origin, mutated_pcrs(&expected_pcrs))
        .unwrap()
        .expected_key_exchange(suite)
        .connect()
        .await;
    assert!(
        matches!(pcr_mismatch, Err(Error::AttestationVerification(_))),
        "the remote enclave did not reject a mutated PCR policy: {pcr_mismatch:?}"
    );

    let suite_mismatch = Client::builder(&origin, expected_pcrs.clone())
        .unwrap()
        .expected_key_exchange(opposite_suite(suite))
        .connect()
        .await;
    assert!(
        matches!(
            suite_mismatch,
            Err(Error::ProtocolStatus { status, .. }) if status.as_u16() == 400
        ),
        "the remote enclave did not reject the wrong key-exchange suite: {suite_mismatch:?}"
    );

    let session_started = Instant::now();
    let client = Client::builder(&origin, expected_pcrs.clone())
        .unwrap()
        .expected_key_exchange(suite)
        .request_timeout(Duration::from_secs(10))
        .connect()
        .await
        .expect("real Nitro session establishment failed");
    println!(
        "Nitro timing: session establishment completed in {:?}",
        session_started.elapsed()
    );
    let first = client.verify_attestation().await.unwrap();
    assert_expected_pcrs(&first.pcrs, &expected_pcrs);

    let fixture = client
        .get("/.well-known/steve-test-fixture")
        .send()
        .await
        .unwrap()
        .json::<FixtureCapabilities>()
        .unwrap();
    assert_eq!(
        fixture,
        FixtureCapabilities {
            contract: FIXTURE_CONTRACT.to_owned(),
            capabilities: vec![
                "echo".to_owned(),
                "unauthorized".to_owned(),
                "delay".to_owned(),
                "compressed".to_owned(),
            ],
            max_echo_bytes: MAX_ECHO_BYTES,
            max_delay_ms: MAX_DELAY_MS,
        }
    );

    let large_body = vec![b'x'; 100 * 1024];
    let large_echo_started = Instant::now();
    let echo = client
        .post("/echo")
        .header("content-type", "application/octet-stream")
        .unwrap()
        .body(large_body.clone())
        .send()
        .await
        .unwrap();
    println!(
        "Nitro timing: 100 KiB echo completed in {:?}",
        large_echo_started.elapsed()
    );
    assert_eq!(echo.status().as_u16(), 200);
    assert_eq!(echo.headers()["content-type"], "application/octet-stream");
    assert_eq!(echo.bytes(), large_body);

    let compressed = client.get("/compressed").send().await.unwrap();
    assert_eq!(compressed.status().as_u16(), 200);
    assert_eq!(compressed.bytes(), b"identity-through-steve");
    assert_eq!(
        compressed.headers()["x-upstream-accept-encoding"],
        "identity"
    );
    assert!(!compressed.headers().contains_key("content-encoding"));

    let unauthorized = client.get("/unauthorized").send().await.unwrap();
    assert_eq!(unauthorized.status().as_u16(), 401);
    assert_eq!(unauthorized.bytes(), b"application unauthorized\n");
    assert_eq!(
        client.verify_attestation().await.unwrap().session_id,
        first.session_id
    );

    let short_session_started = Instant::now();
    let timeout_client = Client::builder(&origin, expected_pcrs.clone())
        .unwrap()
        .expected_key_exchange(suite)
        .request_timeout(Duration::from_secs(3))
        .connect()
        .await
        .expect("real Nitro short-timeout session establishment failed");
    println!(
        "Nitro timing: short-timeout session establishment completed in {:?}",
        short_session_started.elapsed()
    );
    let timeout_session = timeout_client.verify_attestation().await.unwrap();
    let timeout_started = Instant::now();
    let timed_out = timeout_client.get("/delay?ms=5000").send().await;
    println!(
        "Nitro timing: controlled timeout completed in {:?}",
        timeout_started.elapsed()
    );
    assert!(
        matches!(
            timed_out,
            Err(Error::Timeout {
                operation: "protected request"
            })
        ),
        "controlled delay did not produce a request-local timeout: {timed_out:?}"
    );
    let recovery_started = Instant::now();
    let recovered = timeout_client
        .post("/echo")
        .body(b"after-timeout".to_vec())
        .send()
        .await
        .unwrap();
    println!(
        "Nitro timing: request after timeout completed in {:?}",
        recovery_started.elapsed()
    );
    assert_eq!(recovered.status().as_u16(), 200);
    assert_eq!(recovered.bytes(), b"after-timeout");
    assert_eq!(
        timeout_client
            .verify_attestation()
            .await
            .unwrap()
            .session_id,
        timeout_session.session_id
    );

    let second = client.reconnect().await.unwrap();
    assert_ne!(first.session_id, second.session_id);
    assert_expected_pcrs(&second.pcrs, &expected_pcrs);
    let rotated = client
        .post("/echo")
        .body(b"after-rotation".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(rotated.status().as_u16(), 200);
    assert_eq!(rotated.bytes(), b"after-rotation");

    println!(
        "real Nitro native SDK E2E passed: suite={suite}, module_id={}",
        second.module_id
    );
}
