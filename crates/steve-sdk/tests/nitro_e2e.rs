use std::env;

use steve_sdk::{Client, Error, ExpectedPcrs, KeyExchangeSuite};

const DEFAULT_PATH: &str = "/index.html";
const DEFAULT_BODY: &str = "xwing demo app\n";

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
    (0..encoded.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&encoded[offset..offset + 2], 16)
                .unwrap_or_else(|_| panic!("{name} must contain only hexadecimal characters"))
        })
        .collect()
}

fn expected_pcrs() -> ExpectedPcrs {
    ExpectedPcrs::from([
        (0, decode_pcr("STEVE_EXPECTED_PCR0")),
        (1, decode_pcr("STEVE_EXPECTED_PCR1")),
        (2, decode_pcr("STEVE_EXPECTED_PCR2")),
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

    let result = Client::builder(&origin, expected_pcrs.clone())
        .unwrap()
        .expected_key_exchange(suite)
        .connect()
        .await;

    if env::var("STEVE_REMOTE_EXPECT_PCR_MISMATCH").as_deref() == Ok("1") {
        assert!(
            matches!(result, Err(Error::AttestationVerification(_))),
            "the remote enclave did not fail closed on the intentionally wrong PCR policy: {result:?}"
        );
        println!("real Nitro attestation rejected the intentionally wrong PCR policy");
        return;
    }

    let client = result.expect("real Nitro session establishment failed");
    let first = client.verify_attestation().await.unwrap();
    assert_expected_pcrs(&first.pcrs, &expected_pcrs);

    let mismatch = Client::builder(&origin, expected_pcrs.clone())
        .unwrap()
        .expected_key_exchange(opposite_suite(suite))
        .connect()
        .await;
    assert!(
        matches!(
            mismatch,
            Err(Error::ProtocolStatus { status, .. }) if status.as_u16() == 400
        ),
        "the remote enclave did not reject the wrong key-exchange suite: {mismatch:?}"
    );

    let path = env::var("STEVE_REMOTE_PATH").unwrap_or_else(|_| DEFAULT_PATH.to_owned());
    let expected_body =
        env::var("STEVE_REMOTE_EXPECTED_BODY").unwrap_or_else(|_| DEFAULT_BODY.to_owned());

    let response = client.get(&path).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.bytes(), expected_body.as_bytes());

    let second = client.reconnect().await.unwrap();
    assert_ne!(first.session_id, second.session_id);
    assert_expected_pcrs(&second.pcrs, &expected_pcrs);

    let response = client.get(path).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.bytes(), expected_body.as_bytes());

    println!(
        "real Nitro native SDK E2E passed: suite={suite}, module_id={}",
        second.module_id
    );
}
