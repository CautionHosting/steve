use serde::Serialize;
use rand::TryRngCore;

#[derive(Debug, Clone, Serialize)]
struct MetadataOutput {
    public_key: Vec<u8>,
}

fn main() {
    let mut bytes = vec![0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).unwrap();
    let metadata_output = MetadataOutput {
        public_key: bytes,
    };
    let metadata_file = std::fs::File::create_new("/metadata.json").unwrap();
    serde_json::to_writer(metadata_file, &metadata_output).unwrap();

    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}
