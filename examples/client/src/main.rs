use std::path::PathBuf;

use clap::Parser;
use nsm_nitro_enclave_utils::{
    api::{nsm::AttestationDoc, ByteBuf},
    time::Time,
    verify::AttestationDocVerifierExt,
};
use reqwest::StatusCode;
use serde::Deserialize;

#[derive(Parser, Debug)]
struct Args {
    #[arg(
        long,
        allow_hyphen_values = true,
        default_value = "./test_data/root-certificate.der"
    )]
    root_cert: PathBuf,
}

#[derive(Deserialize)]
struct AttestResponse {
    document: Vec<u8>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let root_cert = std::fs::read(&args.root_cert).unwrap();

    let nonce = hex::encode(ByteBuf::from([0u8; 32]).as_ref());

    let response = reqwest::get(format!("http://127.0.0.1:3000/attest/{}", nonce))
        .await
        .unwrap();

    if response.status() != StatusCode::OK {
        eprintln!("Received bad response: {}", response.status());
        return;
    }

    let response_body = response.text().await.unwrap();
    let response: AttestResponse = serde_json::from_str(response_body.as_ref()).unwrap();

    let doc = AttestationDoc::from_cose(&response.document, &root_cert, Time::default()).unwrap();

    // Ensure our nonce made it into our document and convert to a string so we can compare it to our hex string
    let Some(doc_nonce) = doc
        .nonce
        .clone()
        .map(|nonce| String::from_utf8(nonce.to_vec()).unwrap())
    else {
        eprintln!("Document nonce is missing!");
        return;
    };

    if nonce != doc_nonce {
        eprintln!("Nonce mismatch! Expected {}, received {}", nonce, doc_nonce);
        return;
    }

    println!("Success! {:?}", doc);
}
