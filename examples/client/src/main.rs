use clap::Parser;
use nsm_nitro_enclave_utils::api::nsm::AttestationDoc;
use nsm_nitro_enclave_utils::{AttestationDocVerifierExt, GetTimestamp};
use reqwest::StatusCode;
use serde::Deserialize;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    nonce: String,
    #[arg(long, allow_hyphen_values = true)]
    root_cert_pem: String,
}

#[derive(Deserialize)]
struct AttestResponse {
    document: Vec<u8>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let root_cert = Certificate::from_pem(args.root_cert_pem)
        .unwrap()
        .to_der()
        .unwrap();

    let response = reqwest::get(format!("http://127.0.0.1:3000/attest/{}", args.nonce))
        .await
        .unwrap();

    if response.status() != StatusCode::OK {
        eprintln!("Received bad response: {}", response.status());
    }

    let text = response.text().await.unwrap();
    let response: AttestResponse = serde_json::from_str(text.as_ref()).unwrap();

    let doc = AttestationDoc::from_cose(
        &response.document,
        &root_cert,
        GetTimestamp::default(),
    )
    .unwrap();

    println!("Success! {:?}", doc);
}
