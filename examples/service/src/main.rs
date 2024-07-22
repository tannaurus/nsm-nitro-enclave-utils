use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use nsm_nitro_enclave_utils::{
    api::{
        nsm::{Request as NsmRequest, Response as NsmResponse},
        ByteBuf,
    },
    Nsm, NsmBuilder,
};
#[cfg(feature = "dev")]
use nsm_nitro_enclave_utils::{
    api::{GetTimestamp, SecretKey},
    Pcrs,
};
use serde::Serialize;
use std::sync::Arc;
#[cfg(feature = "dev")]
use x509_cert::der::{DecodePem, Encode};
#[cfg(feature = "dev")]
use x509_cert::Certificate;

#[allow(unused)]
#[derive(Parser, Debug)]
struct Args {
    #[arg(long, allow_hyphen_values = true)]
    signing_key_pem: String,
    #[arg(long, allow_hyphen_values = true)]
    end_cert_pem: String,
    #[arg(long, allow_hyphen_values = true)]
    int_cert_pem: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    nitro: Arc<Nsm>,
}

#[tokio::main]
async fn main() {
    #[cfg(feature = "dev")]
    let args = Args::parse();
    #[cfg(feature = "dev")]
    let signing_key = SecretKey::from_sec1_pem(&args.signing_key_pem).unwrap();
    #[cfg(feature = "dev")]
    let end_cert = Certificate::from_pem(args.end_cert_pem).unwrap();
    #[cfg(feature = "dev")]
    let end_cert = ByteBuf::from(end_cert.to_der().unwrap());

    #[cfg(feature = "dev")]
    let int_certs = args
        .int_cert_pem
        .into_iter()
        .map(|pem| ByteBuf::from(Certificate::from_pem(pem).unwrap().to_der().unwrap()))
        .collect::<Vec<ByteBuf>>();

    let nitro = NsmBuilder::new();

    // Hit the phony driver when the `dev` feature is enabled
    // You can enable this while working locally, ensuring it's disabled when this service is deployed.
    #[cfg(feature = "dev")]
    let nitro = nitro
        .dev_mode(signing_key, end_cert, GetTimestamp::system_time())
        // Using `Pcrs::zeros` to get attestation documents similar to how the Nsm module will return all zeros in "debug mode"
        // https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html#run
        // `Pcrs` can be generated in another ways too, but some of them require extra feature flags not enabled in this binary.
        .pcrs(Pcrs::zeros())
        .ca_bundle(int_certs);

    let nitro = nitro.build();

    let app_state = AppState {
        nitro: Arc::new(nitro),
    };

    let app = Router::new()
        .route("/attest/:nonce", get(attest))
        .with_state(app_state);

    // Configure this to listen on vsock inside Nitro environments
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

#[derive(Serialize)]
struct AttestResponse {
    document: Vec<u8>,
}

async fn attest(State(app_state): State<AppState>, Path(nonce): Path<String>) -> Response {
    let response = app_state.nitro.process_request(NsmRequest::Attestation {
        user_data: None,
        public_key: None,
        nonce: Some(ByteBuf::from(nonce.as_bytes())),
    });

    println!("Nsm response: {:?}", response);

    if let NsmResponse::Attestation { document } = response {
        return (
            StatusCode::OK,
            serde_json::to_string(&AttestResponse { document }).unwrap(),
        )
            .into_response();
    }

    StatusCode::BAD_REQUEST.into_response()
}
