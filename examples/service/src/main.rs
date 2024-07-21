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
        ByteBuf, GetTimestamp, SecretKey,
    },
    Nsm, NsmBuilder, Pcrs,
};
use std::sync::Arc;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, allow_hyphen_values = true)]
    signing_key_pem: String,
    #[arg(long, allow_hyphen_values = true)]
    end_cert_pem: String,
}

#[derive(Clone)]
struct AppState {
    nitro: Arc<Nsm>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let signing_key = SecretKey::from_sec1_pem(&args.signing_key_pem).unwrap();

    let end_cert = Certificate::from_pem(args.end_cert_pem).unwrap();
    let end_cert = ByteBuf::from(end_cert.to_der().unwrap());

    let nitro = NsmBuilder::new()
        .dev_mode(signing_key, end_cert, GetTimestamp::system_time())
        .pcrs(Pcrs::zeros())
        .build();
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

async fn attest(State(app_state): State<AppState>, Path(nonce): Path<String>) -> Response {
    let response = app_state.nitro.process_request(NsmRequest::Attestation {
        user_data: None,
        public_key: None,
        nonce: Some(ByteBuf::from(nonce.as_bytes())),
    });

    if let NsmResponse::Attestation { document } = response {
        return (StatusCode::OK, document).into_response();
    }

    StatusCode::BAD_REQUEST.into_response()
}
