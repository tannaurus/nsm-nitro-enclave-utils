use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use nsm_nitro_enclave_utils::{
    api::{
        nsm::{Request as NsmRequest, Response as NsmResponse},
        ByteBuf,
    },
    nsm::{Nsm, NsmBuilder},
};
#[cfg(feature = "dev")]
use nsm_nitro_enclave_utils::{
    api::{DecodePrivateKey, SecretKey},
    pcr::Pcrs,
};
use serde::Serialize;
use std::sync::Arc;

#[cfg(feature = "dev")]
#[derive(clap::Parser, Debug)]
struct Args {
    #[arg(
        long,
        allow_hyphen_values = true,
        default_value = "./test_data/end-signing-key.der"
    )]
    signing_key: std::path::PathBuf,
    #[arg(
        long,
        allow_hyphen_values = true,
        default_value = "./test_data/end-certificate.der"
    )]
    end_cert: std::path::PathBuf,
    #[arg(
        long,
        allow_hyphen_values = true,
        default_value = "./test_data/int-certificate.der"
    )]
    int_cert: Vec<std::path::PathBuf>,
}

#[derive(Clone)]
struct AppState {
    nitro: Arc<Nsm>,
}

#[tokio::main]
async fn main() {
    let nitro = NsmBuilder::new();

    // Hit the dev driver when the `dev` feature is enabled
    // You can enable this while working locally, ensuring it's disabled when this service is deployed.
    #[cfg(feature = "dev")]
    let nitro = {
        use clap::Parser;
        let args = Args::parse();

        let int_certs = args
            .int_cert
            .into_iter()
            .map(|path| {
                let der = std::fs::read(&path).unwrap();
                ByteBuf::from(der)
            })
            .collect::<Vec<ByteBuf>>();

        let end_cert = {
            let der = std::fs::read(&args.end_cert).unwrap();
            ByteBuf::from(der)
        };

        let signing_key = {
            let der = std::fs::read(&args.signing_key).unwrap();
            SecretKey::from_pkcs8_der(&der).unwrap()
        };

        nitro
            .dev_mode(signing_key, end_cert)
            // Using `Pcrs::zeros` to get attestation documents similar to how the Nsm module will return all zeros in "debug mode"
            // https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html#run
            // `Pcrs` can be generated in another ways too, but some of them require extra feature flags not enabled in this binary.
            .pcrs(Pcrs::zeros())
            .ca_bundle(int_certs)
    };

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

async fn attest(State(app_state): State<AppState>, Path(nonce): Path<ByteBuf>) -> Response {
    let response = app_state.nitro.process_request(NsmRequest::Attestation {
        user_data: None,
        public_key: None,
        nonce: Some(nonce),
    });

    if let NsmResponse::Attestation { document } = response {
        return (
            StatusCode::OK,
            serde_json::to_string(&AttestResponse { document }).unwrap(),
        )
            .into_response();
    }

    StatusCode::BAD_REQUEST.into_response()
}
