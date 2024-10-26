use clap::{Parser, ValueEnum};
use nsm_nitro_enclave_utils_keygen::{
    encode::der::DerNsmCertChain, encode::pem::PemNsmCertChain, NsmCertChain,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Clone, Debug)]
#[command(version, about)]
struct Args {
    #[arg(
        short,
        long,
        default_value = "pem",
        help = "The desired output format."
    )]
    format: Format,
    #[arg(
        long,
        default_value = "365",
        help = "The amount of days the generated certificates will be valid for."
    )]
    days: u64,
    #[arg(
        long,
        help = "The directory where the generated certificates will be written to. If omitted, the generated certificates will be sent to stdout."
    )]
    dir: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Debug)]
enum Format {
    Pem,
    Der,
}

impl Format {
    fn as_file_extension(&self) -> &'static str {
        match self {
            Format::Pem => "pem",
            Format::Der => "der",
        }
    }
}

fn main() {
    let args = Args::parse();

    let duration = Duration::from_secs(60 * 60 * 24 * args.days);
    let cert_chain = NsmCertChain::generate(duration);

    let json = match args.format {
        Format::Pem => {
            serde_json::to_value(&PemNsmCertChain(cert_chain)).expect("Failed to serialize")
        }
        Format::Der => {
            serde_json::to_value(&DerNsmCertChain(cert_chain)).expect("Failed to serialize")
        }
    };

    if let Some(mut path) = args.dir {
        let file_extension = args.format.as_file_extension();

        // Push the first filename, use `set_file_name` for everything else.
        path.push(format!("root-certificate.{file_extension}"));
        let root: Vec<u8> = serde_json::from_value(json["rootCertificate"].to_owned())
            .expect("Invalid certificate");
        fs::write(path.clone(), root).expect("Failed to write root certificate");

        path.set_file_name(format!("int-certificate.{file_extension}"));
        let int: Vec<u8> =
            serde_json::from_value(json["intCertificate"].to_owned()).expect("Invalid certificate");
        fs::write(path.clone(), int).expect("Failed to write int certificate");

        path.set_file_name(format!("end-certificate.{file_extension}"));
        let end_certificate: Vec<u8> =
            serde_json::from_value(json["endCertificate"].to_owned()).expect("Invalid certificate");
        fs::write(path.clone(), end_certificate).expect("Failed to write end certificate");

        path.set_file_name(format!("end-signing-key.{file_extension}"));
        let end_signing_key: Vec<u8> =
            serde_json::from_value(json["endSigningKey"].to_owned()).expect("Invalid certificate");
        fs::write(path, end_signing_key).expect("Failed to write end signing key");

        return;
    }

    println!("{json}");
}
