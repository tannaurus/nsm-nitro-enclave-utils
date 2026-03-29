use assert_cmd::Command;
use tempfile::TempDir;
use time::{macros::format_description, OffsetDateTime};

fn nsm_keygen() -> Command {
    Command::cargo_bin("nsm-keygen").unwrap()
}

fn date_from_now(days: i64) -> String {
    let dt = OffsetDateTime::now_utc() + time::Duration::days(days);
    dt.format(format_description!("[year]-[month]-[day]"))
        .unwrap()
}

// ── generate ─────────────────────────────────────────────────────────────────

#[test]
fn generate_creates_pem_files() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args(["generate", "--dir", dir.path().to_str().unwrap()])
        .assert()
        .success();

    for name in [
        "root-certificate.pem",
        "int-certificate.pem",
        "end-certificate.pem",
        "end-signing-key.pem",
    ] {
        assert!(dir.path().join(name).exists(), "{name} not found");
    }
}

#[test]
fn generate_creates_der_files() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args([
            "generate",
            "--format",
            "der",
            "--dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    for name in [
        "root-certificate.der",
        "int-certificate.der",
        "end-certificate.der",
        "end-signing-key.der",
    ] {
        assert!(dir.path().join(name).exists(), "{name} not found");
    }
}

#[test]
fn generate_stdout_is_valid_json() {
    let output = nsm_keygen()
        .arg("generate")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("stdout should be valid JSON");
    for key in [
        "rootCertificate",
        "intCertificate",
        "endCertificate",
        "endSigningKey",
    ] {
        assert!(json.get(key).is_some(), "missing key: {key}");
    }
}

#[test]
fn generate_respects_days_flag() {
    let dir = TempDir::new().unwrap();
    // 30-day certs should pass a check against tomorrow but fail against 2 years from now
    nsm_keygen()
        .args([
            "generate",
            "--days",
            "30",
            "--dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    nsm_keygen()
        .args([
            "check",
            "--dir",
            dir.path().to_str().unwrap(),
            "--expires-after",
            &date_from_now(1),
        ])
        .assert()
        .success();

    nsm_keygen()
        .args([
            "check",
            "--dir",
            dir.path().to_str().unwrap(),
            "--expires-after",
            &date_from_now(730),
        ])
        .assert()
        .failure();
}

// ── check ─────────────────────────────────────────────────────────────────────

#[test]
fn check_passes_with_valid_certs() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args(["generate", "--dir", dir.path().to_str().unwrap()])
        .assert()
        .success();

    nsm_keygen()
        .args(["check", "--dir", dir.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn check_expires_after_near_future_passes() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args([
            "generate",
            "--days",
            "365",
            "--dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    nsm_keygen()
        .args([
            "check",
            "--dir",
            dir.path().to_str().unwrap(),
            "--expires-after",
            &date_from_now(30),
        ])
        .assert()
        .success();
}

#[test]
fn check_expires_after_beyond_expiry_fails() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args([
            "generate",
            "--days",
            "30",
            "--dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    nsm_keygen()
        .args([
            "check",
            "--dir",
            dir.path().to_str().unwrap(),
            "--expires-after",
            &date_from_now(60),
        ])
        .assert()
        .failure();
}

#[test]
fn check_fails_with_invalid_date() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args(["generate", "--dir", dir.path().to_str().unwrap()])
        .assert()
        .success();

    nsm_keygen()
        .args([
            "check",
            "--dir",
            dir.path().to_str().unwrap(),
            "--expires-after",
            "not-a-date",
        ])
        .assert()
        .failure();
}

#[test]
fn check_fails_with_missing_cert_files() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args(["check", "--dir", dir.path().to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn check_der_format() {
    let dir = TempDir::new().unwrap();
    nsm_keygen()
        .args([
            "generate",
            "--format",
            "der",
            "--dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    nsm_keygen()
        .args([
            "check",
            "--format",
            "der",
            "--dir",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}
