//! `vault-web` flags, through the public `args` API.

use std::path::Path;

use clap::{CommandFactory, Parser};
use vault_web::args::Args;
use vault_web::tls::CertSource;

const DATA_DIR: &str = "/data/secure-pass-manager";

/// Parses `vault-web` followed by `flags`.
///
/// ```text
/// let args = parse(&["--bind", "127.0.0.1:9443"]).unwrap();
/// ```
fn parse(flags: &[&str]) -> Result<Args, clap::Error> {
    Args::try_parse_from(std::iter::once("vault-web").chain(flags.iter().copied()))
}

#[test]
fn defaults_listen_on_localhost_8443_with_web_vaults_and_a_self_signed_certificate() {
    let args = parse(&[]).unwrap();
    assert_eq!(args.bind, "127.0.0.1:8443".parse().unwrap());
    let data = Path::new(DATA_DIR);
    assert_eq!(args.vault_dir(Some(data)).unwrap(), data.join("web-vaults"));
    assert_eq!(
        args.cert_source(Some(data)).unwrap(),
        CertSource::SelfSigned {
            cache_dir: data.join("web-tls")
        }
    );
}

#[test]
fn without_a_data_directory_paths_must_be_given() {
    let args = parse(&[]).unwrap();
    assert_eq!(args.vault_dir(None), None);
    assert_eq!(args.cert_source(None), None);

    let args = parse(&[
        "--vault-dir",
        "/v",
        "--tls-cert",
        "c.pem",
        "--tls-key",
        "k.pem",
    ])
    .unwrap();
    assert_eq!(args.vault_dir(None).unwrap(), Path::new("/v"));
    assert_eq!(
        args.cert_source(None).unwrap(),
        CertSource::Files {
            cert: "c.pem".into(),
            key: "k.pem".into()
        }
    );
}

#[test]
fn tls_cert_and_key_come_together_or_not_at_all() {
    assert!(parse(&["--tls-cert", "c.pem"]).is_err());
    assert!(parse(&["--tls-key", "k.pem"]).is_err());
}

#[test]
fn bind_must_be_an_address_with_a_port() {
    assert!(parse(&["--bind", "localhost"]).is_err());
    assert_eq!(
        parse(&["--bind", "127.0.0.1:9443"]).unwrap().bind.port(),
        9443
    );
}

#[test]
fn help_shows_the_plain_summary_without_doc_examples() {
    let help = Args::command().render_long_help().to_string();
    assert!(
        help.contains("HTTPS server for the password manager's browser client"),
        "{help}"
    );
    assert!(!help.contains("```") && !help.contains("assert"), "{help}");
}
