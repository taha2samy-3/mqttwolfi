use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Loads X.509 certificates from a PEM file.
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Loads a private key from a PEM file (supporting PKCS#8 or RSA).
pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("No private key found in {}", path),
                ))
            }
            _ => {}
        }
    }
}

/// Creates a TLS Acceptor for the MQTT server with optional mTLS client certificate verification.
pub fn create_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    ca_cert_path: Option<&str>,
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let server_config = if let Some(ca_path) = ca_cert_path {
        // Strict Mutual TLS (mTLS) configuration
        let ca_certs = load_certs(ca_path)?;
        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)?;
        }

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;
        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)?
    } else {
        // Standard one-way TLS
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };

    let mut config = server_config;
    config.alpn_protocols = vec![b"mqtt".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Creates a TLS Connector for MQTT clients/benchmarks.
pub fn create_tls_connector(
    ca_cert_path: &str,
    client_cert_and_key: Option<(&str, &str)>,
) -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    let ca_certs = load_certs(ca_cert_path)?;
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let client_config = if let Some((cert_path, key_path)) = client_cert_and_key {
        let client_certs = load_certs(cert_path)?;
        let client_key = load_private_key(key_path)?;
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)?
    } else {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let mut config = client_config;
    config.alpn_protocols = vec![b"mqtt".to_vec()];

    Ok(TlsConnector::from(Arc::new(config)))
}
