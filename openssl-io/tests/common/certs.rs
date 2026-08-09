//! Test fixtures shared between the engine's unit tests (via `#[path]`
//! include) and the integration tests under `tests/`.
//!
//! Certificates are generated in memory per test, following the existing
//! convention in `openssl-ktls-tests`: nothing is written to disk and no
//! fixture files are tracked.

#![allow(dead_code)]

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVerifyMode};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};

/// Generate a self-signed certificate valid for `localhost`.
pub fn self_signed() -> (X509, PKey<Private>) {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();

    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    let serial = {
        let mut s = BigNum::new().unwrap();
        s.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        s.to_asn1_integer().unwrap()
    };
    b.set_serial_number(&serial).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    b.append_extension(BasicConstraints::new().build().unwrap())
        .unwrap();
    b.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .unwrap(),
    )
    .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();

    (b.build(), key)
}

/// A client context trusting `cert`, or trusting nothing when `cert` is `None`.
pub fn client_ctx(cert: Option<&X509>) -> SslContext {
    let mut b = SslContextBuilder::new(SslMethod::tls_client()).unwrap();
    if let Some(c) = cert {
        b.cert_store_mut().add_cert(c.clone()).unwrap();
    }
    b.set_verify(SslVerifyMode::PEER);
    b.build()
}

/// A server context presenting `cert`/`key`.
pub fn server_ctx(cert: &X509, key: &PKey<Private>) -> SslContext {
    let mut b = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
    b.set_certificate(cert).unwrap();
    b.set_private_key(key).unwrap();
    b.build()
}

/// A client/server `Ssl` pair that will complete a handshake successfully.
pub fn engine_ssl_pair() -> (Ssl, Ssl) {
    let (cert, key) = self_signed();
    let c = client_ctx(Some(&cert));
    let s = server_ctx(&cert, &key);
    (Ssl::new(&c).unwrap(), Ssl::new(&s).unwrap())
}

/// A pair whose client does not trust the server's certificate, so the
/// handshake must fail verification.
pub fn untrusted_ssl_pair() -> (Ssl, Ssl) {
    let (cert, key) = self_signed();
    // The client trusts nothing relevant, so the server's cert cannot chain.
    let c = client_ctx(None);
    let s = server_ctx(&cert, &key);
    (Ssl::new(&c).unwrap(), Ssl::new(&s).unwrap())
}
