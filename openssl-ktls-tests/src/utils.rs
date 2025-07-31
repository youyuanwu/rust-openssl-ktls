use openssl::ssl::{SslConnector, SslVersion};

pub const HELLO: &str = "hello";

pub mod ssl_gen {
    //! A program that generates ca certs, certs verified by the ca, and public
    //! and private keys.

    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::error::ErrorStack;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        BasicConstraints, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509, X509NameBuilder};

    /// Make a self signed certificate and private key using openssl
    pub fn mk_self_signed_cert(
        subject_alt_names: Vec<String>,
    ) -> Result<(X509, PKey<Private>), ErrorStack> {
        let rsa = Rsa::generate(2048)?;
        let key_pair = PKey::from_rsa(rsa)?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "US")?;
        x509_name.append_entry_by_text("ST", "TX")?;
        x509_name.append_entry_by_text("O", "Some CA organization")?;
        x509_name.append_entry_by_text("CN", "self test")?;
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(&x509_name)?;
        cert_builder.set_pubkey(&key_pair)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().build()?)?; // not ca
        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;

        // add dns
        let mut subject_alt_name_ex = SubjectAlternativeName::new();
        for name in subject_alt_names {
            subject_alt_name_ex.dns(name.as_str());
        }
        let subject_alt_name_ex =
            subject_alt_name_ex.build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_alt_name_ex)?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        cert_builder.sign(&key_pair, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, key_pair))
    }
}

pub fn create_openssl_acceptor_builder(
    cert: &openssl::x509::X509,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> openssl::ssl::SslAcceptorBuilder {
    let mut acceptor =
        openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()).unwrap();
    acceptor.set_private_key(key).unwrap();
    acceptor.set_certificate(cert).unwrap();
    acceptor.cert_store_mut().add_cert(cert.clone()).unwrap();
    acceptor.check_private_key().unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    // require client to present cert with matching subject name.
    acceptor.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |ok, ctx| {
        if !ok {
            let e = ctx.error();
            println!("verify failed : {e}");
        }
        ok
    });
    acceptor
}

pub fn create_openssl_connector(cert: &openssl::x509::X509) -> SslConnector {
    let mut connector =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
    connector.cert_store_mut().add_cert(cert.clone()).unwrap();
    connector.add_client_ca(cert).unwrap();
    connector.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |ok, ctx| {
        if !ok {
            let e = ctx.error();
            println!("verify failed : {e}");
        }
        ok
    });
    // connector
    //     .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
    //     .unwrap();
    connector
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    connector.build()
}

pub fn create_openssl_connector_with_ktls(cert: &openssl::x509::X509) -> SslConnector {
    let mut connector =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();

    use openssl_ktls::kbio::ffi::SSL_OP_ENABLE_KTLS;
    unsafe {
        openssl_sys::SSL_CTX_set_options(connector.as_ptr(), SSL_OP_ENABLE_KTLS);
        // Use TLS 1.2 with KTLS-compatible cipher suite
        let cipher_list = std::ffi::CString::new("ECDHE-RSA-AES128-GCM-SHA256").unwrap();
        openssl_sys::SSL_CTX_set_cipher_list(connector.as_ptr(), cipher_list.as_ptr());
    }

    connector.cert_store_mut().add_cert(cert.clone()).unwrap();
    connector.add_client_ca(cert).unwrap();
    connector.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |ok, ctx| {
        if !ok {
            let e = ctx.error();
            println!("verify failed : {e}");
        }
        ok
    });
    connector
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    connector.build()
}
