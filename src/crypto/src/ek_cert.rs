// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec;
use der::{Any, Tag, Encodable};
use der::asn1::ObjectIdentifier;
use ring::signature::KeyPair;
use ring::{rand::SystemRandom, digest};

use crate::resolve::{EXTENDED_KEY_USAGE, EXTNID_VTPMTD_QUOTE, EXTNID_VTPMTD_EVENT_LOG};
use crate::x509::{self, Extension};
use crate::{resolve::{generate_ecdsa_keypairs, ResolveError, ID_EC_PUBKEY_OID, SECP384R1_OID, VTPMTD_EXTENDED_KEY_USAGE}, x509::{AlgorithmIdentifier, X509Error}};

pub fn generate_ek_cert (td_quote: &[u8], event_log: &[u8]) -> Result<alloc::vec::Vec<u8>, ResolveError> {

    log::info!(">>td_quote = {0:#x} bytes, event_log = {1:#x} bytes\n", td_quote.len(), event_log.len());

    let mut pkcs8 = generate_ecdsa_keypairs().expect("Failed to generate ecdsa keypair.\n");
    let mut key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8.as_ref(),
    );

    if key_pair.is_err() {
        return Err(ResolveError::GetTdQuote);
    }
    let mut key_pair = key_pair.unwrap();

    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let rand = SystemRandom::new();
        let signature = key_pair.sign(&rand, data).unwrap();
        sig_buf.extend_from_slice(signature.as_ref());
    };

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };
    let eku: alloc::vec::Vec<ObjectIdentifier> = vec![VTPMTD_EXTENDED_KEY_USAGE];
    let eku = eku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;
    let x509_certificate =
        x509::CertificateBuilder::new(algorithm, algorithm, key_pair.public_key().as_ref())?
            // 1970-01-01T00:00:00Z
            .set_not_before(core::time::Duration::new(0, 0))?
            // 9999-12-31T23:59:59Z
            .set_not_after(core::time::Duration::new(253402300799, 0))?
            .add_extension(Extension::new(
                EXTENDED_KEY_USAGE,
                Some(false),
                Some(eku.as_slice()),
            )?)?
            .add_extension(Extension::new(
                EXTNID_VTPMTD_QUOTE,
                Some(false),
                Some(td_quote),
            )?)?
            .add_extension(Extension::new(
                EXTNID_VTPMTD_EVENT_LOG,
                Some(false),
                Some(event_log),
            )?)?
            .sign(&mut sig_buf, signer)?
            .build();

    x509_certificate
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}