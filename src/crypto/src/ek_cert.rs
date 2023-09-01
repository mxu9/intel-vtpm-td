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

fn generate_td_quote(public_key: &[u8]) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let public_key_hash = digest::digest(&digest::SHA384, public_key);

    // Generate the TD Report that contains the public key hash as nonce
    let mut td_report_data = [0u8; 64];
    td_report_data[..public_key_hash.as_ref().len()].copy_from_slice(public_key_hash.as_ref());
    let td_report = tdx_tdcall::tdreport::tdcall_report(&td_report_data)
        .map_err(|_| ResolveError::GetTdQuote)?;
    Ok(td_report.as_bytes().to_vec())
}

pub fn generate_ek_cert (ek_pub: &[u8]) -> Result<alloc::vec::Vec<u8>, ResolveError> {

    let mut pkcs8 = generate_ecdsa_keypairs().expect("Failed to generate ecdsa keypair.\n");
    let mut key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8.as_ref(),
    );

    if key_pair.is_err() {
        return Err(ResolveError::GetTdQuote);
    }
    let mut key_pair = key_pair.unwrap();

    // TODO get event_log
    let event_log: [u8; 256] = [0; 256];

    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let rand = SystemRandom::new();
        let signature = key_pair.sign(&rand, data).unwrap();
        sig_buf.extend_from_slice(signature.as_ref());
    };

    // generate td_quote
    let td_quote = generate_td_quote(ek_pub)?;

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
                Some(td_quote.as_slice()),
            )?)?
            .add_extension(Extension::new(
                EXTNID_VTPMTD_EVENT_LOG,
                Some(false),
                Some(&event_log),
            )?)?
            .sign(&mut sig_buf, signer)?
            .build();

    x509_certificate
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}