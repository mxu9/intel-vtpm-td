// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec;
use der::asn1::{ObjectIdentifier, PrintableString, SetOfVec};
use der::{Any, Encodable, Tag};
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};

use crate::resolve::{
    AUTHORITY_KEY_IDENTIFIER, BASIC_CONSTRAINTS, EXTENDED_KEY_USAGE, EXTNID_VTPMTD_EVENT_LOG,
    EXTNID_VTPMTD_QUOTE, ID_EC_SIG_OID, KEY_USAGE, VTPMTD_CA_EXTENDED_KEY_USAGE,
};
use crate::x509::{self, DistinguishedName, Extension};
use crate::{
    resolve::{ResolveError, ID_EC_PUBKEY_OID, SECP384R1_OID},
    x509::{AlgorithmIdentifier, X509Error},
};

const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.17");
const TCG_TPM_MANUFACTURER: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.1");
const TCG_TPM_MODEL: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.2");
const TCG_TPM_VERSION: ObjectIdentifier = ObjectIdentifier::new("2.23.133.2.3");

pub fn generate_ca_cert(
    td_quote: &[u8],
    event_log: &[u8],
    ecdsa_keypair: &EcdsaKeyPair,
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let rand = SystemRandom::new();
        let signature = ecdsa_keypair.sign(&rand, data).unwrap();
        sig_buf.extend_from_slice(signature.as_ref());
    };

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };

    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    // extended key usage
    let eku: alloc::vec::Vec<ObjectIdentifier> = vec![VTPMTD_CA_EXTENDED_KEY_USAGE];
    let eku = eku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    // basic constrains
    let basic_constrains: alloc::vec::Vec<bool> = vec![true];
    let basic_constrains = basic_constrains
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    let x509_certificate =
        x509::CertificateBuilder::new(sig_alg, algorithm, ecdsa_keypair.public_key().as_ref())?
            // 1970-01-01T00:00:00Z
            .set_not_before(core::time::Duration::new(0, 0))?
            // 9999-12-31T23:59:59Z
            .set_not_after(core::time::Duration::new(253402300799, 0))?
            .add_extension(Extension::new(
                BASIC_CONSTRAINTS,
                Some(true),
                Some(basic_constrains.as_slice()),
            )?)?
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

pub fn generate_ek_cert(
    ek_pub: &[u8],
    ecdsa_keypair: &EcdsaKeyPair,
) -> Result<alloc::vec::Vec<u8>, ResolveError> {
    let mut sig_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
        let rand = SystemRandom::new();
        let signature = ecdsa_keypair.sign(&rand, data).unwrap();
        sig_buf.extend_from_slice(signature.as_ref());
    };

    // Generate x.509 certificate
    let algorithm = AlgorithmIdentifier {
        algorithm: ID_EC_PUBKEY_OID,
        parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
    };

    let sig_alg = AlgorithmIdentifier {
        algorithm: ID_EC_SIG_OID,
        parameters: None,
    };

    let basic_constrains: alloc::vec::Vec<bool> = vec![false];
    let basic_constrains = basic_constrains
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    let ek_pub_sha1 = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, ek_pub);
    let key_identifier: alloc::vec::Vec<u8> = ek_pub_sha1.as_ref().to_vec();

    // follow ek-credential spec Section 3.2.
    // keyAgreement (4) refers to https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    let ku: alloc::vec::Vec<u8> = vec![4_u8];
    let ku: alloc::vec::Vec<u8> = ku
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    let mut tcg_tpm_manufaturer = SetOfVec::new();
    let _ = tcg_tpm_manufaturer.add(DistinguishedName {
        attribute_type: TCG_TPM_MANUFACTURER,
        value: PrintableString::new("Intel").unwrap().into(),
    });

    let mut tcg_tpm_model = SetOfVec::new();
    let _ = tcg_tpm_model.add(DistinguishedName {
        attribute_type: TCG_TPM_MODEL,
        value: PrintableString::new("vTPM").unwrap().into(),
    });

    let mut tcg_tpm_version = SetOfVec::new();
    let _ = tcg_tpm_version.add(DistinguishedName {
        attribute_type: TCG_TPM_VERSION,
        value: PrintableString::new("00010000").unwrap().into(),
    });

    let sub_alt_name = vec![tcg_tpm_manufaturer, tcg_tpm_model, tcg_tpm_version];
    let sub_alt_name: alloc::vec::Vec<u8> = sub_alt_name
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))?;

    let x509_certificate = x509::CertificateBuilder::new(sig_alg, algorithm, ek_pub)?
        // 1970-01-01T00:00:00Z
        .set_not_before(core::time::Duration::new(0, 0))?
        // 9999-12-31T23:59:59Z
        .set_not_after(core::time::Duration::new(253402300799, 0))?
        .add_extension(Extension::new(
            BASIC_CONSTRAINTS,
            Some(true),
            Some(basic_constrains.as_slice()),
        )?)?
        .add_extension(Extension::new(
            AUTHORITY_KEY_IDENTIFIER,
            Some(false),
            Some(&key_identifier.as_slice()),
        )?)?
        .add_extension(Extension::new(KEY_USAGE, Some(true), Some(&ku))?)?
        .add_extension(Extension::new(
            SUBJECT_ALT_NAME,
            Some(false),
            Some(&sub_alt_name),
        )?)?
        .sign(&mut sig_buf, signer)?
        .build();

    x509_certificate
        .to_vec()
        .map_err(|e| ResolveError::GenerateCertificate(X509Error::DerEncoding(e)))
}
