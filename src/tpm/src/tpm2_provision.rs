// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

// use core::slice::SlicePattern;

use crypto::ek_cert::generate_ek_cert;
use global::{VtpmResult, VtpmError};
use crate::{execute_command, tpm2_cmd_rsp::{startup::tpm2_startup, command::Tpm2CommandHeader, TPM_ST_SESSIONS, TPM2_CC_CREATEPRIMARY, shutdown::tpm2_shutdown, TPM2_COMMAND_HEADER_SIZE, TPM2_CC_NV_DEFINESPACE, TPM2_CC_NV_WRITE}, tpm2_sys::_plat__TPMT_PUBLIC_Size};
use alloc::{vec::Vec, slice};

const TPM2_EK_RSA_HANDLE: u32 = 0x81010001;
const TPM2_ALG_AES: u16 = 0x0006;
const TPM2_ALG_CFB: u16 = 0x0043;
const TPM2_RS_PW: u32 = 0x40000009;
const TPM2_ALG_RSA: u16 = 0x0001;
const TPM2_ALG_SHA256: u16 = 0x000b;
const TPM2_ALG_NULL: u16 = 0x0010;
const TPM2_RH_ENDORSEMENT: u32 = 0x4000000b;
const TPM2_RH_PLATFORM: u32 = 0x4000000c;
const TPM2_AUTHBLOCK_SIZE: usize = 9;

const TPMA_NV_PLATFORMCREATE: u32 = 0x40000000;
const TPMA_NV_AUTHREAD: u32 = 0x40000;
const TPMA_NV_NO_DA: u32 = 0x2000000;
const TPMA_NV_PPWRITE: u32 = 0x1;
const TPMA_NV_PPREAD: u32 = 0x10000;
const TPMA_NV_OWNERREAD: u32 = 0x20000;
const TPMA_NV_WRITEDEFINE: u32 = 0x2000;

const TPM2_NV_INDEX_RSA2048_EKCERT: u32 = 0x01c00002;
const TPM2_NV_INDEX_RSA2048_EKTEMPLATE: u32 = 0x01c00004;
const TPM2_NV_INDEX_RSA3072_HI_EKCERT: u32 = 0x01c0001c;
const TPM2_NV_INDEX_RSA3072_HI_EKTEMPLATE: u32 = 0x01c0001d;
// For ECC follow "TCG EK Credential Profile For TPM Family 2.0; Level 0"
// Specification Version 2.1; Revision 13; 10 December 2018
const TPM2_NV_INDEX_PLATFORMCERT: u32 = 0x01c08000;

const TPM2_NV_INDEX_ECC_SECP384R1_HI_EKCERT: u32 = 0x01c00016;
const TPM2_NV_INDEX_ECC_SECP384R1_HI_EKTEMPLATE: u32 = 0x01c00017;

struct tpm2_authblock {
    pub auth: u32,
    pub foo: u16,
    pub continue_session: u8,
    pub bar: u16,
}

impl tpm2_authblock {
    fn new(auth: u32, foo: u16, continue_session: u8, bar: u16) -> Self {
        Self {
            auth: auth,
            foo: foo.to_be(),
            bar: bar.to_be(),
            continue_session: continue_session,
        }
    }

    pub fn to_bytes(&self, out_buffer: &mut [u8]) -> Option<usize> {
        if out_buffer.len() < TPM2_AUTHBLOCK_SIZE {
            log::error!("Invalid size({:?}) of input buffer\n", out_buffer.len());
            return None;
        }

        let auth = self.auth.to_be_bytes();
        let foo = self.foo.to_be_bytes();
        let continue_session = self.continue_session.to_be_bytes();
        let bar = self.bar.to_be_bytes();

        out_buffer[..4].copy_from_slice(&auth);
        out_buffer[4..6].copy_from_slice(&foo);
        out_buffer[6] = self.continue_session;
        out_buffer[7..TPM2_AUTHBLOCK_SIZE].copy_from_slice(&bar);

        Some(TPM2_AUTHBLOCK_SIZE)
    }

    // fn as_slice(&self) -> &[u8] {
    //     unsafe {
    //         slice::from_raw_parts(
    //             self as *const tpm2_authblock as *const u8,
    //             core::mem::size_of::<tpm2_authblock>(),
    //         )
    //     }
    // }
    fn size() -> u32 {
        TPM2_AUTHBLOCK_SIZE as u32
    }

}

const TPM2_EVICTCONTROL_REQ_SIZE: usize = TPM2_COMMAND_HEADER_SIZE + 4 + 4 + 4 + TPM2_AUTHBLOCK_SIZE + 4;

struct tpm2_evictcontrol_req {
    pub hdr: Tpm2CommandHeader,
    pub auth: u32,
    pub obj_handle: u32,
    pub authblk_len: u32,
    pub authblock: tpm2_authblock,
    persistent_handle: u32,
}

impl tpm2_evictcontrol_req {
    fn new(
        hdr: Tpm2CommandHeader,
        auth: u32,
        obj_handle: u32,
        authblk_len: u32,
        authblock: tpm2_authblock,
        persistent_handle: u32,
    ) -> Self {
        tpm2_evictcontrol_req {
            hdr,
            auth,
            obj_handle,
            authblk_len,
            authblock,
            persistent_handle,
        }
    }

    pub fn to_bytes(&self, out_buffer: &mut [u8]) -> Option<usize> {
        if out_buffer.len() < TPM2_EVICTCONTROL_REQ_SIZE {
            log::error!("Invalid size({:?}) of input buffer\n", out_buffer.len());
            return None;
        }

        let mut hdr_buf: [u8; TPM2_COMMAND_HEADER_SIZE] = [0; TPM2_COMMAND_HEADER_SIZE];
        self.hdr.to_bytes(&mut hdr_buf);
        let auth_buf = self.auth.to_be_bytes();
        let obj_handle_buf = self.obj_handle.to_be_bytes();
        let authblk_len_buf = self.authblk_len.to_be_bytes();
        let mut authblock_buf: [u8; TPM2_AUTHBLOCK_SIZE] = [0; TPM2_AUTHBLOCK_SIZE];
        self.authblock.to_bytes(&mut authblock_buf);
        let persistent_handle_buf = self.persistent_handle.to_be_bytes();

        out_buffer[..TPM2_COMMAND_HEADER_SIZE].copy_from_slice(&hdr_buf);

        let mut offset: usize = TPM2_COMMAND_HEADER_SIZE;
        out_buffer[offset..offset+4].copy_from_slice(&auth_buf);

        offset += 4;
        out_buffer[offset..offset+4].copy_from_slice(&obj_handle_buf);

        offset += 4;
        out_buffer[offset..offset+4].copy_from_slice(&authblk_len_buf);

        offset += 4;
        out_buffer[offset..offset+TPM2_AUTHBLOCK_SIZE].copy_from_slice(&authblock_buf);

        offset += TPM2_AUTHBLOCK_SIZE;
        out_buffer[offset..offset+4].copy_from_slice(&persistent_handle_buf);

        assert!(offset + 4 == TPM2_EVICTCONTROL_REQ_SIZE);
        
        Some(TPM2_EVICTCONTROL_REQ_SIZE)
    }

    fn size() -> u32 {
        // core::mem::size_of::<Self>() as u32
        TPM2_EVICTCONTROL_REQ_SIZE as u32
    }    
}

fn tpm2_create_ek () -> VtpmResult {
    let create_primary_req: [u8; 0xb3] = [
        0x80, 0x02, 0x00, 0x00, 0x00, 0xb3, 0x00, 0x00, 0x01, 0x31, 0x40, 0x00, 0x00, 0x0b, 0x00, 0x00,
        0x00, 0x49, 0x02, 0x00, 0x00, 0x01, 0x00, 0x20, 0x69, 0xd6, 0x3a, 0xd4, 0x05, 0xfc, 0x74, 0x0b,
        0xdf, 0x24, 0x6c, 0x31, 0xe9, 0x25, 0xda, 0x19, 0x5d, 0x39, 0x81, 0x25, 0x1e, 0x12, 0xaa, 0x81,
        0x58, 0x69, 0x29, 0x33, 0x88, 0x5f, 0x58, 0xee, 0x01, 0x00, 0x20, 0x06, 0x98, 0xdf, 0xd9, 0xea,
        0x84, 0x31, 0xaf, 0xdc, 0x26, 0xe6, 0xc5, 0x7a, 0x6a, 0x0c, 0x47, 0xb8, 0x31, 0xe1, 0x6a, 0x76,
        0x5d, 0x44, 0x32, 0x79, 0x8d, 0x42, 0xaf, 0x2b, 0x93, 0x0d, 0xb4, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x4a, 0x00, 0x23, 0x00, 0x0c, 0x00, 0x03, 0x00, 0xf2, 0x00, 0x30, 0xb2, 0x6e, 0x7d,
        0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc, 0xf5, 0xfd, 0x3a, 0x1a, 0x07, 0x41, 0x48,
        0xbb, 0x35, 0xd3, 0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4, 0x19, 0xca, 0xcb, 0x47, 0xba,
        0x09, 0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3, 0xf8, 0x0e, 0x12, 0x00, 0x06, 0x01,
        0x00, 0x00, 0x43, 0x00, 0x10, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00];
    
    let mut create_primary_resp: [u8; 1024] = [0; 1024];
    let _ = execute_command(&create_primary_req, &mut create_primary_resp, 0);

    let handle_data: &[u8] = &create_primary_resp[10..14];
    let curr_handle = u32::from_be_bytes([
        handle_data[0],
        handle_data[1],
        handle_data[2],
        handle_data[3],
    ]);

    let tpm2_ek_handle: u32 = TPM2_EK_RSA_HANDLE;
    tpm2_evictcontrol(curr_handle, tpm2_ek_handle);

    Ok(())
}

fn tpm2_create_ek_rsa2048 () -> VtpmResult {
    let mut keyflags: u32 = 0;
    let symkeylen: u16 = 128;
    let authpolicy_len: u16 = 32;
    let rsa_keysize: u16 = 2048;
    let tpm2_ek_handle: u32 = TPM2_EK_RSA_HANDLE;
    let authpolicy: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa,
    ];
    // keyflags: fixedTPM, fixedParent, sensitiveDatOrigin,
    // adminWithPolicy, restricted, decrypt
    keyflags |= 0x000300b2;
    // symmetric: TPM_ALG_AES, 128bit or 256bit, TPM_ALG_CFB
    let symkeydata_len = 6;
    let symkeydata: &[u8] = &[
        TPM2_ALG_AES.to_be_bytes(),
        symkeylen.to_be_bytes(),
        TPM2_ALG_CFB.to_be_bytes(),
    ]
    .concat();

    let authblock: tpm2_authblock = tpm2_authblock::new(TPM2_RS_PW, 0, 0, 0);

    let mut hdr: Tpm2CommandHeader = Tpm2CommandHeader::new(TPM_ST_SESSIONS, 0, TPM2_CC_CREATEPRIMARY);

    let mut nonce_rsa2048: [u8; 0x102] = [0; 0x102];
    nonce_rsa2048[0..2].copy_from_slice(&0x100_u16.to_be_bytes());

    let mut public: Vec<u8> = Vec::new();
    public.extend_from_slice(&TPM2_ALG_RSA.to_be_bytes());
    public.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());
    public.extend_from_slice(&keyflags.to_be_bytes());
    public.extend_from_slice(&authpolicy_len.to_be_bytes());
    public.extend_from_slice(&authpolicy);
    public.extend_from_slice(&symkeydata);
    public.extend_from_slice(&TPM2_ALG_NULL.to_be_bytes());
    public.extend_from_slice(&rsa_keysize.to_be_bytes());
    public.extend_from_slice(&0_u32.to_be_bytes());
    public.extend_from_slice(&nonce_rsa2048);

    let mut hdr_buff: [u8; 10] = [0; 10];
    hdr.to_bytes(&mut hdr_buff);

    let mut authblock_buff: [u8; TPM2_AUTHBLOCK_SIZE] = [0; TPM2_AUTHBLOCK_SIZE];
    authblock.to_bytes(&mut authblock_buff);

    let mut create_primary_req: Vec<u8> = Vec::new();
    create_primary_req.extend_from_slice(&hdr_buff);
    create_primary_req.extend_from_slice(&TPM2_RH_ENDORSEMENT.to_be_bytes());
    create_primary_req.extend_from_slice(&tpm2_authblock::size().to_be_bytes());
    create_primary_req.extend_from_slice(&authblock_buff);
    create_primary_req.extend_from_slice(&4_u16.to_be_bytes());
    create_primary_req.extend_from_slice(&0_u32.to_be_bytes());
    create_primary_req.extend_from_slice(&(public.len() as u16).to_be_bytes());
    create_primary_req.extend_from_slice(public.as_slice());
    create_primary_req.extend_from_slice(&0_u32.to_be_bytes());
    create_primary_req.extend_from_slice(&0_u16.to_be_bytes());

    let final_req_len = create_primary_req.len() as u32;
    let (left_hdr, _) = create_primary_req.split_at_mut(TPM2_COMMAND_HEADER_SIZE);
    hdr.set_size(final_req_len);
    hdr.to_bytes(&mut hdr_buff);
    left_hdr.copy_from_slice(&hdr_buff);

    let mut create_primary_resp: [u8; 1024] = [0; 1024];
    let _ = execute_command(&create_primary_req.as_mut_slice(), &mut create_primary_resp, 0);

    let handle_data: &[u8] = &create_primary_resp[10..14];
    let curr_handle = u32::from_be_bytes([
        handle_data[0],
        handle_data[1],
        handle_data[2],
        handle_data[3],
    ]);

    tpm2_evictcontrol(curr_handle, tpm2_ek_handle);

    Ok(())
}

const TPM2_CC_EVICTCONTROL: u32 = 0x00000120;
const TPM2_RH_OWNER: u32 = 0x40000001;

fn tpm2_evictcontrol(curr_handle: u32, perm_handle: u32) {
    let hdr: Tpm2CommandHeader = Tpm2CommandHeader::new(
        TPM_ST_SESSIONS,
        tpm2_evictcontrol_req::size(),
        TPM2_CC_EVICTCONTROL,
    );
    let authblock: tpm2_authblock = tpm2_authblock::new(TPM2_RS_PW, 0, 0, 0);
    let mut evictcontrol_req: tpm2_evictcontrol_req = tpm2_evictcontrol_req::new(
        hdr,
        TPM2_RH_OWNER,
        curr_handle,
        tpm2_authblock::size(),
        authblock,
        perm_handle,
    );

    let mut req: [u8; 1024] = [0; 1024];
    let mut rsp: [u8; 1024] = [0; 1024];

    evictcontrol_req.to_bytes(&mut req);

    let _ = execute_command(&req[..TPM2_EVICTCONTROL_REQ_SIZE], &mut rsp, 0);
}

/// Get the TPM EKpub in the TSS format (marshaled TPM2B_PUBLIC structure)
/// TSS format e.g.: tpm2_createek -c 0x81000000 -G rsa -f tss -u /tmp/ekpub.tss
pub fn tpm2_get_ek_pub() -> Vec<u8> {

    let mut TPMT_PUBLIC_Siz: usize = 0;
    unsafe {
        TPMT_PUBLIC_Siz = _plat__TPMT_PUBLIC_Size() as usize;
    }

    // TPM2_CC_ReadPublic 0x00000173
    let cmd_req: &mut [u8] = &mut [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x73, 0x81, 0x01, 0x00, 0x01,
    ];
    let mut response_buf: [u8; 1024] = [0; 1024];
    // TPM command response buffer
    let _ = execute_command(cmd_req, &mut response_buf, 0);

    // Output parameters
    let out_parms: &[u8] = &response_buf[{Tpm2CommandHeader::size() as usize}..];

    const U16_SIZE: usize = core::mem::size_of::<u16>();

    // TPM2B_PUBLIC.size field
    let size: u16 = u16::from_be_bytes(out_parms[..U16_SIZE].try_into().unwrap());
    if size as usize > TPMT_PUBLIC_Siz {
        log::error!("ERROR: TPM2B_PUBLIC.size={:#x} is too big\n", size);
        return Vec::new();
    }

    // TPM2B_PUBLIC structure
    let out_public: &[u8] = &out_parms[..{size as usize + U16_SIZE}];
    log::info!("out_public {:x} {:02x?}\n", {out_public.len()}, out_public);
    out_public.to_vec()
}

pub fn tpm2_provision_ek() -> VtpmResult {
    // First call TPM2_CC_Startup
    tpm2_startup()?;

    // Create EK pub in the TPM.
    tpm2_create_ek_rsa2048()?;

    // get the ek_pub
    let ek_pub: Vec<u8> = tpm2_get_ek_pub();
    if ek_pub.is_empty() {
        tpm2_shutdown()?;
        return Err(VtpmError::TpmLibError);
    }

    // generate ek_cert
    let ek_cert = generate_ek_cert (ek_pub.as_slice());
    if ek_cert.is_err() {
        let _ = tpm2_shutdown();
        return Err(VtpmError::TpmLibError);
    }

    // save it into NV
    let ek_cert = ek_cert.unwrap();
    tpm2_write_cert_nvram(ek_cert.as_slice());

    tpm2_shutdown()?;
    Ok(())
}

pub fn tpm2_write_cert_nvram(cert: &[u8]) {
    if cert.len() > usize::from(u16::MAX) {
        log::error!("ERROR: Cert size = {:#x} too big\n", {cert.len()});
        return;
    }
    let nvindex_attrs: u32 = TPMA_NV_PLATFORMCREATE
        | TPMA_NV_AUTHREAD
        | TPMA_NV_OWNERREAD
        | TPMA_NV_PPREAD
        | TPMA_NV_PPWRITE
        | TPMA_NV_NO_DA
        | TPMA_NV_WRITEDEFINE;
    let nvindex = TPM2_NV_INDEX_RSA2048_EKCERT;
    tpm2_nvdefine_space(nvindex, nvindex_attrs, cert.len());
    //
    // The report size might be bigger than the MAX_NV_BUFFER_SIZE (max buffer size for TPM
    // NV commands) defined in the TPM spec. For simplicity let's just assume it is at least 1024.
    //
    let mut start: u16 = 0;
    let mut end: u16 = 0;
    loop {
        end = start + 1024;
        if  usize::from(end) > cert.len() {
            end = cert.len().try_into().unwrap();
        }
        if start >= end {
            break;
        }
        tpm2_nv_write(nvindex, start, &cert[usize::from(start)..usize::from(end)]);
        start = end;
    }
    log::info!("INFO: Cert ({} bytes) written to the TPM NV index {:#x}\n", {cert.len()}, nvindex);
}

fn tpm2_nvdefine_space(nvindex: u32, nvindex_attrs: u32, data_len: usize) {
    let mut hdr: Tpm2CommandHeader = Tpm2CommandHeader::new(TPM_ST_SESSIONS, 0, TPM2_CC_NV_DEFINESPACE);
    let mut hdr_buf: [u8; TPM2_COMMAND_HEADER_SIZE] = [0; TPM2_COMMAND_HEADER_SIZE];
    hdr.to_bytes(&mut hdr_buf);

    let authblock: tpm2_authblock = tpm2_authblock::new(TPM2_RS_PW, 0, 0, 0);
    let mut authblock_buff: [u8; TPM2_AUTHBLOCK_SIZE] = [0; TPM2_AUTHBLOCK_SIZE];
    authblock.to_bytes(&mut authblock_buff);

    let mut nvpublic: Vec<u8> = Vec::new();
    nvpublic.extend_from_slice(&nvindex.to_be_bytes());
    nvpublic.extend_from_slice(&TPM2_ALG_SHA256.to_be_bytes());
    nvpublic.extend_from_slice(&nvindex_attrs.to_be_bytes());
    nvpublic.extend_from_slice(&0_u16.to_be_bytes());
    nvpublic.extend_from_slice(&(data_len as u16).to_be_bytes());

    let mut nv_req: Vec<u8> = Vec::new();
    nv_req.extend_from_slice(&hdr_buf);
    nv_req.extend_from_slice(&TPM2_RH_PLATFORM.to_be_bytes());
    nv_req.extend_from_slice(&tpm2_authblock::size().to_be_bytes());
    nv_req.extend_from_slice(&authblock_buff);
    nv_req.extend_from_slice(&0_u16.to_be_bytes());
    nv_req.extend_from_slice(&(nvpublic.len() as u16).to_be_bytes());
    nv_req.extend_from_slice(nvpublic.as_slice());

    let final_req_len = nv_req.len() as u32;
    let (left_hdr, _) = nv_req.split_at_mut(TPM2_COMMAND_HEADER_SIZE);
    hdr.set_size(final_req_len);
    hdr.to_bytes(&mut hdr_buf);
    left_hdr.copy_from_slice(&hdr_buf);

    let mut rsp: [u8; 1024] = [0; 1024];
    let _ = execute_command(nv_req.as_slice(), &mut rsp, 0);
}

fn tpm2_nv_write(nvindex: u32, offset: u16, data: &[u8]) {
    let mut hdr: Tpm2CommandHeader = Tpm2CommandHeader::new(TPM_ST_SESSIONS, 0, TPM2_CC_NV_WRITE);
    let mut hdr_buf: [u8; TPM2_COMMAND_HEADER_SIZE] = [0; TPM2_COMMAND_HEADER_SIZE];
    hdr.to_bytes(&mut hdr_buf);

    let authblock: tpm2_authblock = tpm2_authblock::new(TPM2_RS_PW, 0, 0, 0);
    let mut authblock_buff: [u8; TPM2_AUTHBLOCK_SIZE] = [0; TPM2_AUTHBLOCK_SIZE];
    authblock.to_bytes(&mut authblock_buff);

    let mut nv_req: Vec<u8> = Vec::with_capacity(4096);
    nv_req.extend_from_slice(&hdr_buf);
    nv_req.extend_from_slice(&TPM2_RH_PLATFORM.to_be_bytes());
    nv_req.extend_from_slice(&nvindex.to_be_bytes());
    nv_req.extend_from_slice(&tpm2_authblock::size().to_be_bytes());
    nv_req.extend_from_slice(&authblock_buff);
    nv_req.extend_from_slice(&(data.len() as u16).to_be_bytes());
    nv_req.extend_from_slice(data);
    nv_req.extend_from_slice(&offset.to_be_bytes());

    let final_req_len = nv_req.len() as u32;
    let (left_hdr, _) = nv_req.split_at_mut(TPM2_COMMAND_HEADER_SIZE);
    hdr.set_size(final_req_len);
    hdr.to_bytes(&mut hdr_buf);
    left_hdr.copy_from_slice(&hdr_buf);

    let mut rsp: [u8; 1024] = [0; 1024];
    let _ = execute_command(nv_req.as_slice(), &mut rsp, 0);

}