use std::ffi::{c_char, c_uchar, c_ulong, CStr, CString};

use sshcerts::{
    ssh::{SshSignature, VerifiedSshSignature},
    PrivateKey, PublicKey,
};

#[no_mangle]
/// Take a private key and sign arbitrary data with it under the given namespace.
/// Returns the signature as a string which then needs to be freed. All failures
/// return a null pointer.
pub unsafe extern "C" fn ffi_sign_data(
    key_path: *const c_char,
    namespace: *const c_char,
    data: *const c_uchar,
    data_len: c_ulong,
) -> *const c_char {
    let key_path = match CStr::from_ptr(key_path).to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let private_key = match PrivateKey::from_path(key_path) {
        Err(_) => return std::ptr::null(),
        Ok(k) => k,
    };

    let namespace = match CStr::from_ptr(namespace).to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let data = std::slice::from_raw_parts(data, data_len as usize);

    match VerifiedSshSignature::new_with_private_key(data, namespace, private_key, None) {
        Err(_) => return std::ptr::null(),
        Ok(signature) => match CString::new(signature.to_string()) {
            Err(_) => return std::ptr::null(),
            Ok(s) => s.into_raw(),
        },
    }
}

fn parse_allowed_signer<'a>(allowed_signer: &'a str) -> Option<(PublicKey, &'a str)> {
    let allowed_signer = allowed_signer.splitn(2, ' ').collect::<Vec<&str>>();
    if allowed_signer.len() != 2 {
        return None;
    }

    match PublicKey::from_string(allowed_signer[1]) {
        Err(_) => None,
        Ok(k) => Some((k, allowed_signer[0])),
    }
}

#[no_mangle]
/// Verify a signature against the given allowed_signers, data, and namespace.
/// Returns the name of the allowed signer which then needs to be freed. All failures
/// return a null pointer.
pub unsafe extern "C" fn ffi_verify_signed_data(
    allowed_signers_path: *const c_char,
    namespace: *const c_char,
    data: *const c_uchar,
    data_len: c_ulong,
    signature_contents: *const c_char,
) -> *const c_char {
    let signature_contents = match CStr::from_ptr(signature_contents).to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let ssh_signature = match SshSignature::from_armored_string(&signature_contents) {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let allowed_signers_path = match CStr::from_ptr(allowed_signers_path).to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let allowed_signers = match std::fs::read_to_string(allowed_signers_path) {
        Ok(s) => s,
        Err(_) => return std::ptr::null(),
    };

    let allowed_signer = allowed_signers
        .lines()
        .filter_map(parse_allowed_signer)
        .filter(|x| ssh_signature.pubkey == x.0)
        .next();

    let allowed_signer = match allowed_signer {
        None => return std::ptr::null(),
        Some(s) => s,
    };

    let message = std::slice::from_raw_parts(data, data_len as usize);

    let namespace = match CStr::from_ptr(namespace).to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    match VerifiedSshSignature::from_ssh_signature(
        message,
        ssh_signature,
        namespace,
        Some(allowed_signer.0),
    ) {
        Err(_) => return std::ptr::null(),
        Ok(_) => match CString::new(allowed_signer.1) {
            Err(_) => return std::ptr::null(),
            Ok(s) => s.into_raw(),
        },
    }
}
