/*
Copyright (c) 2017 Marin Atanasov Nikolov <dnaeon@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer
    in this position and unchanged.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

//#![deny(warnings)]
//#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

//! This is a heavily modified version of the `sshkeys` crate
//! that adds certificate verification, and many other things to
//! support that. The original licence for the code is in the source
//! code provided
//! 
//! The `sshkeys` crate provides types and methods for parsing
//! OpenSSH public keys and certificates.
//!
//! The following public key types are supported.
//!
//! - RSA
//! - ECDSA
//! - ED25519
//!
//! The following OpenSSH certificate types are supported as well.
//!
//! - ssh-rsa-cert-v01@openssh.com
//! - ssh-dss-cert-v01@openssh.com
//! - ecdsa-sha2-nistp256-cert-v01@openssh.com
//! - ecdsa-sha2-nistp384-cert-v01@openssh.com
//! - ecdsa-sha2-nistp512-cert-v01@openssh.com
//! - ssh-ed25519-cert-v01@openssh.com
//!
//! # Examples
//!
//! In order to view examples of this crate in use, please refer to the
//! `examples` directory.

mod cert;
mod error;
mod keytype;
mod pubkey;
mod reader;
mod writer;

// Serialization and deserialization support for sshkeys
#[cfg(feature = "serde")]
mod serde;

pub use self::cert::{CertType, Certificate};
pub use self::error::{Error, Result};
pub use self::keytype::{KeyType, KeyTypeKind};
pub use self::pubkey::{
    Curve, CurveKind, EcdsaPublicKey, Ed25519PublicKey, Fingerprint, FingerprintKind,
    PublicKey, PublicKeyKind, RsaPublicKey,
};
pub use self::reader::Reader;
pub use self::writer::Writer;
