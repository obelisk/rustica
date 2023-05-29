/// The Yubikey signer uses a connected Yubikey 4/5 to sign requests. It
/// currently only supports Ecdsa256 and Ecdsa384. To use the Yubikey
/// signer, the `yubikey-support` feature must be enabled.
use super::{Signer, SignerConfig, SigningError};

use sshcerts::yubikey::piv::management::CSRSigner;
use sshcerts::yubikey::piv::{SlotId, Yubikey};
use sshcerts::{ssh::CertType, Certificate, PublicKey};

use async_trait::async_trait;

use serde::Deserialize;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

use rcgen::{Certificate as X509Certificate, CertificateParams, DnType, IsCa, RemoteKeyPair};

#[derive(Deserialize)]
pub struct Config {
    /// The slot on the Yubikey to use for signing user certificates
    #[serde(default)]
    #[serde(deserialize_with = "parse_option_slot")]
    user_slot: Option<SlotId>,
    /// The slot on the Yubikey to use for signing host certificates
    #[serde(default)]
    #[serde(deserialize_with = "parse_option_slot")]
    host_slot: Option<SlotId>,
    /// The slot on the Yubikey to use for signing X509 certificates
    #[serde(default)]
    #[serde(deserialize_with = "parse_option_slot")]
    x509_slot: Option<SlotId>,
    /// The slot on the Yubikey to use for signing client certificates
    #[serde(default)]
    #[serde(deserialize_with = "parse_option_slot")]
    client_certificate_authority_slot: Option<SlotId>,
    /// The common name to use in the client certificate authority
    client_certificate_authority_common_name: Option<String>,
}

struct SshKey {
    /// The slot on the Yubikey to use for signing user certificates
    slot: SlotId,
    // The public key of the CA used for signing user certificates
    public_key: PublicKey,
}

struct SshKeys {
    /// The key that will be used to sign user SSH certificate requests
    user: SshKey,
    /// The key that will be used to sign host SSH certificate requests
    host: SshKey,
}

pub struct YubikeySigner {
    /// The possibly configured SSH keys to be used for fulfilling SSH
    /// certificate signing requests
    ssh_keys: Option<SshKeys>,
    /// The X509 certificate that will be the issuer for requested x509 certificates
    x509_certificate: Option<X509Certificate>,
    /// The X509 certificate that will be the issuer for client certificates
    client_certificate_authority: Option<X509Certificate>,
    /// A mutex to ensure there is no concurrent access to the Yubikey. Without
    /// this, handling two requests at the same time would result in possibly
    /// corrupted certificates for both.
    yubikey: Arc<Mutex<Yubikey>>,
}

fn rcgen_certificate_from_yubikey(
    common_name: &str,
    serial: u32,
    slot: SlotId,
) -> Result<X509Certificate, SigningError> {
    let yk_x509_signer = CSRSigner::new(serial, slot);

    let mut ca_params = CertificateParams::new(vec![]);
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    ca_params.alg = yk_x509_signer.algorithm();

    let kp = match rcgen::KeyPair::from_remote(Box::new(yk_x509_signer)) {
        Ok(kp) => kp,
        Err(_) => {
            return Err(SigningError::AccessError(
                "Could not create remote signer for X509 key".to_owned(),
            ))
        }
    };

    ca_params.key_pair = Some(kp);
    X509Certificate::from_params(ca_params).map_err(|_| {
        SigningError::AccessError(format!("Could not create certificate for slot {:?}", slot))
    })
}

#[async_trait]
impl SignerConfig for Config {
    async fn into_signer(self) -> Result<Box<dyn Signer + Send + Sync>, SigningError> {
        let yubikey = new_yubikey_mutex();
        let serial = yubikey.lock().unwrap().yk.serial().0;

        let ssh_keys = match (self.user_slot, self.host_slot) {
            (Some(user_slot), Some(host_slot)) => {
                let mut yk = yubikey.lock().map_err(|e| {
                    SigningError::AccessError(format!("Could not lock Yubikey. Error: {}", e))
                })?;
    
                let user = SshKey {
                    slot: user_slot,
                    public_key: yk.ssh_cert_fetch_pubkey(&user_slot).map_err(|_| {
                        SigningError::AccessError(format!("Could fetch public key for user key"))
                    })?
                };

                let host = SshKey {
                    slot: host_slot,
                    public_key: yk.ssh_cert_fetch_pubkey(&host_slot).map_err(|_| {
                        SigningError::AccessError(format!("Could fetch public key for user key"))
                    })?
                };
                Some(SshKeys {user, host})
            }
            (None, None) => None,
            _ => return Err(SigningError::SignerDoesNotAllRequiredSSHKeys),
        };

        let x509_certificate = match self.x509_slot {
            Some(x509_slot) => Some(rcgen_certificate_from_yubikey("Rustica", serial, x509_slot)?),
            None => None,
        };

        let client_certificate_authority = if let (Some(slot), Some(cn)) = (
            self.client_certificate_authority_slot,
            self.client_certificate_authority_common_name,
        ) {
            Some(rcgen_certificate_from_yubikey(&cn, serial, slot)?)
        } else {
            None
        };

        Ok(Box::new(YubikeySigner {
            ssh_keys,
            x509_certificate,
            client_certificate_authority,
            yubikey,
        }))
    }
}

#[async_trait]
impl Signer for YubikeySigner {
    async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        let ssh_keys = self.ssh_keys.as_ref().ok_or(SigningError::SignerDoesNotHaveSSHKeys)?;

        let slot = match cert.cert_type {
            CertType::User => ssh_keys.user.slot,
            CertType::Host => ssh_keys.host.slot,
        };

        match self.yubikey.lock() {
            Ok(_) => {
                // Unfortunatly we need to create a new Yubikey here because otherwise
                // everything will have to be mutable which causes an issue
                // for the RusticaServer struct
                let mut yk = Yubikey::new().unwrap();
                match yk.ssh_cert_signer(&cert.tbs_certificate(), &slot) {
                    Ok(sig) => cert
                        .add_signature(&sig)
                        .map_err(|_| SigningError::SigningFailure),
                    Err(_) => Err(SigningError::SigningFailure),
                }
            }
            Err(e) => Err(SigningError::AccessError(e.to_string())),
        }
    }

    fn get_signer_public_key(&self, cert_type: CertType) -> Option<PublicKey> {
        let ssh_keys = self.ssh_keys.as_ref()?;

        match cert_type {
            CertType::User => Some(ssh_keys.user.public_key.clone()),
            CertType::Host => Some(ssh_keys.host.public_key.clone()),
        }
    }

    fn get_attested_x509_certificate_authority(&self) -> Option<&rcgen::Certificate> {
        self.x509_certificate.as_ref()
    }

    fn get_client_certificate_authority(&self) -> Option<&rcgen::Certificate> {
        self.client_certificate_authority.as_ref()
    }
}

pub fn parse_option_slot<'de, D>(deserializer: D) -> Result<Option<SlotId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let slot = match String::deserialize(deserializer) {
        Ok(s) => s,
        _ => return Ok(None),
    };

    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Ok(Some(SlotId::try_from(0x81_u8 + v).unwrap())),
            _ => Err(serde::de::Error::custom("Invalid Slot")),
        }
    } else if slot.len() == 4 && slot.starts_with("0x") {
        let slot_value = hex::decode(&slot[2..]).unwrap()[0];
        Ok(Some(SlotId::try_from(slot_value).unwrap()))
    } else {
        Err(serde::de::Error::custom("Invalid Slot"))
    }
}

pub fn new_yubikey_mutex() -> Arc<Mutex<Yubikey>> {
    let yk = Yubikey::new().unwrap();
    Arc::new(Mutex::new(yk))
}
