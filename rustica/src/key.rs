use std::convert::TryFrom;
use std::fmt;

#[derive(Debug)]
pub struct Key {
    pub fingerprint: String,
    pub attestation: Option<KeyAttestation>
}

#[derive(Debug)]
pub struct PIVAttestation {
    pub pin_policy: PinPolicy,
    pub touch_policy: TouchPolicy,
    pub serial: u64,
    pub firmware: String,
    pub certificate: Vec<u8>,
    pub intermediate: Vec<u8>,
}

#[derive(Debug)]
pub struct U2fAttestation {
    pub aaguid: String,
    pub firmware: String,
    pub auth_data: Vec<u8>,
    pub auth_data_signature: Vec<u8>,
    pub intermediate: Vec<u8>,
}

#[derive(Debug)]
pub enum KeyAttestation {
    Piv(PIVAttestation),
    U2f(U2fAttestation),
}

#[derive(Debug, PartialEq)]
pub enum TouchPolicy {
    Never,
    Always,
    Cached,
}

#[derive(Debug, PartialEq)]
pub enum PinPolicy {
    Never = 1,
    Once = 2,
    Always = 3,
}

impl fmt::Display for PinPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for TouchPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u8> for TouchPolicy {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(TouchPolicy::Never),
            2 => Ok(TouchPolicy::Always),
            3 => Ok(TouchPolicy::Cached),
            _ => Err(()),
        }
    }
}

impl TryFrom<u8> for PinPolicy {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(PinPolicy::Never),
            2 => Ok(PinPolicy::Once),
            3 => Ok(PinPolicy::Always),
            _ => Err(()),
        }
    }
}