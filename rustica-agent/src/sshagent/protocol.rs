use byteorder::{BigEndian, WriteBytesExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
};

use sshcerts::ssh::Reader;

use super::error::{ParsingError, WrittingError};

/// Parsed SSH agent key constraint.
#[derive(Debug, PartialEq)]
#[allow(dead_code)]
enum KeyConstraint {
    Lifetime(u32),
    Confirm,
    Extension { name: String, data: Vec<u8> },
    Unknown(u8),
}

/// Parse constraints from an AddIdConstrained message body.
///
/// Skips past the private key fields and comment, then reads the trailing constraint bytes.
fn parse_constraints(buf: &[u8]) -> Option<Vec<KeyConstraint>> {
    enum F { Str, Byte }
    use F::*;

    let mut r = Reader::new(buf);
    let key_type = r.read_string().ok()?;

    // Field layout between key-type string and comment
    let fields: &[F] = match key_type.as_str() {
        "ssh-rsa"                              => &[Str, Str, Str, Str, Str, Str],
        "ssh-ed25519"                          => &[Str, Str],
        t if t.starts_with("ecdsa-sha2-")      => &[Str, Str, Str],
        "sk-ssh-ed25519@openssh.com"           => &[Str, Str, Byte, Str, Str],
        "sk-ecdsa-sha2-nistp256@openssh.com"   => &[Str, Str, Str, Byte, Str, Str],
        _ => return None,
    };

    for f in fields {
        match f {
            Str  => { r.read_bytes().ok()?; }
            Byte => { r.read_raw_bytes(1).ok()?; }
        }
    }
    r.read_string().ok()?; // comment

    let mut r = Reader::new(&buf[r.get_offset()..]);
    let mut constraints = Vec::new();
    while let Ok(ty) = r.read_raw_bytes(1).map(|b| b[0]) {
        match ty {
            1   => constraints.push(KeyConstraint::Lifetime(r.read_u32().ok()?)),
            2   => constraints.push(KeyConstraint::Confirm),
            255 => constraints.push(KeyConstraint::Extension {
                name: r.read_string().ok()?,
                data: r.read_bytes().ok()?,
            }),
            _ => { constraints.push(KeyConstraint::Unknown(ty)); break; }
        }
    }
    Some(constraints)
}

#[derive(Debug, Copy, Clone)]
enum MessageRequest {
    Identities,
    Sign,
    AddIdentity,
    RemoveIdentity,
    RemoveAllIdentities,
    AddIdConstrained,
    AddSmartcardKey,
    RemoveSmartcardKey,
    Lock,
    Unlock,
    AddSmartcardKeyConstrained,
    Extension,
    Unknown,
}

impl MessageRequest {
    fn from_u8(value: u8) -> MessageRequest {
        match value {
            11 => MessageRequest::Identities,
            13 => MessageRequest::Sign,
            17 => MessageRequest::AddIdentity,
            18 => MessageRequest::RemoveIdentity,
            19 => MessageRequest::RemoveAllIdentities,
            25 => MessageRequest::AddIdConstrained,
            20 => MessageRequest::AddSmartcardKey,
            21 => MessageRequest::RemoveSmartcardKey,
            22 => MessageRequest::Lock,
            23 => MessageRequest::Unlock,
            26 => MessageRequest::AddSmartcardKeyConstrained,
            27 => MessageRequest::Extension,
            _ => MessageRequest::Unknown,
        }
    }
}

async fn read_message<R: AsyncRead + std::marker::Unpin>(stream: &mut R) -> ParsingError<Vec<u8>> {
    let len = AsyncReadExt::read_u32(stream).await?;

    let mut buf = vec![0; len as usize];
    AsyncReadExt::read_exact(stream, &mut buf).await?;

    Ok(buf)
}

async fn write_message<W: AsyncWrite + std::marker::Unpin>(
    w: &mut W,
    string: &[u8],
) -> WrittingError<()> {
    AsyncWriteExt::write_u32(w, string.len() as u32).await?;
    AsyncWriteExt::write_all(w, string).await?;
    Ok(())
}

#[derive(Debug)]
pub enum Request {
    Identities,
    Sign {
        // Blob of the public key
        // (encoded as per RFC4253 "6.6. Public Key Algorithms").
        pubkey_blob: Vec<u8>,
        // The data to sign.
        data: Vec<u8>,
        // Request flags.
        flags: u32,
    },
    AddIdentity {
        private_key: sshcerts::PrivateKey,
    },
    Unknown,
}

impl Request {
    pub async fn read(stream: &mut UnixStream) -> ParsingError<Self> {
        debug!("reading request");
        let raw_msg = read_message(stream).await?;
        let mut buf = raw_msg.as_slice();

        let msg = AsyncReadExt::read_u8(&mut buf).await?;
        match MessageRequest::from_u8(msg) {
            MessageRequest::Identities => Ok(Request::Identities),
            MessageRequest::Sign => Ok(Request::Sign {
                pubkey_blob: read_message(&mut buf).await?,
                data: read_message(&mut buf).await?,
                flags: AsyncReadExt::read_u32(&mut buf).await?,
            }),
            MessageRequest::AddIdentity => match sshcerts::PrivateKey::from_bytes(buf) {
                Ok(private_key) => Ok(Request::AddIdentity { private_key }),
                Err(_) => Ok(Request::Unknown),
            },
            MessageRequest::RemoveIdentity => Ok(Request::Unknown),
            MessageRequest::RemoveAllIdentities => Ok(Request::Unknown),
            MessageRequest::AddIdConstrained => {
                if let Some(constraints) = parse_constraints(buf) {
                    debug!("AddIdConstrained constraints: {:?}", constraints);
                }
                match sshcerts::PrivateKey::from_bytes(buf) {
                    Ok(private_key) => Ok(Request::AddIdentity { private_key }),
                    Err(_) => Ok(Request::Unknown),
                }
            }
            MessageRequest::AddSmartcardKey => Ok(Request::Unknown),
            MessageRequest::RemoveSmartcardKey => Ok(Request::Unknown),
            MessageRequest::Lock => Ok(Request::Unknown),
            MessageRequest::Unlock => Ok(Request::Unknown),
            MessageRequest::AddSmartcardKeyConstrained => Ok(Request::Unknown),
            MessageRequest::Extension => Ok(Request::Unknown),
            MessageRequest::Unknown => {
                debug!("Unknown request {}", msg);
                Ok(Request::Unknown)
            }
        }
    }
}

enum AgentMessageResponse {
    Failure = 5,
    Success = 6,
    IdentitiesAnswer = 12,
    SignResponse = 14,
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub key_comment: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Response {
    Success,
    Failure,
    Identities(Vec<Identity>),
    SignResponse { signature: Vec<u8> },
}

impl Response {
    pub async fn write(&self, stream: &mut UnixStream) -> WrittingError<()> {
        let mut buf = Vec::new();
        match *self {
            Response::Success => {
                WriteBytesExt::write_u8(&mut buf, AgentMessageResponse::Success as u8)?
            }
            Response::Failure => {
                WriteBytesExt::write_u8(&mut buf, AgentMessageResponse::Failure as u8)?
            }
            Response::Identities(ref identities) => {
                WriteBytesExt::write_u8(&mut buf, AgentMessageResponse::IdentitiesAnswer as u8)?;
                WriteBytesExt::write_u32::<BigEndian>(&mut buf, identities.len() as u32)?;

                for identity in identities {
                    write_message(&mut buf, &identity.key_blob).await?;
                    write_message(&mut buf, identity.key_comment.as_bytes()).await?;
                }
            }
            Response::SignResponse { ref signature } => {
                WriteBytesExt::write_u8(&mut buf, AgentMessageResponse::SignResponse as u8)?;

                write_message(&mut buf, signature.as_slice()).await?;
            }
        }
        AsyncWriteExt::write_u32(stream, buf.len() as u32).await?;
        AsyncWriteExt::write_all(stream, &buf).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, WriteBytesExt};

    // Captured from: ssh-add -t 3600 -c /tmp/test_ed25519 (comment "test-key")
    // Message type 25 (SSH_AGENTC_ADD_ID_CONSTRAINED), body only (no msg type byte).
    const REAL_ADD_ID_CONSTRAINED: &[u8] = &[
        // key_type: "ssh-ed25519" (len=11)
        0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39,
        // pubkey (len=32)
        0x00, 0x00, 0x00, 0x20,
        0x39, 0x2c, 0xfb, 0x01, 0xe0, 0xa3, 0x41, 0x66, 0x08, 0x9b, 0x88, 0x81, 0xa9, 0x65, 0x7a, 0xa9,
        0x49, 0x88, 0x14, 0xc2, 0x2d, 0x7a, 0xe0, 0xd6, 0x8f, 0xa0, 0x8c, 0xfa, 0xac, 0xd5, 0x44, 0x1c,
        // private key (len=64)
        0x00, 0x00, 0x00, 0x40,
        0x62, 0x6c, 0xe7, 0x5a, 0xe2, 0x8b, 0x18, 0xf6, 0xaa, 0x2b, 0xf1, 0x70, 0x79, 0x69, 0x0f, 0x79,
        0x93, 0x70, 0x0f, 0x1b, 0xd3, 0x85, 0xec, 0xb9, 0x8f, 0x0c, 0x1e, 0x4e, 0xb7, 0xdb, 0x48, 0xee,
        0x39, 0x2c, 0xfb, 0x01, 0xe0, 0xa3, 0x41, 0x66, 0x08, 0x9b, 0x88, 0x81, 0xa9, 0x65, 0x7a, 0xa9,
        0x49, 0x88, 0x14, 0xc2, 0x2d, 0x7a, 0xe0, 0xd6, 0x8f, 0xa0, 0x8c, 0xfa, 0xac, 0xd5, 0x44, 0x1c,
        // comment: "test-key" (len=8)
        0x00, 0x00, 0x00, 0x08, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79,
        // constraints: Lifetime(3600) + Confirm
        0x01, 0x00, 0x00, 0x0e, 0x10,
        0x02,
    ];

    #[test]
    fn parse_real_ssh_add_message() {
        let constraints = parse_constraints(REAL_ADD_ID_CONSTRAINED).unwrap();
        assert_eq!(constraints, vec![
            KeyConstraint::Lifetime(3600),
            KeyConstraint::Confirm,
        ]);
    }

    #[test]
    fn real_message_key_parses_with_sshcerts() {
        // Verify sshcerts can also parse the key portion of the captured message
        let key = sshcerts::PrivateKey::from_bytes(REAL_ADD_ID_CONSTRAINED).unwrap();
        assert_eq!(key.comment, "test-key");
    }

    #[test]
    fn parse_no_constraints() {
        // Same real key data but without the trailing constraint bytes
        let buf = &REAL_ADD_ID_CONSTRAINED[..REAL_ADD_ID_CONSTRAINED.len() - 6];
        let constraints = parse_constraints(buf).unwrap();
        assert!(constraints.is_empty());
    }

    #[test]
    fn parse_extension_constraint() {
        let mut buf = REAL_ADD_ID_CONSTRAINED[..REAL_ADD_ID_CONSTRAINED.len() - 6].to_vec();
        buf.push(255); // Extension type
        WriteBytesExt::write_u32::<BigEndian>(&mut buf, 15).unwrap();
        buf.extend_from_slice(b"foo@example.com");
        WriteBytesExt::write_u32::<BigEndian>(&mut buf, 3).unwrap();
        buf.extend_from_slice(b"\x01\x02\x03");

        let constraints = parse_constraints(&buf).unwrap();
        assert_eq!(constraints, vec![KeyConstraint::Extension {
            name: "foo@example.com".into(),
            data: vec![0x01, 0x02, 0x03],
        }]);
    }

    #[test]
    fn parse_unknown_key_type_returns_none() {
        let mut buf = Vec::new();
        WriteBytesExt::write_u32::<BigEndian>(&mut buf, 7).unwrap();
        buf.extend_from_slice(b"unknown");
        assert!(parse_constraints(&buf).is_none());
    }
}
