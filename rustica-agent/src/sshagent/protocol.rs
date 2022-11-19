use byteorder::{BigEndian, WriteBytesExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
};

use super::error::{ParsingError, WrittingError};

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
            MessageRequest::AddIdConstrained => Ok(Request::Unknown),
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
