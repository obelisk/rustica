use byteorder::{BigEndian, WriteBytesExt};
use sshcerts::ssh::Reader;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
};

use super::error::{ParsingError, WrittingError};

const MAX_MESSAGE_SIZE: usize = 256 * 1024;

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
            20 => MessageRequest::AddSmartcardKey,
            21 => MessageRequest::RemoveSmartcardKey,
            22 => MessageRequest::Lock,
            23 => MessageRequest::Unlock,
            25 => MessageRequest::AddIdConstrained,
            26 => MessageRequest::AddSmartcardKeyConstrained,
            27 => MessageRequest::Extension,
            _ => MessageRequest::Unknown,
        }
    }
}

async fn read_message<R: AsyncRead + std::marker::Unpin>(stream: &mut R) -> ParsingError<Vec<u8>> {
    let len = AsyncReadExt::read_u32(stream).await? as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err("SSH agent message exceeds the 256 KiB limit".into());
    }

    let mut buf = vec![0; len];
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
    AddIdentityConstrained {
        private_key: sshcerts::PrivateKey,
        constraints: Vec<super::constraints::Constraint>,
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
            MessageRequest::Sign => {
                let mut reader = Reader::new(buf);
                Ok(Request::Sign {
                    pubkey_blob: reader
                        .read_bytes()
                        .map_err(|_| "Failed to read signing public key")?,
                    data: reader
                        .read_bytes()
                        .map_err(|_| "Failed to read signing data")?,
                    flags: reader
                        .read_u32()
                        .map_err(|_| "Failed to read signing flags")?,
                })
            }
            MessageRequest::AddIdentity => match sshcerts::PrivateKey::from_bytes(buf) {
                Ok(private_key) => Ok(Request::AddIdentity { private_key }),
                Err(_) => Ok(Request::Unknown),
            },
            MessageRequest::RemoveIdentity => Ok(Request::Unknown),
            MessageRequest::RemoveAllIdentities => Ok(Request::Unknown),
            MessageRequest::AddIdConstrained => {
                let mut reader = Reader::new(buf);

                let private_key = match sshcerts::PrivateKey::read_private_key(&mut reader) {
                    Ok(private_key) => private_key,
                    Err(_) => return Ok(Request::Unknown),
                };

                let constraints_buf = &buf[reader.get_offset()..];
                let constraints = match super::constraints::parse_constraints(constraints_buf) {
                    Ok(constraints) => constraints,
                    Err(_) => return Ok(Request::Unknown),
                };
                Ok(Request::AddIdentityConstrained {
                    private_key,
                    constraints,
                })
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
    use std::time::Duration;
    use tokio::time::timeout;

    async fn read_request(body: &[u8]) -> ParsingError<Request> {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let (write, request) = tokio::join!(write_message(&mut sender, body), async move {
            Request::read(&mut receiver).await
        });
        write.unwrap();
        request
    }

    #[tokio::test]
    async fn oversized_message_is_rejected_before_payload() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        AsyncWriteExt::write_u32(&mut sender, (MAX_MESSAGE_SIZE + 1) as u32)
            .await
            .unwrap();

        let result = timeout(Duration::from_secs(1), Request::read(&mut receiver))
            .await
            .expect("oversized messages must be rejected without waiting for their payload");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn reads_maximum_size_sign_request() {
        let pubkey = b"key";
        let data = vec![42; MAX_MESSAGE_SIZE - 1 - 4 - pubkey.len() - 4 - 4];
        let mut body = vec![13];
        write_message(&mut body, pubkey).await.unwrap();
        write_message(&mut body, &data).await.unwrap();
        AsyncWriteExt::write_u32(&mut body, 2).await.unwrap();
        assert_eq!(body.len(), MAX_MESSAGE_SIZE);

        match read_request(&body).await.unwrap() {
            Request::Sign {
                pubkey_blob,
                data: parsed_data,
                flags,
            } => {
                assert_eq!(pubkey_blob, pubkey);
                assert_eq!(parsed_data, data);
                assert_eq!(flags, 2);
            }
            request => panic!("expected a signing request, got {request:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_sign_fields_exceeding_message() {
        for field in 0..2 {
            let mut body = vec![13];
            if field == 1 {
                write_message(&mut body, b"key").await.unwrap();
            }
            AsyncWriteExt::write_u32(&mut body, MAX_MESSAGE_SIZE as u32)
                .await
                .unwrap();

            assert!(read_request(&body).await.is_err());
        }
    }
}
