//! Owner-only local control protocol for a running Rustica agent.
//!
//! Messages are JSON framed by a four-byte big-endian length.  The endpoint is
//! derived from an SSH agent path as `<ssh socket>.control/socket`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::Receiver;

use crate::sshagent::Agent;
use crate::Handler;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum ControlError {
    Io(io::Error),
    Protocol(&'static str),
    Remote { code: String, message: String },
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "control socket error: {e}"),
            Self::Protocol(e) => write!(f, "control protocol error: {e}"),
            Self::Remote { code, message } => {
                write!(f, "control request failed ({code}): {message}")
            }
        }
    }
}
impl std::error::Error for ControlError {}
impl From<io::Error> for ControlError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    DisableCertificate,
    ConfigPath,
}
impl Setting {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "disable_certificate" => Some(Self::DisableCertificate),
            "config_path" => Some(Self::ConfigPath),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::DisableCertificate => "disable_certificate",
            Self::ConfigPath => "config_path",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SettingValue {
    Bool(bool),
    Path(PathBuf),
}
impl SettingValue {
    fn json(&self) -> Value {
        match self {
            Self::Bool(v) => Value::Bool(*v),
            Self::Path(v) => Value::String(v.display().to_string()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u64,
    op: String,
    setting: String,
    #[serde(default)]
    value: RequestValue,
}
#[derive(Default)]
struct RequestValue(Option<Value>);
impl<'de> Deserialize<'de> for RequestValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Value::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}
#[derive(Serialize)]
struct ClientRequest<'a> {
    version: u8,
    op: &'a str,
    setting: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
}
#[derive(Serialize)]
struct Response {
    version: u8,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorResponse>,
}
#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

fn response_error(code: &'static str, message: impl Into<String>) -> Response {
    Response {
        version: PROTOCOL_VERSION,
        ok: false,
        value: None,
        error: Some(ErrorResponse {
            code,
            message: message.into(),
        }),
    }
}

/// Derive the control endpoint for an SSH socket without reading configuration.
pub fn default_endpoint(ssh_socket: impl AsRef<Path>) -> PathBuf {
    let ssh_socket = ssh_socket.as_ref();
    let mut path = ssh_socket.as_os_str().to_os_string();
    path.push(".control/socket");
    PathBuf::from(path)
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn absolute_path(path: &Path) -> Result<PathBuf, ControlError> {
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ControlError::Protocol(
            "control endpoint must not contain ..",
        ));
    }
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir | std::path::Component::Prefix(_) => {}
        }
    }
    Ok(normalized)
}

fn secure_directory(path: &Path, create: bool) -> Result<(), ControlError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound && create => {
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
            fs::symlink_metadata(path)?
        }
        Err(e) => return Err(e.into()),
    };
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ControlError::Protocol(
            "control directory is not a directory",
        ));
    }
    if metadata.uid() != current_uid() {
        return Err(ControlError::Protocol(
            "control directory is not owned by this user",
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(ControlError::Protocol(
            "control directory permissions must be 0700",
        ));
    }
    // A private leaf directory is not enough if an untrusted ancestor can be
    // swapped out. `/tmp` is safe because root owns it and its sticky bit
    // prevents another user from replacing our child directory.
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => ancestor.push(component.as_os_str()),
            std::path::Component::Normal(component) => ancestor.push(component),
            std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                ancestor.pop();
                continue;
            }
            std::path::Component::Prefix(_) => continue,
        }
        let metadata = fs::symlink_metadata(&ancestor)?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || (metadata.uid() != current_uid() && metadata.uid() != 0)
        {
            return Err(ControlError::Protocol("unsafe control directory ancestor"));
        }
        if metadata.mode() & 0o022 != 0
            && !(metadata.uid() == 0 && metadata.mode() & u32::from(libc::S_ISVTX) != 0)
        {
            return Err(ControlError::Protocol(
                "unsafe writable control directory ancestor",
            ));
        }
    }
    Ok(())
}

fn lock_directory(dir: &Path) -> Result<File, ControlError> {
    let path = dir.join("lock");
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.file_type().is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != current_uid()
            || meta.mode() & 0o077 != 0
        {
            return Err(ControlError::Protocol("unsafe control lock file"));
        }
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = lock.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != current_uid()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(ControlError::Protocol("unsafe control lock file"));
    }
    let result = unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(&lock),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    if result != 0 {
        return Err(ControlError::Io(io::Error::last_os_error()));
    }
    Ok(lock)
}

/// Owns the control socket and its advisory lock. Dropping it removes only the
/// socket this instance successfully bound; its private directory and lock stay.
pub struct ControlListener {
    listener: UnixListener,
    endpoint: PathBuf,
    device: u64,
    inode: u64,
    _lock: File,
}
impl ControlListener {
    pub fn bind(endpoint: impl AsRef<Path>) -> Result<Self, ControlError> {
        let endpoint = absolute_path(endpoint.as_ref())?;
        if endpoint.file_name().is_some_and(|name| name == "lock") {
            return Err(ControlError::Protocol(
                "control endpoint conflicts with lock file",
            ));
        }
        let directory = endpoint.parent().ok_or(ControlError::Protocol(
            "control endpoint has no parent directory",
        ))?;
        secure_directory(directory, true)?;
        let lock = lock_directory(directory)?;
        match fs::symlink_metadata(&endpoint) {
            Ok(meta)
                if meta.file_type().is_socket()
                    && meta.uid() == current_uid()
                    && meta.mode() & 0o077 == 0 =>
            {
                fs::remove_file(&endpoint)?
            }
            Ok(_) => {
                return Err(ControlError::Protocol(
                    "unsafe preexisting control endpoint",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&endpoint)?;
        if let Err(e) = fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&endpoint);
            return Err(e.into());
        }
        let socket_metadata = fs::symlink_metadata(&endpoint)?;
        Ok(Self {
            listener,
            endpoint,
            device: socket_metadata.dev(),
            inode: socket_metadata.ino(),
            _lock: lock,
        })
    }
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }
    async fn accept(&self) -> io::Result<(UnixStream, tokio::net::unix::SocketAddr)> {
        self.listener.accept().await
    }
}
impl Drop for ControlListener {
    fn drop(&mut self) {
        remove_owned_socket(&self.endpoint, self.device, self.inode);
    }
}

fn remove_owned_socket(path: &Path, device: u64, inode: u64) {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_socket() && metadata.dev() == device && metadata.ino() == inode {
            let _ = fs::remove_file(path);
        }
    }
}

fn bind_ssh_socket(path: &Path) -> Result<(UnixListener, u64, u64), ControlError> {
    let bind = || UnixListener::bind(path).map_err(ControlError::from);
    let listener = match bind() {
        Ok(listener) => listener,
        Err(ControlError::Io(error)) if error.kind() == io::ErrorKind::AddrInUse => {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != current_uid()
                || metadata.mode() & 0o077 != 0
            {
                return Err(ControlError::Protocol("unsafe preexisting SSH endpoint"));
            }
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => return Err(ControlError::Protocol("SSH endpoint is already active")),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?;
                    bind()?
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error),
    };
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        return Err(error.into());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = fs::remove_file(path);
            return Err(error.into());
        }
    };
    Ok((listener, metadata.dev(), metadata.ino()))
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, ControlError> {
    let length = stream.read_u32().await? as usize;
    if length > MAX_FRAME_SIZE {
        return Err(ControlError::Protocol("frame exceeds 64 KiB"));
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(body)
}
async fn write_frame(stream: &mut UnixStream, body: &[u8]) -> Result<(), ControlError> {
    if body.len() > MAX_FRAME_SIZE {
        return Err(ControlError::Protocol("response exceeds 64 KiB"));
    }
    stream.write_u32(body.len() as u32).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

async fn apply_request(handler: &Handler, request: Request) -> Response {
    if request.version != u64::from(PROTOCOL_VERSION) {
        return response_error(
            "unsupported_version",
            "only protocol version 1 is supported",
        );
    }
    let Some(setting) = Setting::parse(&request.setting) else {
        return response_error("unknown_setting", "unknown setting");
    };
    let value = match request.op.as_str() {
        "get" if request.value.0.is_none() => match setting {
            Setting::DisableCertificate => Value::Bool(handler.certificates_disabled()),
            Setting::ConfigPath => Value::String(handler.config_path().await.display().to_string()),
        },
        "get" => return response_error("invalid_request", "get does not accept value"),
        "set" => match (setting, request.value.0) {
            (Setting::DisableCertificate, Some(Value::Bool(value))) => {
                Value::Bool(handler.set_certificates_disabled(value))
            }
            (Setting::ConfigPath, Some(Value::String(path))) => {
                let path = PathBuf::from(path);
                if !path.is_absolute() {
                    return response_error("invalid_request", "config_path must be absolute");
                }
                match handler.set_config_path(path).await {
                    Ok(path) => Value::String(path.display().to_string()),
                    Err(_) => {
                        return response_error(
                            "invalid_value",
                            "configuration path could not be loaded",
                        )
                    }
                }
            }
            _ => return response_error("invalid_request", "invalid setting value"),
        },
        "toggle" if request.value.0.is_some() => {
            return response_error("invalid_request", "toggle does not accept value");
        }
        "toggle" if setting == Setting::DisableCertificate => {
            Value::Bool(handler.toggle_certificates_disabled())
        }
        "toggle" => return response_error("invalid_request", "setting cannot be toggled"),
        _ => return response_error("unsupported_operation", "unsupported operation"),
    };
    Response {
        version: PROTOCOL_VERSION,
        ok: true,
        value: Some(value),
        error: None,
    }
}

async fn handle_connection(
    handler: Arc<Handler>,
    mut stream: UnixStream,
) -> Result<(), ControlError> {
    loop {
        let response = match serde_json::from_slice::<Request>(&read_frame(&mut stream).await?) {
            Ok(request) => apply_request(&handler, request).await,
            Err(_) => response_error("invalid_request", "invalid JSON request"),
        };
        let response = serde_json::to_vec(&response)
            .map_err(|_| ControlError::Protocol("could not encode response"))?;
        write_frame(&mut stream, &response).await?;
    }
}

/// Rustica's paired listener runner. `bind` completes only after both sockets
/// are bound, so callers may report startup success only after it returns.
pub struct RusticaAgentRunner {
    ssh: UnixListener,
    ssh_endpoint: PathBuf,
    ssh_device: u64,
    ssh_inode: u64,
    control: ControlListener,
    handler: Arc<Handler>,
}
impl RusticaAgentRunner {
    pub fn bind(
        handler: Arc<Handler>,
        ssh_endpoint: impl AsRef<Path>,
        control_endpoint: Option<PathBuf>,
    ) -> Result<Self, ControlError> {
        let ssh_path = absolute_path(ssh_endpoint.as_ref())?;
        let endpoint =
            absolute_path(&control_endpoint.unwrap_or_else(|| default_endpoint(&ssh_path)))?;
        if endpoint == ssh_path {
            return Err(ControlError::Protocol(
                "control endpoint must differ from SSH endpoint",
            ));
        }
        let control = ControlListener::bind(endpoint)?;
        let (ssh, ssh_device, ssh_inode) = bind_ssh_socket(&ssh_path)?;
        Ok(Self {
            ssh,
            ssh_endpoint: ssh_path,
            ssh_device,
            ssh_inode,
            control,
            handler,
        })
    }
    pub fn control_endpoint(&self) -> &Path {
        self.control.endpoint()
    }
    pub async fn run(self, mut termination: Receiver<()>) {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = termination.recv() => break,
                Some(_) = clients.join_next(), if !clients.is_empty() => {},
                accepted = self.ssh.accept() => match accepted {
                    Ok((stream, _)) => {
                        let handler = self.handler.clone();
                        clients.spawn(async move {
                            let _ = Agent::handle_client(handler, stream).await;
                        });
                    }
                    Err(e) => {
                        debug!("SSH socket accept failed: {e}");
                        break;
                    }
                },
                accepted = self.control.accept() => match accepted {
                    Ok((stream, _)) => {
                        let handler = self.handler.clone();
                        clients.spawn(async move {
                            let _ = handle_connection(handler, stream).await;
                        });
                    }
                    Err(e) => {
                        debug!("control socket accept failed: {e}");
                        break;
                    }
                },
            }
        }
        clients.abort_all();
        while clients.join_next().await.is_some() {}
    }
}
impl Drop for RusticaAgentRunner {
    fn drop(&mut self) {
        remove_owned_socket(&self.ssh_endpoint, self.ssh_device, self.ssh_inode);
    }
}

/// Request/response client for the version 1 control protocol.
pub struct ControlClient {
    endpoint: PathBuf,
}
impl ControlClient {
    pub fn new(endpoint: impl Into<PathBuf>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }
    pub async fn request(
        &self,
        op: &str,
        setting: Setting,
        value: Option<Value>,
    ) -> Result<SettingValue, ControlError> {
        let mut stream = UnixStream::connect(&self.endpoint).await?;
        let request = ClientRequest {
            version: PROTOCOL_VERSION,
            op,
            setting: setting.as_str(),
            value,
        };
        write_frame(
            &mut stream,
            &serde_json::to_vec(&request)
                .map_err(|_| ControlError::Protocol("could not encode request"))?,
        )
        .await?;
        let response: ClientResponse = serde_json::from_slice(&read_frame(&mut stream).await?)
            .map_err(|_| ControlError::Protocol("invalid JSON response"))?;
        if response.version != PROTOCOL_VERSION {
            return Err(ControlError::Protocol("unsupported response version"));
        }
        if !response.ok {
            let error = response
                .error
                .ok_or(ControlError::Protocol("error response without error"))?;
            return Err(ControlError::Remote {
                code: error.code,
                message: error.message,
            });
        }
        let value = response
            .value
            .ok_or(ControlError::Protocol("success response without value"))?;
        match (setting, value) {
            (Setting::DisableCertificate, Value::Bool(v)) => Ok(SettingValue::Bool(v)),
            (Setting::ConfigPath, Value::String(v)) => Ok(SettingValue::Path(PathBuf::from(v))),
            _ => Err(ControlError::Protocol("response value has wrong type")),
        }
    }
    pub async fn get(&self, setting: Setting) -> Result<SettingValue, ControlError> {
        self.request("get", setting, None).await
    }
    pub async fn set(
        &self,
        setting: Setting,
        value: SettingValue,
    ) -> Result<SettingValue, ControlError> {
        self.request("set", setting, Some(value.json())).await
    }
    pub async fn toggle_disable_certificate(&self) -> Result<bool, ControlError> {
        match self
            .request("toggle", Setting::DisableCertificate, None)
            .await?
        {
            SettingValue::Bool(value) => Ok(value),
            _ => unreachable!(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientResponse {
    version: u8,
    ok: bool,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    error: Option<ClientError>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientError {
    code: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::UpdatableConfiguration, CertificateConfig, CertificateState, PrivateKey, Signatory,
    };
    use sshcerts::ssh::KeyTypeKind;
    use std::collections::HashMap;
    use std::process::Command;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::sync::mpsc;

    fn test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rustica-control-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn test_handler(config_path: &Path) -> Arc<Handler> {
        fs::write(config_path, "version = 2\nservers = []\n").unwrap();
        let configuration = UpdatableConfiguration::new(config_path).unwrap();
        let certificate_options =
            CertificateConfig::from(configuration.get_configuration().options.clone());
        let private_key = PrivateKey::new(KeyTypeKind::Ed25519, "control-test").unwrap();
        Arc::new(Handler {
            certificate_state: tokio::sync::Mutex::new(CertificateState::new(
                configuration,
                certificate_options,
            )),
            pubkey: private_key.pubkey.clone(),
            signatory: Signatory::Direct(tokio::sync::Mutex::new(private_key)),
            identities: tokio::sync::Mutex::new(HashMap::new()),
            piv_identities: HashMap::new(),
            notification_function: None,
            certificate_priority: false,
            disable_certificate: AtomicBool::new(false),
            list_primary_certificate_only: false,
            fido_identity: None,
        })
    }

    fn metadata_identity(path: &Path) -> (u64, u64) {
        let metadata = fs::symlink_metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    }

    #[test]
    fn crash_recovery_runner_helper() {
        let Ok(ssh_endpoint) = std::env::var("RUSTICA_CONTROL_TEST_SSH_ENDPOINT") else {
            return;
        };
        let control_endpoint =
            PathBuf::from(std::env::var("RUSTICA_CONTROL_TEST_CONTROL_ENDPOINT").unwrap());
        let ready_marker =
            PathBuf::from(std::env::var("RUSTICA_CONTROL_TEST_READY_MARKER").unwrap());
        let config_path = PathBuf::from(std::env::var("RUSTICA_CONTROL_TEST_CONFIG_PATH").unwrap());

        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                let runner = RusticaAgentRunner::bind(
                    test_handler(&config_path),
                    ssh_endpoint,
                    Some(control_endpoint),
                )
                .unwrap();
                fs::write(ready_marker, b"ready").unwrap();
                let (_shutdown, shutdown_requests) = mpsc::channel(1);
                runner.run(shutdown_requests).await;
            });
    }

    #[test]
    fn derives_without_lossy_path_conversion() {
        assert_eq!(
            default_endpoint("/tmp/agent.sock"),
            PathBuf::from("/tmp/agent.sock.control/socket")
        );
    }

    #[tokio::test]
    async fn creates_private_endpoint_and_removes_only_its_socket() {
        let directory = test_dir("permissions");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = directory.join("socket");
        let listener = ControlListener::bind(&endpoint).unwrap();
        assert_eq!(fs::metadata(&directory).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&endpoint).unwrap().mode() & 0o777, 0o600);
        drop(listener);
        assert!(!endpoint.exists());
        assert!(directory.join("lock").exists());
        fs::remove_file(directory.join("lock")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn rejects_unsafe_directory_and_competing_holder() {
        let directory = test_dir("unsafe");
        fs::create_dir(&directory).unwrap();
        let endpoint = directory.join("socket");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ControlListener::bind(&endpoint).is_err());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let first = ControlListener::bind(&endpoint).unwrap();
        assert!(ControlListener::bind(&endpoint).is_err());
        drop(first);
        fs::remove_file(directory.join("lock")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn request_decoding_rejects_unknown_and_trailing_json_and_keeps_null_present() {
        assert!(serde_json::from_slice::<Request>(
            br#"{"version":1,"op":"get","setting":"config_path","extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<Request>(
            br#"{"version":1,"op":"get","setting":"config_path"} {}"#
        )
        .is_err());
        let null = serde_json::from_slice::<Request>(
            br#"{"version":1,"op":"toggle","setting":"disable_certificate","value":null}"#,
        )
        .unwrap();
        assert_eq!(null.value.0, Some(Value::Null));
    }

    #[tokio::test]
    async fn stale_socket_is_recovered_after_the_previous_holder_crashes() {
        let directory = test_dir("stale");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = directory.join("socket");
        let stale = UnixListener::bind(&endpoint).unwrap();
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)).unwrap();
        drop(stale);
        assert!(endpoint.exists());
        let recovered = ControlListener::bind(&endpoint).unwrap();
        drop(recovered);
        fs::remove_file(directory.join("lock")).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_reading_a_body() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_u32((MAX_FRAME_SIZE + 1) as u32).await.unwrap();
        assert!(matches!(
            read_frame(&mut server).await,
            Err(ControlError::Protocol(_))
        ));
    }

    #[tokio::test]
    async fn rejects_symlink_endpoint_and_lock_hardlink() {
        let directory = test_dir("links");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.join("target");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, directory.join("socket")).unwrap();
        assert!(ControlListener::bind(directory.join("socket")).is_err());
        fs::remove_file(directory.join("socket")).unwrap();
        fs::remove_file(directory.join("lock")).unwrap();
        std::fs::hard_link(&target, directory.join("lock")).unwrap();
        assert!(ControlListener::bind(directory.join("socket")).is_err());
        fs::remove_file(directory.join("lock")).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[tokio::test]
    async fn recovers_paired_sockets_after_a_process_is_killed_without_replacing_the_lock() {
        let directory = test_dir("crash-recovery");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let ssh_endpoint = directory.join("agent.sock");
        let control_directory = directory.join("control");
        let control_endpoint = control_directory.join("socket");
        let ready_marker = directory.join("ready");
        let config_path = directory.join("config.toml");

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "control::tests::crash_recovery_runner_helper"])
            .env("RUSTICA_CONTROL_TEST_SSH_ENDPOINT", &ssh_endpoint)
            .env("RUSTICA_CONTROL_TEST_CONTROL_ENDPOINT", &control_endpoint)
            .env("RUSTICA_CONTROL_TEST_READY_MARKER", &ready_marker)
            .env("RUSTICA_CONTROL_TEST_CONFIG_PATH", &config_path)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready_marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready_marker.exists(), "child runner did not become ready");

        let directory_identity = metadata_identity(&control_directory);
        let lock_identity = metadata_identity(&control_directory.join("lock"));
        assert!(RusticaAgentRunner::bind(
            test_handler(&directory.join("competing-config.toml")),
            &ssh_endpoint,
            Some(control_endpoint.clone()),
        )
        .is_err());
        assert!(ssh_endpoint.exists());
        assert!(control_endpoint.exists());

        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());

        let recovered = RusticaAgentRunner::bind(
            test_handler(&directory.join("recovered-config.toml")),
            &ssh_endpoint,
            Some(control_endpoint.clone()),
        )
        .unwrap();
        assert_eq!(metadata_identity(&control_directory), directory_identity);
        assert_eq!(
            metadata_identity(&control_directory.join("lock")),
            lock_identity
        );
        assert!(ssh_endpoint.exists());
        assert!(control_endpoint.exists());
        drop(recovered);

        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_active_clients_and_partial_startup_cleans_only_its_socket() {
        let directory = test_dir("runner-shutdown");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let ssh_endpoint = directory.join("agent.sock");
        let control_endpoint = directory.join("control/socket");
        let runner = RusticaAgentRunner::bind(
            test_handler(&directory.join("config.toml")),
            &ssh_endpoint,
            Some(control_endpoint.clone()),
        )
        .unwrap();
        let control_directory = control_endpoint.parent().unwrap().to_owned();
        let lock_identity = metadata_identity(&control_directory.join("lock"));
        let (shutdown, shutdown_requests) = mpsc::channel(1);
        let running = tokio::spawn(runner.run(shutdown_requests));

        let mut control_client = UnixStream::connect(&control_endpoint).await.unwrap();
        write_frame(
            &mut control_client,
            br#"{"version":1,"op":"get","setting":"disable_certificate"}"#,
        )
        .await
        .unwrap();
        let _ = read_frame(&mut control_client).await.unwrap();
        let mut ssh_client = UnixStream::connect(&ssh_endpoint).await.unwrap();
        ssh_client.write_all(&[0, 0, 0, 1, 11]).await.unwrap();
        let response_length = ssh_client.read_u32().await.unwrap() as usize;
        let mut response = vec![0; response_length];
        ssh_client.read_exact(&mut response).await.unwrap();

        shutdown.send(()).await.unwrap();
        running.await.unwrap();
        let mut byte = [0];
        assert_eq!(control_client.read(&mut byte).await.unwrap(), 0);
        assert_eq!(ssh_client.read(&mut byte).await.unwrap(), 0);
        assert!(!control_endpoint.exists());
        assert!(!ssh_endpoint.exists());
        assert_eq!(
            metadata_identity(&control_directory.join("lock")),
            lock_identity
        );

        let failed_ssh_endpoint = directory.join("failed-agent.sock");
        fs::write(&failed_ssh_endpoint, b"do not replace").unwrap();
        let failed_control_endpoint = directory.join("failed-control/socket");
        assert!(RusticaAgentRunner::bind(
            test_handler(&directory.join("failed-config.toml")),
            &failed_ssh_endpoint,
            Some(failed_control_endpoint.clone()),
        )
        .is_err());
        assert_eq!(fs::read(&failed_ssh_endpoint).unwrap(), b"do not replace");
        assert!(!failed_control_endpoint.exists());
        assert!(failed_control_endpoint
            .parent()
            .unwrap()
            .join("lock")
            .exists());

        fs::remove_file(failed_ssh_endpoint).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
