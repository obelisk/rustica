use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct AgentProcess(Child);

impl Drop for AgentProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_rustica-agent-cli")
}
fn temp_dir() -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = env::temp_dir().join(format!("rustica-cli-settings-{}-{n}", std::process::id()));
    fs::create_dir(&p).unwrap();
    p
}
fn config(path: &Path) {
    fs::write(path, "version = 2\nservers = []\n").unwrap();
}
fn run(dir: &Path, args: &[&str], ssh: Option<&Path>) -> std::process::Output {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(dir);
    if let Some(ssh) = ssh {
        cmd.env("SSH_AUTH_SOCK", ssh);
    } else {
        cmd.env_remove("SSH_AUTH_SOCK");
    }
    cmd.output().unwrap()
}

fn start_agent(cfg: &Path, key: &Path, socket: &Path, control: &Path) -> AgentProcess {
    let child = AgentProcess(
        Command::new(binary())
            .args([
                "single",
                "--config",
                cfg.to_str().unwrap(),
                "--file",
                key.to_str().unwrap(),
                "--socket",
                socket.to_str().unwrap(),
                "--disable-certificate",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if control.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    child
}

#[test]
fn settings_commands_use_real_control_socket_and_reset_after_sigterm() {
    let dir = temp_dir();
    let socket = dir.join("agent.sock");
    let control = PathBuf::from(format!("{}.control/socket", socket.display()));
    let cfg = dir.join("config.toml");
    let replacement = dir.join("replacement.toml");
    let invalid = dir.join("invalid.toml");
    config(&cfg);
    config(&replacement);
    fs::write(&invalid, "not toml").unwrap();
    let key = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/test_ed25519");
    let mut child = start_agent(&cfg, &key, &socket, &control);
    assert!(socket.exists() && control.exists());
    assert!(
        !run(&dir, &["settings", "get", "disable_certificate"], None)
            .status
            .success()
    );
    assert!(!run(
        &dir,
        &[
            "settings",
            "--control-socket",
            "/tmp/rustica-missing-control",
            "get",
            "disable_certificate"
        ],
        None
    )
    .status
    .success());
    assert_eq!(
        run(
            &dir,
            &["settings", "get", "disable_certificate"],
            Some(&socket)
        )
        .stdout,
        b"true\n"
    );
    assert_eq!(
        run(
            &dir,
            &[
                "settings",
                "--control-socket",
                control.to_str().unwrap(),
                "get",
                "config_path"
            ],
            None
        )
        .stdout,
        format!("\"{}\"\n", cfg.display()).into_bytes()
    );
    assert_eq!(
        run(
            &dir,
            &["settings", "set", "disable_certificate", "false"],
            Some(&socket)
        )
        .stdout,
        b"false\n"
    );
    assert_eq!(
        run(
            &dir,
            &["settings", "toggle", "disable_certificate"],
            Some(&socket)
        )
        .stdout,
        b"true\n"
    );
    let bad_bool = run(
        &dir,
        &["settings", "set", "disable_certificate", "yes"],
        Some(&socket),
    );
    assert!(!bad_bool.status.success());
    assert_eq!(
        run(
            &dir,
            &["settings", "set", "config_path", "replacement.toml"],
            Some(&socket)
        )
        .stdout,
        format!("\"{}\"\n", replacement.display()).into_bytes()
    );
    let bad_path = run(
        &dir,
        &["settings", "set", "config_path", invalid.to_str().unwrap()],
        Some(&socket),
    );
    assert!(!bad_path.status.success());
    assert_eq!(
        run(&dir, &["settings", "get", "config_path"], Some(&socket)).stdout,
        format!("\"{}\"\n", replacement.display()).into_bytes()
    );
    let changed = run(
        &dir,
        &["settings", "set", "disable_certificate", "false"],
        Some(&socket),
    );
    assert!(changed.status.success());
    assert_eq!(changed.stdout, b"false\n");
    Command::new("kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()
        .unwrap();
    child.0.wait().unwrap();
    assert!(!socket.exists() && !control.exists());
    let mut restarted = start_agent(&cfg, &key, &socket, &control);
    assert_eq!(
        run(
            &dir,
            &["settings", "get", "disable_certificate"],
            Some(&socket)
        )
        .stdout,
        b"true\n"
    );
    assert_eq!(
        run(&dir, &["settings", "get", "config_path"], Some(&socket)).stdout,
        format!("\"{}\"\n", cfg.display()).into_bytes()
    );
    Command::new("kill")
        .args(["-TERM", &restarted.0.id().to_string()])
        .status()
        .unwrap();
    restarted.0.wait().unwrap();
    fs::remove_dir_all(dir).unwrap();
}
