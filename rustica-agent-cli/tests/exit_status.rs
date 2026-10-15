use std::process::Command;

#[test]
fn configuration_errors_fail_on_stderr() {
    let missing_config = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/missing-config.toml");
    assert!(!std::path::Path::new(missing_config).exists());

    for (path, expected_error) in [
        (missing_config, "CouldNotReadConfigurationFile"),
        ("/dev/null", "BadConfiguration"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rustica-agent-cli"))
            .args(["immediate", "--config", path])
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(1), "config: {path}");
        assert!(output.stdout.is_empty(), "config: {path}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected_error),
            "config: {path}, stderr: {stderr}"
        );
    }
}

#[test]
fn no_arguments_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustica-agent-cli"))
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}
