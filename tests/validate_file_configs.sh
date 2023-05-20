# Exit when any command fails
set -e

cargo run --features=all --bin rustica -- -v --config examples/rustica_external.toml
#cargo run --features=all --bin rustica -- -v --config examples/rustica_local_amazonkms.toml
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_file.toml
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_file_alt.toml
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_file_multi.toml
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_file_with_influx.toml
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_file_with_splunk.toml
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_file_with_webhook.toml
#cargo run --features=all --bin rustica -- -v --config examples/rustica_local_yubikey.toml