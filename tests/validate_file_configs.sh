# Exit when any command fails
set -e

cargo run --bin rustica -- -v --config examples/rustica_external.toml
cargo run --bin rustica -- -v --config examples/rustica_local_file.toml
cargo run --bin rustica -- -v --config examples/rustica_local_file_alt.toml
cargo run --bin rustica -- -v --config examples/rustica_local_file_multi.toml
cargo run --bin rustica -- -v --config examples/rustica_local_file_with_influx.toml
cargo run --bin rustica -- -v --config examples/rustica_local_file_with_splunk.toml
cargo run --bin rustica -- -v --config examples/rustica_local_file_with_webhook.toml