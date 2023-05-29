# Exit when any command fails
set -e

## Full Verification
## Parse keys, generate certificates
cargo run --features=all --bin rustica -- -vv --config examples/rustica_external.toml
cargo run --features=all --bin rustica -- -vv --config examples/rustica_local_file.toml
cargo run --features=all --bin rustica -- -vv --config examples/rustica_local_file_alt.toml
cargo run --features=all --bin rustica -- -vv --config examples/rustica_local_file_multi.toml
cargo run --features=all --bin rustica -- -vv --config examples/rustica_local_file_with_influx.toml
cargo run --features=all --bin rustica -- -vv --config examples/rustica_local_file_with_splunk.toml
cargo run --features=all --bin rustica -- -vv --config examples/rustica_local_file_with_webhook.toml

## Configuration Structure Verification
## Only verify that the example configurations parse correctly. This allows us
## to test Yubikey and AmazonKMS configurations without having them connected
## or validly configured
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_amazonkms.toml
cargo run --features=all --bin rustica -- -v --config examples/rustica_local_yubikey.toml