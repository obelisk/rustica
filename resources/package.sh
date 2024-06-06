#!/bin/zsh
export X86_64_APPLE_DARWIN_OPENSSL_LIB_DIR=/usr/local/Cellar/openssl@3/3.2.0/lib/
export X86_64_APPLE_DARWIN_OPENSSL_INCLUDE_DIR=/usr/local/Cellar/openssl@3/3.2.0/include/
export OPENSSL_STATIC=1

BINARY=rustica-agent-cli

# Remove the old version of the package
rm RusticaAgent.pkg RusticaAgentInterim.pkg

# Build universal application binary
cd ..
cargo build --bin ${BINARY} --release
cargo build --bin ${BINARY} --release --target x86_64-apple-darwin
mkdir -p resources/root/usr/local/bin/
lipo -create target/release/${BINARY} target/x86_64-apple-darwin/release/${BINARY} -output resources/root/usr/local/bin/rustica-agent-cli

cargo build --bin ${BINARY} --release --no-default-features  --features "ctap2_hid"
cargo build --bin ${BINARY} --release --no-default-features --features "ctap2_hid" --target x86_64-apple-darwin
mkdir -p resources/root/usr/local/bin/
lipo -create target/release/${BINARY} target/x86_64-apple-darwin/release/${BINARY} -output resources/root/usr/local/bin/rustica-agent-cli-ctap2

# Codesign the binary
codesign --options=runtime --timestamp -f -s "5QY" --identifier "io.confurious.RusticaAgent" resources/root/usr/local/bin/rustica-agent
codesign --options=runtime --timestamp -f -s "5QY" --identifier "io.confurious.RusticaAgent" resources/root/usr/local/bin/rustica-agent-ctap2


echo "Done!"

# Use the below if you need to build a package

# # Build the package that installs the application
# pkgbuild --sign 5q --root resources/root --identifier io.confurious.RusticaAgent --install-location / --timestamp resources/RusticaAgentInterim.pkg

# # Build the final product
# productbuild --sign 5Q --package resources/RusticaAgentInterim.pkg resources/RusticaAgent.pkg

# # Clean up artifacts
# rm -rf RusticaAgentInterim.pkg root/
