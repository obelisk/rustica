#!/bin/zsh
PACKAGE=rustica-agent
BINARY=rustica-agent

# Remove the old version of the package
rm RusticaAgent.pkg RusticaAgentInterim.pkg

# Build universal application binary
cd ..
cargo build --package ${PACKAGE} --release
cargo build --package ${PACKAGE} --release --target x86_64-apple-darwin
mkdir -p resources/root/usr/local/bin/
lipo -create target/release/${BINARY} target/x86_64-apple-darwin/release/${PACKAGE} -output resources/root/usr/local/bin/rustica-agent

# Codesign the binary
codesign --options=runtime --timestamp -f -s "5QY" --identifier "io.confurious.RusticaAgent" resources/root/usr/local/bin/rustica-agent
echo "Built ${BINARY}"

# Build the package that installs the application
pkgbuild --sign 5q --root resources/root --identifier io.confurious.RusticaAgent --install-location / --timestamp resources/RusticaAgentInterim.pkg

# Build the final product
productbuild --sign 5Q --package resources/RusticaAgentInterim.pkg resources/RusticaAgent.pkg

# Clean up artifacts
rm -rf RusticaAgentInterim.pkg root/
