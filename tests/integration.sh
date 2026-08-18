#!/bin/bash
# Run integration tests for Rustica
#
# This works by setting up a Rustica server and RusticaAgent client then trying
# testing certificate pull functionality as well as SSH signing for logging
# into remote system.

cleanup_and_exit () {
    rm $SSH_AUTH_SOCK
    docker kill rustica_test_ssh_server > /dev/null 2>&1
    docker rm rustica_test_ssh_server > /dev/null 2>&1
    exit $1
}


# Build Rustica and RusticaAgent
cargo build --features=all

# Build test SSH Server. This server trusts all the test keys in this folder as
# as well as the user key in rustica_local_file.toml. The reason we start up alt
# first is to run other tests on the manual key add functionality.
cd tests/ssh_server
docker build -t rustica_test_ssh_server:latest .
cd ../..

# Run test SSH Server
docker run --name rustica_test_ssh_server -p 2424:22 rustica_test_ssh_server:latest &

# Verify that Rustica is not running and that this should fail
if ./target/debug/rustica-agent-cli immediate --config examples/rustica_agent_local.toml > /tmp/rustica_log 2>&1; then
    echo "FAIL: Some other Rustica instance is running!"
    exit 1
else
    echo "PASS: No other Rustica instance appears to be running...starting one"
fi

# Start a Rustica Server
./target/debug/rustica --config tests/test_configs/rustica_local_file_alt.toml > /dev/null 2>&1 &
RUSTICA_PID=$!
sleep 2

# Test that we can fetch a certificate
if ./target/debug/rustica-agent-cli immediate --config examples/rustica_agent_local.toml > /tmp/rustica_agent_log 2>&1; then
    echo "PASS: Successfully pulled a certificate from Rustica"
else 
    echo "FAIL: Could not pull a certificate from Rustica"
    echo "Rustica Log:"
    cat /tmp/rustica_log
    echo ""
    echo "Rustica Agent Log"
    cat /tmp/rustica_agent_log
    cleanup_and_exit 1
fi

# Test that we can fetch a certificate and write it to a file
if ./target/debug/rustica-agent-cli immediate --config examples/rustica_agent_local.toml --out /tmp/testing_cert > /dev/null 2>&1; then
    echo "PASS: Successfully saved a certificate to a file"
    if ssh-keygen -Lf /tmp/testing_cert > /dev/null; then
        echo "PASS: Validated ssh-keygen parses saved certificate"
        rm /tmp/testing_cert
    else
        echo "FAIL: ssh-keygen could not read the output certificate successfully"
        cleanup_and_exit 1
    fi
else 
    echo "FAIL: Could not pull a certificate from Rustica"
    cleanup_and_exit 1
fi

# Generate random socket
SOCKET_RND=$(head -n 5 /dev/urandom | shasum | head -c 10)
SOCKET_PATH="/tmp/rustica_agent_$SOCKET_RND"

echo "PASS: Using the following socket path for this test run: $SOCKET_PATH"

# Start RusticaAgent
./target/debug/rustica-agent-cli single --config examples/rustica_agent_local.toml --socket $SOCKET_PATH > /dev/null 2>&1 &
AGENT_PID=$!
sleep 2

chmod 600 tests/test_ec256
chmod 600 tests/test_ec384
chmod 600 tests/test_ed25519

SSH_AUTH_SOCK="$SOCKET_PATH"
export SSH_AUTH_SOCK;

if ssh-add tests/test_ec256 > /dev/null 2>&1; then
    echo "PASS: Added EC256 private key to RusticaAgent"
else
    echo "FAIL: Could not add EC256 private key to RusticaAgent"
    cleanup_and_exit 1
fi


if ssh -o StrictHostKeyChecking=no testuser@localhost -p2424 -t 'exit' > /dev/null 2>&1; then
    echo "PASS: RusticaAgent used manually added EC256 to connect to SSH Server"
else
    echo "Fail: RusticaAgent failed using manually added EC256 to connect to SSH Server"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

# Restart RusticaAgent because it doesn't support key removal at this time
kill $AGENT_PID
wait $AGENT_PID 2>/dev/null
rm $SSH_AUTH_SOCK
./target/debug/rustica-agent-cli single --config examples/rustica_agent_local.toml --socket $SOCKET_PATH > /dev/null 2>&1 & 
AGENT_PID=$!
sleep 2

if ssh-add tests/test_ec384 > /dev/null 2>&1; then
    echo "PASS: Added EC384 private key to RusticaAgent"
else
    echo "FAIL: Could not add EC384 private key to RusticaAgent"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

if ssh -o StrictHostKeyChecking=no testuser@localhost -p2424 -t 'exit' > /dev/null 2>&1; then
    echo "PASS: RusticaAgent used manually added EC384 to connect to SSH Server"
else
    echo "Fail: RusticaAgent failed using manually added EC384 to connect to SSH Server"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

# Restart RusticaAgent because it doesn't support key removal at this time
kill $AGENT_PID
wait $AGENT_PID 2>/dev/null
rm $SSH_AUTH_SOCK
./target/debug/rustica-agent-cli single --config examples/rustica_agent_local.toml --socket $SOCKET_PATH > /dev/null 2>&1 & 
AGENT_PID=$!
sleep 2

if ssh-add tests/test_ed25519 > /dev/null 2>&1; then
    echo "PASS: Added Ed25519 private key to RusticaAgent"
else
    echo "FAIL: Could not add Ed25519 private key to RusticaAgent"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

if ssh -o StrictHostKeyChecking=no testuser@localhost -p2424 -t 'exit' > /dev/null 2>&1; then
    echo "PASS: RusticaAgent used manually added Ed25519 to connect to SSH Server"
else
    echo "Fail: RusticaAgent failed using manually added Ed25519 to connect to SSH Server"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

# Restart RusticaAgent because it doesn't support key removal at this time
rm $SSH_AUTH_SOCK
kill $AGENT_PID $RUSTICA_PID
wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1

./target/debug/rustica --config tests/test_configs/rustica_local_file.toml > /dev/null 2>&1 &
RUSTICA_PID=$!
sleep 2

./target/debug/rustica-agent-cli single --config examples/rustica_agent_local.toml --socket $SOCKET_PATH > /dev/null 2>&1 &
AGENT_PID=$!
sleep 2

if ssh -o StrictHostKeyChecking=no testuser@localhost -p2424 -t 'exit' > /dev/null 2>&1; then
    echo "PASS: RusticaAgent used Rustica server to connect to SSH Server"
else
    echo "Fail: RusticaAgent failed using Rustica server to connect to SSH Server"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

# Positive control: the default agent advertises the certificate
if ssh-add -L | grep -q "cert-v01@openssh.com"; then
    echo "PASS: Certificate is advertised by default"
else
    echo "FAIL: Certificate missing from default agent listing"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

# Restart RusticaAgent with --priority to check certificate ordering
kill $AGENT_PID
wait $AGENT_PID 2>/dev/null
rm $SSH_AUTH_SOCK
./target/debug/rustica-agent-cli single --config examples/rustica_agent_local.toml --socket $SOCKET_PATH --priority > /dev/null 2>&1 &
AGENT_PID=$!
sleep 2

if ssh-add -L | head -n 1 | grep -q "cert-v01@openssh.com"; then
    echo "PASS: Certificate listed first with --priority"
else
    echo "FAIL: Certificate not listed first with --priority"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
fi

# Restart RusticaAgent with certificates disabled
kill $AGENT_PID
wait $AGENT_PID 2>/dev/null
rm $SSH_AUTH_SOCK
./target/debug/rustica-agent-cli single --config examples/rustica_agent_local.toml --socket $SOCKET_PATH --disable-certificate > /dev/null 2>&1 &
AGENT_PID=$!
sleep 2

if ssh-add -L | grep -q "cert-v01@openssh.com"; then
    echo "FAIL: Certificate advertised despite --disable-certificate"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
else
    echo "PASS: Certificate not advertised with --disable-certificate"
fi

# The test server only trusts the CA for this key, so the connection must
# fail without the certificate. Success here would mean the certificate is
# still being offered (OpenSSH 10.5+ always prefers certificates when the
# agent lists one).
if ssh -o StrictHostKeyChecking=no testuser@localhost -p2424 -t 'exit' > /dev/null 2>&1; then
    echo "FAIL: SSH succeeded despite --disable-certificate"
    kill $AGENT_PID $RUSTICA_PID
    wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
else
    echo "PASS: SSH correctly fails without certificate (--disable-certificate)"
fi

kill $AGENT_PID $RUSTICA_PID
wait $AGENT_PID $RUSTICA_PID > /dev/null 2>&1
cleanup_and_exit 0