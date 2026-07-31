#!/bin/bash
# Run integration tests for Rustica
#
# This works by setting up a Rustica server and RusticaAgent client then trying
# testing certificate pull functionality as well as SSH signing for logging
# into remote system.

cleanup_and_exit () {
    rm $SSH_AUTH_SOCK
    if [ -n "$AGENT_CONFIG" ]; then
        rm -f "$AGENT_CONFIG" "$AGENT_CONFIG.pre"
    fi
    docker kill rustica_test_ssh_server > /dev/null 2>&1
    docker rm rustica_test_ssh_server > /dev/null 2>&1
    exit $1
}

# mtls_key is the only "PRIVATE KEY" PEM block in an agent config (other keys
# are "OPENSSH PRIVATE KEY"). tr -d '\n' ignores line-wrap differences.
mtls_key_from_config () {
    sed -n '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/p' "$1" | tr -d '\n'
}

renewal_fail () {
    echo "FAIL: $1"
    kill $RUSTICA_PID
    wait $RUSTICA_PID > /dev/null 2>&1
    cleanup_and_exit 1
}

# Runs `immediate`, logging and failing via renewal_fail on error.
run_immediate () {
    if ./target/debug/rustica-agent-cli immediate --config "$AGENT_CONFIG" > "$1" 2>&1; then
        return 0
    fi
    cat "$1"
    renewal_fail "$2"
}


# Build Rustica and RusticaAgent
cargo build --features=all

# The agent rewrites its config in place when the server renews our mTLS
# access certificate, so work from a copy and leave the tracked example alone.
AGENT_CONFIG=$(mktemp /tmp/rustica_agent_config.XXXXXX)
cp examples/rustica_agent_local.toml "$AGENT_CONFIG"

# Build test SSH Server. This server trusts all the test keys in this folder as
# as well as the user key in rustica_local_file.toml. The reason we start up alt
# first is to run other tests on the manual key add functionality.
cd tests/ssh_server
docker build -t rustica_test_ssh_server:latest .
cd ../..

# Run test SSH Server
docker run --name rustica_test_ssh_server -p 2424:22 rustica_test_ssh_server:latest &

# Verify that Rustica is not running and that this should fail
if ./target/debug/rustica-agent-cli immediate --config "$AGENT_CONFIG" > /tmp/rustica_log 2>&1; then
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
if ./target/debug/rustica-agent-cli immediate --config "$AGENT_CONFIG" > /tmp/rustica_agent_log 2>&1; then
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
if ./target/debug/rustica-agent-cli immediate --config "$AGENT_CONFIG" --out /tmp/testing_cert > /dev/null 2>&1; then
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
./target/debug/rustica-agent-cli single --config "$AGENT_CONFIG" --socket $SOCKET_PATH > /dev/null 2>&1 &
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
./target/debug/rustica-agent-cli single --config "$AGENT_CONFIG" --socket $SOCKET_PATH > /dev/null 2>&1 & 
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
./target/debug/rustica-agent-cli single --config "$AGENT_CONFIG" --socket $SOCKET_PATH > /dev/null 2>&1 & 
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

./target/debug/rustica-agent-cli single --config "$AGENT_CONFIG" --socket $SOCKET_PATH > /dev/null 2>&1 &
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

# Stop the single-mode agent; keep the Rustica server running (its config
# forces an mTLS renewal on every request, which we test next).
kill $AGENT_PID
wait $AGENT_PID > /dev/null 2>&1

# Renewal test: server renews the mTLS access cert, reuses our existing key
# via the CSR we send, and the renewed cert is accepted on the next request.
cp "$AGENT_CONFIG" "$AGENT_CONFIG.pre"
PRE_MTLS_KEY=$(mtls_key_from_config "$AGENT_CONFIG.pre")
[ -z "$PRE_MTLS_KEY" ] && renewal_fail "Could not find an mTLS private key in the agent configuration"

run_immediate /tmp/rustica_renewal_log "Could not pull a certificate from Rustica during renewal test"
echo "PASS: Successfully pulled a certificate while renewal was expected"

if grep -q "Your access credentials to the server have been updated" /tmp/rustica_renewal_log; then
    echo "PASS: Rustica renewed our mTLS access certificate"
else
    renewal_fail "Rustica did not renew our mTLS access certificate when it should have"
fi

if cmp -s "$AGENT_CONFIG" "$AGENT_CONFIG.pre"; then
    renewal_fail "Agent config was not updated with the renewed mTLS access certificate"
else
    echo "PASS: Agent config was updated with the renewed mTLS access certificate"
fi

POST_MTLS_KEY=$(mtls_key_from_config "$AGENT_CONFIG")
if [ -n "$POST_MTLS_KEY" ] && [ "$PRE_MTLS_KEY" = "$POST_MTLS_KEY" ]; then
    echo "PASS: Renewal reused our existing mTLS private key"
else
    renewal_fail "Renewal replaced our mTLS private key instead of reusing it"
fi

# A mismatched key here would fail the mTLS handshake, so success also
# confirms the renewed certificate matches the retained key.
run_immediate /tmp/rustica_renewed_log "Renewed mTLS access certificate was rejected by Rustica"
echo "PASS: Renewed mTLS access certificate was accepted by Rustica"

rm -f "$AGENT_CONFIG.pre"
kill $RUSTICA_PID
wait $RUSTICA_PID > /dev/null 2>&1

# No-renewal test: a cert nowhere near expiry shouldn't be renewed even with
# a short renewal window.
./target/debug/rustica --config tests/test_configs/rustica_local_file_no_renewal.toml > /dev/null 2>&1 &
RUSTICA_PID=$!
sleep 2

cp "$AGENT_CONFIG" "$AGENT_CONFIG.pre"
run_immediate /tmp/rustica_no_renewal_log "Could not pull a certificate from Rustica during no-renewal test"
echo "PASS: Successfully pulled a certificate while no renewal was expected"

if grep -q "Your access credentials to the server have been updated" /tmp/rustica_no_renewal_log; then
    renewal_fail "Rustica renewed our mTLS access certificate when it should not have"
else
    echo "PASS: Rustica did not renew our mTLS access certificate"
fi

if cmp -s "$AGENT_CONFIG" "$AGENT_CONFIG.pre"; then
    echo "PASS: Agent config was left unchanged when no renewal was needed"
else
    renewal_fail "Agent config changed even though no renewal should have occurred"
fi

kill $RUSTICA_PID
wait $RUSTICA_PID > /dev/null 2>&1
cleanup_and_exit 0