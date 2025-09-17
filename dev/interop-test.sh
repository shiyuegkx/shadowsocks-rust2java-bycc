#!/bin/bash

# Shadowsocks Java Implementation Integration Test Script
# Tests Java client + server and optionally tests against rust implementation

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVER_PORT=18388
CLIENT_HTTP_PORT=18080
CLIENT_SOCKS_PORT=11080
PASSWORD="test-password-123"
METHOD="aes-256-gcm"

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

test_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
}

cleanup() {
    log_info "Cleaning up processes..."

    # Kill Java processes
    pkill -f "proxy-server.*shaded.jar" 2>/dev/null || true
    pkill -f "proxy-client.*shaded.jar" 2>/dev/null || true

    # Kill any rust shadowsocks if testing interop
    pkill -f "ssserver" 2>/dev/null || true
    pkill -f "sslocal" 2>/dev/null || true

    # Clean up temp files
    rm -f /tmp/ss-test-*.yaml
}

build_project() {
    log_info "Building Java implementation..."
    cd "$PROJECT_DIR"
    mvn clean package -DskipTests

    if [ ! -f "proxy-client/target/proxy-client-1.0.0-shaded.jar" ]; then
        log_error "Client JAR not found after build"
        exit 1
    fi

    if [ ! -f "proxy-server/target/proxy-server-1.0.0-shaded.jar" ]; then
        log_error "Server JAR not found after build"
        exit 1
    fi

    log_info "Build completed successfully"
}

create_configs() {
    # Create server config
    cat > /tmp/ss-test-server.yaml << EOF
server: "127.0.0.1"
server_port: $SERVER_PORT
password: "$PASSWORD"
method: "$METHOD"
timeout: 30
EOF

    # Create client config
    cat > /tmp/ss-test-client.yaml << EOF
server: "127.0.0.1"
server_port: $SERVER_PORT
local_address: "127.0.0.1"
local_port: $CLIENT_HTTP_PORT
password: "$PASSWORD"
method: "$METHOD"
timeout: 30
EOF
}

start_java_server() {
    log_info "Starting Java server on port $SERVER_PORT..."
    java -jar "$PROJECT_DIR/proxy-server/target/proxy-server-1.0.0-shaded.jar" \
        /tmp/ss-test-server.yaml > /tmp/ss-server.log 2>&1 &

    sleep 3

    if ! pgrep -f "proxy-server.*shaded.jar" > /dev/null; then
        log_error "Failed to start Java server"
        cat /tmp/ss-server.log
        return 1
    fi

    log_info "Java server started"
}

start_java_client() {
    log_info "Starting Java client (HTTP: $CLIENT_HTTP_PORT, SOCKS: 1080)..."
    java -jar "$PROJECT_DIR/proxy-client/target/proxy-client-1.0.0-shaded.jar" \
        /tmp/ss-test-client.yaml > /tmp/ss-client.log 2>&1 &

    sleep 3

    if ! pgrep -f "proxy-client.*shaded.jar" > /dev/null; then
        log_error "Failed to start Java client"
        cat /tmp/ss-client.log
        return 1
    fi

    log_info "Java client started"
}

test_http_proxy() {
    log_info "Testing HTTP proxy..."

    # Test HTTP request
    response=$(curl -s -x http://127.0.0.1:$CLIENT_HTTP_PORT http://httpbin.org/ip 2>/dev/null || echo "FAILED")

    if echo "$response" | grep -q "origin"; then
        test_pass "HTTP proxy test"
        echo "  Response: $(echo $response | head -c 100)..."
    else
        test_fail "HTTP proxy test"
        echo "  Error: Could not fetch through HTTP proxy"
    fi
}

test_https_proxy() {
    log_info "Testing HTTPS proxy (CONNECT tunnel)..."

    # Test HTTPS request
    response=$(curl -s -x http://127.0.0.1:$CLIENT_HTTP_PORT https://httpbin.org/get 2>/dev/null || echo "FAILED")

    if echo "$response" | grep -q "Host.*httpbin.org"; then
        test_pass "HTTPS proxy test"
        echo "  Response: $(echo $response | head -c 100)..."
    else
        test_fail "HTTPS proxy test"
        echo "  Error: Could not fetch through HTTPS proxy"
    fi
}

test_socks5_proxy() {
    log_info "Testing SOCKS5 proxy..."

    # Test SOCKS5 request
    response=$(curl -s --socks5 127.0.0.1:1080 http://httpbin.org/headers 2>/dev/null || echo "FAILED")

    if echo "$response" | grep -q "headers"; then
        test_pass "SOCKS5 proxy test"
        echo "  Response: $(echo $response | head -c 100)..."
    else
        test_fail "SOCKS5 proxy test"
        echo "  Error: Could not fetch through SOCKS5 proxy"
    fi
}

test_large_payload() {
    log_info "Testing large payload transfer..."

    # Download a larger file (1MB test file)
    curl -s -x http://127.0.0.1:$CLIENT_HTTP_PORT \
        -o /tmp/ss-test-download \
        http://www.ovh.net/files/1Mb.dat 2>/dev/null

    if [ -f /tmp/ss-test-download ]; then
        size=$(stat -f%z /tmp/ss-test-download 2>/dev/null || stat -c%s /tmp/ss-test-download 2>/dev/null)
        if [ "$size" -gt 900000 ]; then
            test_pass "Large payload test (${size} bytes)"
        else
            test_fail "Large payload test (incomplete: ${size} bytes)"
        fi
        rm -f /tmp/ss-test-download
    else
        test_fail "Large payload test (download failed)"
    fi
}

test_concurrent_connections() {
    log_info "Testing concurrent connections..."

    # Launch multiple requests in parallel
    success_count=0
    for i in {1..5}; do
        (curl -s -x http://127.0.0.1:$CLIENT_HTTP_PORT http://httpbin.org/delay/1 2>/dev/null && echo "OK" > /tmp/ss-test-concurrent-$i) &
    done

    # Wait for all to complete
    wait

    # Count successes
    for i in {1..5}; do
        if [ -f /tmp/ss-test-concurrent-$i ]; then
            ((success_count++))
            rm -f /tmp/ss-test-concurrent-$i
        fi
    done

    if [ $success_count -eq 5 ]; then
        test_pass "Concurrent connections test (5/5)"
    else
        test_fail "Concurrent connections test ($success_count/5)"
    fi
}

print_summary() {
    echo
    echo "================================"
    echo "Test Summary"
    echo "================================"
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}Some tests failed${NC}"
        return 1
    fi
}

# Main execution
main() {
    log_info "Starting Shadowsocks Java Implementation Tests"

    # Set up cleanup trap
    trap cleanup EXIT

    # Build project
    build_project

    # Create configs
    create_configs

    # Start servers
    start_java_server
    start_java_client

    # Run tests
    test_http_proxy
    test_https_proxy
    test_socks5_proxy
    test_large_payload
    test_concurrent_connections

    # Print summary
    print_summary
}

# Run main
main "$@"