#!/bin/zsh

# Script to run the AWS proxy and test with curl

PROXY_LOG_FILE="proxy_log.txt"
CURL_LOG_FILE="curl_log.txt"
# Use $HOME for reliable path expansion in scripts
CERT_PATH="$HOME/.aws-proxy/certs/mitm.pem"
PROXY_URL="http://127.0.0.1:8080"
TARGET_URL="https://example.com"

# Clear previous logs
echo "" > $PROXY_LOG_FILE
echo "" > $CURL_LOG_FILE

echo "Starting AWS Proxy in the background (logging to $PROXY_LOG_FILE)..."
poetry run aws-proxy > $PROXY_LOG_FILE 2>&1 & WPID=$!

# Wait for the proxy to start (adjust sleep time if needed)
sleep 3

echo "Running curl test via proxy (logging to $CURL_LOG_FILE)..."
curl --proxy $PROXY_URL $TARGET_URL -v --cacert $CERT_PATH > $CURL_LOG_FILE 2>&1

CURL_EXIT_CODE=$?

echo "Stopping AWS Proxy (PID: $WPID)..."
# Check if the process exists before trying to kill it
if ps -p $WPID > /dev/null; then
   kill $WPID
   # Wait a moment for the process to terminate
   sleep 0.5
   # Force kill if it didn't terminate gracefully (optional)
   # if ps -p $WPID > /dev/null; then
   #    echo "Proxy did not terminate gracefully, forcing kill..."
   #    kill -9 $WPID
   # fi
else
   echo "Proxy process $WPID not found (already stopped or failed to start?)."
fi

echo "Curl command exited with code: $CURL_EXIT_CODE"
echo "Test complete. Logs are in $PROXY_LOG_FILE and $CURL_LOG_FILE."

exit $CURL_EXIT_CODE
