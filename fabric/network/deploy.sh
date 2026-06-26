#!/usr/bin/env bash
# Bring up the fabric-samples test-network and deploy the agent-delegation
# chaincode (TypeScript). Run on a machine with Docker, the Fabric binaries,
# and a cloned fabric-samples (see ../README.md for prerequisites).
set -euo pipefail

# Path to a cloned https://github.com/hyperledger/fabric-samples
FABRIC_SAMPLES="${FABRIC_SAMPLES:-$HOME/fabric-samples}"
CC_NAME="${CHAINCODE_NAME:-agentdelegation}"
CHANNEL="${CHANNEL_NAME:-mychannel}"
CC_PATH="$(cd "$(dirname "$0")/../chaincode" && pwd)"

if [[ ! -d "$FABRIC_SAMPLES/test-network" ]]; then
  echo "ERROR: fabric-samples test-network not found at $FABRIC_SAMPLES" >&2
  echo "Clone it and set FABRIC_SAMPLES, or see ../README.md." >&2
  exit 1
fi

cd "$FABRIC_SAMPLES/test-network"

echo ">> Tearing down any previous network"
./network.sh down

echo ">> Starting network and creating channel '$CHANNEL'"
./network.sh up createChannel -c "$CHANNEL" -ca

echo ">> Deploying chaincode '$CC_NAME' (typescript) from $CC_PATH"
./network.sh deployCC \
  -ccn "$CC_NAME" \
  -ccp "$CC_PATH" \
  -ccl typescript

echo ">> Done. Chaincode '$CC_NAME' is live on channel '$CHANNEL'."
echo ">> Now run the benchmark:  cd ../bench && npm install && node bench.js"
