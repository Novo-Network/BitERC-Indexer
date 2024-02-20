#!/bin/bash
set -xe
export RUST_LOG=info
export RUST_BACKTRACE=full

cargo r --bin novolited -- \
  --btc-url="http://127.0.0.1:18443" \
  --username="admin1" \
  --password="123" \
  --chain-id=65535 \
  --datadir="./data/vsdb" \
  --da-file-path="./data/da" \
  --listen="0.0.0.0" \
  --http-port=8545 \
  --ws-port=8546
