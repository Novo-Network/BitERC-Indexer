#!/bin/bash
set -xe
export RUST_LOG=debug
export RUST_BACKTRACE=full

cargo r --bin novolited -- \
  --config=./config.toml \
  --datadir="./data" \
  --listen="0.0.0.0" \
  --http-port=8545 \
  --ws-port=8546
