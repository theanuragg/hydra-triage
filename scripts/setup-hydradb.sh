#!/usr/bin/env bash
# Brings up a single local HydraDB node for hydra-triage to talk to.
# Lifted directly from https://github.com/hydra-db/hydradb#run-a-local-server
# — run this from inside a checkout of that repo, not from hydra-triage.
set -euo pipefail

mkdir -p .hydradb/store .hydradb/cache
printf '%s\n' 'local-development-token-32-bytes' > .hydradb/auth-token

export CLOUD_PROVIDER=local
export LOCAL_PATH="$PWD/.hydradb/store"
export GRAPH_NAMESPACE=default
export GRAPH_ID=default
export GRAPH_CELL_ID=cell-0
export GRAPH_CELLS=cell-0
export GRAPH_NODE_ID=node-0
export GRAPH_BOLT_NODE_ADDRESSES=node-0=127.0.0.1:7687
export GRAPH_ADVERTISED_BOLT_ADDR=127.0.0.1:7687
export GRAPH_DATA_CACHE_DIR="$PWD/.hydradb/cache"
export GRAPH_AUTH_TOKEN_FILE="$PWD/.hydradb/auth-token"
export GRAPH_ALLOW_PLAINTEXT=true
export RUST_MIN_STACK=33554432

if command -v brew >/dev/null; then
  export BINDGEN_EXTRA_CLANG_ARGS="-I$(brew --prefix)/include"
  export LIBRARY_PATH="$(brew --prefix)/lib"
fi

echo "Starting graph-node on :8443 (HTTP) / :7687 (Bolt) / :9090 (admin) ..."
cargo run --locked --features server-runtime --bin graph-node
