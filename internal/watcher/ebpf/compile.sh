#!/bin/bash
# Compile eBPF program in a Docker container
# Run from the ebpf directory: ./compile.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building eBPF program in Docker container..."

docker run --rm \
  -v "${SCRIPT_DIR}:/src" \
  -w /src \
  golang:1.23-bookworm \
  bash -c '
    set -e
    echo "Installing clang and libbpf..."
    apt-get update -qq
    apt-get install -y -qq clang llvm libbpf-dev linux-headers-generic 2>/dev/null || \
    apt-get install -y -qq clang llvm libbpf-dev 2>/dev/null

    echo "Installing bpf2go..."
    go install github.com/cilium/ebpf/cmd/bpf2go@v0.17.1

    echo "Compiling BPF program..."
    export PATH=$PATH:$(go env GOPATH)/bin
    export GOPACKAGE=ebpf

    # Generate the Go bindings (we parse conn_event manually in Go, so no -type flag)
    bpf2go -cc clang -target bpfel,bpfeb connect connect.c -- -I. -O2 -g -Wall

    echo "Done! Generated files:"
    ls -la connect_*.go connect_*.o 2>/dev/null || echo "Note: .o files are embedded in .go files"
  '

echo "eBPF compilation complete!"
echo "Generated files in ${SCRIPT_DIR}:"
ls -la "${SCRIPT_DIR}"/connect_*.go 2>/dev/null || echo "Check for errors above"
