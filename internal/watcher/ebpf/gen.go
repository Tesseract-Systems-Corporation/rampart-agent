// Package ebpf contains the eBPF connection tracer
package ebpf

// To generate the eBPF bytecode and Go loader, run on Linux with clang installed:
//   cd internal/watcher/ebpf && go generate
// Or from project root:
//   go generate ./internal/watcher/ebpf/...

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type conn_event connect connect.c -- -I. -O2 -g -Wall
