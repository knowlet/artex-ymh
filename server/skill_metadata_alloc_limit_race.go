//go:build race

package server

// Race instrumentation adds per-allocation metadata; keep the same bytes/op guarantee
// without race but allow headroom when -race is enabled.
const skillMetadataBenchmarkAllocScale = 2
