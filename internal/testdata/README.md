# testdata

Deterministic test fixtures for the SPV verifier. Generated from a fixed
Ed25519 seed so test runs are reproducible and CI does not depend on live
network state.

Fixtures land here in Phase 1 (header verifier MVP). See
`internal/testdata/gen_test.go` (`go generate ./internal/testdata`).
