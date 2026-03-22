# Tests are part of the main module.
# Run from the project root with:
#
#   go test ./tests/...
#   go test ./tests/... -race -v
#   go test ./tests/controlplane/... -run TestIPToUint32
#
# The tests/controlplane package imports internal functions directly since
# they live in `package main`.  To make that work, the controlplane tests
# must be placed in the same package (package main) or use the exported
# surface only.  The types_test.go uses `package types_test` and imports
# the public types package normally.
#
# Quick run:
#   go test github.com/nsp/ddos-platform/tests/...
