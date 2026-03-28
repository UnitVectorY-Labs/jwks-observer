
# Commands for jwks-observer
default:
  @just --list
# Build jwks-observer with Go
build:
  go build ./...

# Run tests for jwks-observer with Go
test:
  go clean -testcache
  go test ./...