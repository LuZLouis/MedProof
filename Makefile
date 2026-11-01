.PHONY: build test smoke

build:
	go build ./cmd/medproof

test:
	go test ./...

smoke:
	go run ./cmd/medproof smoke
