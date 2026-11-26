CGO_ENABLED ?= 0
BIN         ?= bin/hook-vault
VERSION     ?= 0.5.0-dev

.PHONY: build test test-integration vet fmt lint clean

build:
	CGO_ENABLED=$(CGO_ENABLED) go build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/hook-vault

test:
	CGO_ENABLED=$(CGO_ENABLED) go test ./...

# Needs a disposable database: the suite drops and recreates the public schema.
test-integration:
	test -n "$(HOOKVAULT_TEST_DATABASE_URL)" || (echo "set HOOKVAULT_TEST_DATABASE_URL"; exit 1)
	CGO_ENABLED=$(CGO_ENABLED) go test ./... -count=1 -v

vet:
	CGO_ENABLED=$(CGO_ENABLED) go vet ./...

fmt:
	gofmt -l -w .

lint:
	golangci-lint run

clean:
	rm -rf bin
