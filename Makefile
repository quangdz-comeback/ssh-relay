BINARY := relay
GO ?= go

.PHONY: build test race vet lint e2e clean release

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$$(git describe --tags --always 2>/dev/null || echo dev)" -o $(BINARY) ./cmd/relay

test:
	$(GO) test -timeout 300s ./...

race:
	$(GO) test -race -timeout 300s ./...

vet:
	$(GO) vet ./...

lint: vet
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest ./... || true

e2e: build
	bash test/e2e/run.sh

release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o relay-linux-amd64 ./cmd/relay
	CGO_ENABLED=0 GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o relay-linux-arm64 ./cmd/relay

clean:
	rm -f $(BINARY) relay-linux-amd64 relay-linux-arm64
