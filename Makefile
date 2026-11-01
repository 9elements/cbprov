GO          ?= go
STATICCHECK ?= honnef.co/go/tools/cmd/staticcheck@v0.8.2
FIXTURES    ?=
CBPROV_FIXTURES ?= $(CURDIR)/.cache/fixtures

.PHONY: all build test fixtures e2e lint

all: build

build:
	$(GO) build -o cbprov ./cmd/cbprov

test:
	$(GO) test -race ./...

# Builds coreboot images in the coreboot-sdk container; FIXTURES="q35 ..." limits the set.
fixtures:
	test/fixtures/build.sh $(FIXTURES)

e2e:
	CBPROV_FIXTURES=$(CBPROV_FIXTURES) $(GO) test -count=1 -tags e2e ./test/qemu/ ./test/e2e/

lint:
	@out=$$(gofmt -l $$(git ls-files -co --exclude-standard '*.go')); \
		if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	$(GO) vet -tags e2e ./test/...
	$(GO) run $(STATICCHECK) ./...
	$(GO) run $(STATICCHECK) -tags e2e ./test/...
