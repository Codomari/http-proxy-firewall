.PHONY: build install test test-install race vet fmt check

DESTDIR ?=

build:
	go build -trimpath -o bin/proxy-firewall ./cmd/proxy-firewall

install: build
	sh scripts/install.sh "$(DESTDIR)"

test-install: build
	python3 scripts/test_install.py

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

check: test race vet test-install
