GO ?= go
TOOLS_MOD := -modfile=go.tools.mod
GOFILES := $(shell find . -type f -name "*.go")

## test: run tests
test:
	@$(GO) test -v -cover -coverprofile coverage.txt ./... && echo "\n==>\033[32m Ok\033[m\n" || exit 1

## fmt: format go files using golangci-lint
fmt:
	$(GO) tool $(TOOLS_MOD) golangci-lint fmt

## lint: run golangci-lint to check for issues
lint:
	$(GO) tool $(TOOLS_MOD) golangci-lint run

## clean: remove build artifacts and test coverage
clean:
	rm -rf coverage.txt

.PHONY: help test fmt lint clean

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

.PHONY: install-tools fmt lint
install-tools: ## Download pinned Go tools
	$(GO) mod download $(TOOLS_MOD)
