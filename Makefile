.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: fmt
fmt: ## Format code using gofumpt and goimports
	gofumpt -w .
	goimports -w .

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy and verify module dependencies
	go mod tidy
	go mod verify

.PHONY: update
update: ## Update all dependencies to latest minor/patch versions
	go get -u ./...
	go mod tidy

.PHONY: check
check: fmt vet lint ## Run all checks (fmt, vet, lint)
