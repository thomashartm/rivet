# Shortcuts for building and trying rivet. `make help` lists them.
# rivet reads ./.env, so run the binary from the repository root.

COMPOSE := docker compose --env-file .env -f docker/compose.playground.yml
BIN := target/release/rivet

.PHONY: help build install playground run run-mysql stop reset check

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-11s %s\n", $$1, $$2}'

build: ## Build the rivet executable (target/release/rivet)
	cargo build --release -p rivet-cli
	@echo "built $(BIN)"

install: ## Install rivet into ~/.cargo/bin
	cargo install --locked --path crates/rivet-cli

playground: ## Start PostgreSQL and MySQL in docker and write .env
	docker/playground.sh

run: build ## Open the PostgreSQL playground
	$(BIN) pg

run-mysql: build ## Open the MySQL playground
	$(BIN) mysql

stop: ## Stop the playground; the data stays
	$(COMPOSE) down

reset: ## Stop the playground, delete its data and .env
	$(COMPOSE) down -v
	rm -f .env

check: ## Run the full local gate (format, lint, tests, architecture, licences)
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	cargo xtask check-arch
	cargo deny check
